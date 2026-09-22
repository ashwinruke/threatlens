"""Writes the AI report for an investigation, safely.

Order of events:
  1. Build the evidence packet (with citation ids S0, S1, ...)
  2. Reuse a saved report if the exact same evidence was explained recently
  3. Try Gemini, then Groq. Any failure moves on to the next provider
  4. Check the answer: valid JSON, correct shape, and every statement cites a real source.
     Statements with no valid source are removed and counted.
  5. If every provider fails, return an "unavailable" report. The investigation still works,
     because the score never depended on the AI.
"""
import asyncio
import json
import re
import time
from datetime import timedelta

import httpx2
from pydantic import BaseModel, Field, ValidationError

from app.ai.prompt import SYSTEM_PROMPT, build_evidence, packet_hash, user_message
from app.ai.providers import ProviderError, providers_in_order
from app.config import Settings
from app.models import Action, CitedPoint, Investigation, Report

MAX_ITEMS = {"findings": 5, "affected": 5, "actions": 5, "gaps": 4}
MAX_TEXT = 400
RETRY_DELAY_SECONDS = 2.0
URL_RE = re.compile(r"https?://\S+|www\.\S+", re.IGNORECASE)


class _Draft(BaseModel):
    """The shape the AI must return. Anything else counts as a failed attempt."""

    summary: str
    findings: list[CitedPoint] = Field(default_factory=list)
    affected: list[CitedPoint] = Field(default_factory=list)
    actions: list[Action] = Field(default_factory=list)
    gaps: list[str] = Field(default_factory=list)


def _parse(text: str) -> _Draft:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", cleaned)
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start == -1 or end == -1:
        raise ValueError("no JSON object in the answer")
    return _Draft.model_validate(json.loads(cleaned[start:end + 1]))


def _clean_text(text: str, limit: int = MAX_TEXT) -> str:
    # The AI must not add links; ThreatLens only shows links from its own verified data
    text = URL_RE.sub("[link removed]", " ".join(str(text).split()))
    return text[:limit].rstrip()


def _check(draft: _Draft, valid_ids: set[str]) -> tuple[dict, int]:
    """Keep only statements that cite at least one real source. Returns (clean parts, removed count)."""
    removed = 0

    def keep(items: list, limit: int) -> list:
        nonlocal removed
        kept = []
        for item in items:
            sources = [s.strip().upper() for s in item.sources if s.strip().upper() in valid_ids]
            sources = list(dict.fromkeys(sources))
            if not sources or not item.text.strip():
                removed += 1
                continue
            kept.append(item.model_copy(update={"text": _clean_text(item.text), "sources": sources}))
        return kept[:limit]

    parts = {
        "summary": _clean_text(draft.summary, limit=800),
        "findings": keep(draft.findings, MAX_ITEMS["findings"]),
        "affected": keep(draft.affected, MAX_ITEMS["affected"]),
        "actions": keep(draft.actions, MAX_ITEMS["actions"]),
        "gaps": [_clean_text(g) for g in draft.gaps if str(g).strip()][:MAX_ITEMS["gaps"]],
    }
    return parts, removed


async def write_report(investigation: Investigation, settings: Settings, client: httpx2.AsyncClient,
                       store) -> Report:
    packet, citations = build_evidence(investigation)
    valid_ids = {c.id for c in citations}
    providers = [p for p in providers_in_order(settings) if p.is_configured()]
    if not providers:
        return Report(status="unavailable", citations=citations,
                      message="No AI provider is configured (add GEMINI_API_KEY or GROQ_API_KEY).")

    # Reuse a recent report written for exactly this evidence
    cache_key = packet_hash(packet, "|".join(f"{p.name}:{p.model}" for p in providers))
    try:
        saved = await store.get_report(cache_key, timedelta(hours=settings.ai_report_cache_hours))
    except Exception:
        saved = None
    if saved:
        return saved.model_copy(update={"cached": True})

    attempts: list[str] = []
    message = user_message(packet)
    for provider in providers:
        started = time.perf_counter()
        try:
            try:
                completion = await provider.complete(SYSTEM_PROMPT, message, client)
            except ProviderError as exc:
                if not exc.retryable:
                    raise
                # Busy or brief server error: wait a moment and try this provider once more
                attempts.append(f"{provider.name} ({provider.model}): {exc}, retrying once")
                await asyncio.sleep(RETRY_DELAY_SECONDS)
                completion = await provider.complete(SYSTEM_PROMPT, message, client)
            draft = _parse(completion.text)
            parts, removed = _check(draft, valid_ids)
            if not parts["summary"]:
                raise ValueError("the summary was empty")
        except ProviderError as exc:
            attempts.append(f"{provider.name} ({provider.model}): {exc}")
            continue
        except (httpx2.TimeoutException, TimeoutError):
            attempts.append(f"{provider.name} ({provider.model}): no answer within {settings.ai_timeout_seconds:.0f} seconds")
            continue
        except httpx2.RequestError as exc:
            attempts.append(f"{provider.name} ({provider.model}): couldn't connect ({type(exc).__name__})")
            continue
        except (ValueError, ValidationError, json.JSONDecodeError) as exc:
            attempts.append(f"{provider.name} ({provider.model}): answer wasn't valid report JSON ({type(exc).__name__})")
            continue

        attempts.append(f"{provider.name} ({provider.model}): report written")
        report = Report(
            status="ready", citations=citations, provider=provider.name, model=provider.model,
            duration_ms=round((time.perf_counter() - started) * 1000),
            input_tokens=completion.input_tokens, output_tokens=completion.output_tokens,
            removed_claims=removed, attempts=attempts, **parts,
        )
        try:
            await store.put_report(cache_key, report)
        except Exception:
            pass
        return report

    return Report(status="unavailable", citations=citations, attempts=attempts,
                  message="The AI summary couldn't be written right now. The score and evidence below are unaffected.")
