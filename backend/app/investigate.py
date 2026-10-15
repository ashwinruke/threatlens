"""Runs one investigation from start to finish and records every decision.

Steps:
  1. Detect what the input is
     (a threat name like "Volt Typhoon" takes a different path: see app/threats.py)
  2. Check known-good lists (and skip lookups for private addresses)
  3. Choose sources for this input type
  4. Ask every source at the same time (using cached answers when fresh)
  5. Score the risk from the evidence
  6. Research: an AI agent follows up the leads with read-only tools (never changes the score)
  7. Ask the AI to explain the result, citing the sources and the research
  8. Save the result
"""
import asyncio
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Callable

import httpx2

from app import known_good as kg
from app import threats
from app.agent.runner import research
from app.ai.report import write_report
from app.config import Settings
from app.detection import detect
from app.knowledge.repository import KnowledgeRepository
from app.models import Indicator, IndicatorType, Investigation, Report, Signal, SourceResult, SourceStatus, Verdict
from app.scoring import score_cve, score_ioc
from app.sources import Source, run_source, sources_for
from app.trace import Trace

CACHEABLE = {SourceStatus.OK, SourceStatus.NOT_FOUND}
SUBTYPE_NAMES = {"ipv4": "IPv4", "ipv6": "IPv6", "md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256"}
logger = logging.getLogger("threatlens")

# Live updates for the streaming endpoint: on_event("step", {...}) or on_event("status", {"text": ...})
EventCallback = Callable[[str, dict], None]


def _quiet(text: str) -> None:
    """Default status callback: nobody is listening."""


async def _lookup_with_cache(source: Source, indicator: Indicator, client: httpx2.AsyncClient,
                             store, settings: Settings) -> SourceResult:
    hours = settings.cache_hours_cve if indicator.type == IndicatorType.CVE else settings.cache_hours_ioc
    max_age = timedelta(hours=hours)
    try:
        cached = await store.get_cached(source.name, indicator, max_age)
    except Exception as exc:
        # A cache problem should never stop an investigation, but it must be visible
        logger.warning("Cache read failed for %s: %s: %s", source.name, type(exc).__name__, exc)
        cached = None
    if cached:
        return cached

    result = await run_source(source, indicator, client, settings.source_timeout_seconds)
    if result.status in CACHEABLE:
        try:
            await store.put_cache(indicator, result)
        except Exception as exc:
            logger.warning("Cache write failed for %s: %s: %s", source.name, type(exc).__name__, exc)
    return result


async def investigate(query: str, settings: Settings, store, client: httpx2.AsyncClient,
                      write_ai_report: bool = True, ai_cache_only: bool = False,
                      ai_skipped_message: str | None = None, research_allowed: bool = True,
                      on_event: EventCallback | None = None) -> Investigation:
    """Raises DetectionError (with a friendly message) if the input isn't understood.

    on_event, if given, hears every decision-trail step as soon as it's recorded, plus short
    status messages during slow waits. That's what powers the live view.
    """
    started = time.perf_counter()
    created_at = datetime.now(timezone.utc)
    if on_event:
        trace = Trace(listener=lambda step: on_event("step", step.model_dump(mode="json")))
        def status(text: str) -> None:
            on_event("status", {"text": text})
    else:
        trace = Trace()
        status = _quiet

    # 1. Detect
    with trace.timed("detect", "Identified the input") as step:
        indicator = detect(query)
        step.title = f"Identified the input as {_article(indicator.type)}" + (
            f" ({SUBTYPE_NAMES.get(indicator.subtype, indicator.subtype)})" if indicator.subtype else "")
        step.reason = ("A CWE ID, which names a kind of software weakness." if indicator.value.startswith("CWE-") else
                       "Not a CVE, IP, domain, or hash, so ThreatLens treats it as the name of a known threat "
                       "or software weakness." if indicator.type == IndicatorType.THREAT else
                       "Matched by pattern rules, not AI, so the result is predictable and explainable.")
        step.detail = {"value": indicator.value, "notes": indicator.notes}

    threat = None
    if indicator.type == IndicatorType.THREAT:
        verdict, signals, results, threat = await _threat_steps(indicator, store, trace)
    else:
        verdict, signals, results = await _indicator_steps(indicator, settings, store, client, trace, status)

    if threat and threat.status != "matched":
        trace.add("verdict", "No profile, no risk score", reason=verdict.headline)
    elif verdict.level == "PROFILE" and indicator.subtype == "weakness":
        trace.add("verdict", "Weakness profile, no risk score",
                  reason="A weakness is a kind of mistake, not one specific flaw, so it has no single risk. "
                         "ThreatLens shows what the mistake lets an attacker do and how to prevent it. "
                         "To score a real flaw, investigate its CVE.")
    elif verdict.level == "PROFILE":
        trace.add("verdict", "Threat profile, no risk score",
                  reason="How dangerous a named threat is depends on whether it targets you, which ThreatLens "
                         "can't know. So it shows what the threat does and how to defend against it, "
                         "instead of inventing a number.")
    else:
        trace.add("verdict", f"{verdict.level} risk, score {verdict.score}/100, {verdict.confidence} confidence",
                  reason=verdict.headline)

    investigation = Investigation(
        query=query, indicator=indicator, verdict=verdict, signals=signals, sources=results,
        trace=trace.steps, created_at=created_at, duration_ms=0, threat=threat,
    )

    # 6. Research agent: follows the leads, within a strict budget
    if write_ai_report and settings.research_enabled:
        async def run_indicator(related: Indicator):
            # A related indicator gets the normal source checks, without its own AI report or saved record
            return await _indicator_steps(related, settings, store, client, Trace())

        shown: set[str] = set()

        def on_step(step) -> None:  # each research step appears in the trail the moment it's done
            shown.add(step.id)
            _trace_research_step(trace, step, cached=False)

        investigation.research = await research(investigation, settings, store, client, run_indicator,
                                                allowed=research_allowed and not ai_cache_only,
                                                on_step=on_step, on_status=status)
        _trace_research(trace, investigation.research, already_shown=shown)

    # 7. AI report: explains the verdict, never changes it
    if threat and threat.status != "matched":
        message = ("Pick one of the matches below to see its full profile and summary."
                   if threat.status == "ambiguous" and threat.candidates else
                   "There's nothing for the AI to explain, because no ATT&CK entry matched.")
        investigation.report = Report(status="unavailable", message=message)
        trace.add("report", "No AI summary needed", status="skipped", reason=message)
    elif not write_ai_report and ai_skipped_message:
        investigation.report = Report(status="unavailable", message=ai_skipped_message)
        trace.add("report", "AI summary skipped", status="error", reason=ai_skipped_message)
    elif write_ai_report:
        status("Writing the summary with AI…")
        report = await write_report(investigation, settings, client, store,
                                    cache_only=ai_cache_only, unavailable_message=ai_skipped_message)
        investigation.report = report
        if report.status == "ready":
            title = ("Reused the AI summary written for this same evidence" if report.cached
                     else f"Wrote the AI summary with {report.provider} ({report.model})")
            reason = "The AI explains the score; it didn't set it."
            if report.removed_claims:
                reason += f" Removed {report.removed_claims} statement(s) that didn't cite a real source."
            trace.add("report", title, reason=reason, duration_ms=None if report.cached else report.duration_ms,
                      detail={"attempts": report.attempts, "input_tokens": report.input_tokens,
                              "output_tokens": report.output_tokens})
        else:
            trace.add("report", "AI summary unavailable", status="error", reason=report.message,
                      detail={"attempts": report.attempts})

    investigation.duration_ms = round((time.perf_counter() - started) * 1000)

    # 8. Save (with every step so far, including the report step)
    investigation.trace = list(trace.steps)
    try:
        await store.save(investigation)
        trace.add("save", "Saved the investigation", detail={"id": investigation.id})
    except Exception as exc:
        trace.add("save", "Couldn't save the investigation", status="error", reason=type(exc).__name__)
    investigation.trace = trace.steps
    return investigation


async def _name_weaknesses(results: list[SourceResult], store) -> None:
    """Turn NVD's "CWE-502" into "CWE-502 Deserialization of Untrusted Data", using the CWE catalog.

    Done after caching, so saved source answers stay exactly as NVD sent them. Without the
    database or the CWE import, the IDs are simply left as they are.
    """
    nvd = next((r for r in results if r.source == "NVD" and r.status == SourceStatus.OK), None)
    ids = (nvd.facts.get("weaknesses") or []) if nvd else []
    if not ids or not hasattr(store, "connection"):
        return
    try:
        names = await KnowledgeRepository(store).names(ids)
    except Exception as exc:
        logger.warning("Couldn't name CWE weaknesses: %s", type(exc).__name__)
        return
    nvd.facts = {**nvd.facts, "weaknesses": [f"{i} {names[i.upper()]}" if i.upper() in names else i for i in ids]}


def _trace_research_step(trace: Trace, step, cached: bool) -> None:
    trace.add("research", f"{step.id}: {step.title}", status="ok" if step.ok else "skipped",
              reason=f"Why: {step.why} Found: {step.summary}",
              duration_ms=None if cached else step.duration_ms, detail={"link": step.link})


def _trace_research(trace: Trace, run, already_shown: set[str] | None = None) -> None:
    if not run.steps:
        title = {"skipped": "No further research", "unavailable": "Research unavailable"}.get(run.status, "No research steps")
        trace.add("research", title, status="skipped" if run.status == "skipped" else "error", reason=run.reason)
        return
    for step in run.steps:  # steps not already recorded live, e.g. reused from a saved run
        if step.id not in (already_shown or set()):
            _trace_research_step(trace, step, cached=run.cached)
    cost = (f"Reused saved research for this same evidence." if run.cached else
            f"{run.ai_calls} AI decision(s) with {run.provider} ({run.model}), "
            f"{run.input_tokens + run.output_tokens} tokens.")
    trace.add("research", "Research finished" if run.status == "done" else "Research stopped",
              status="ok" if run.status == "done" else "error",
              reason=f"{run.reason} {cost} Research never changes the score.",
              detail={"ai_calls": run.ai_calls, "tokens": run.input_tokens + run.output_tokens})


def _article(indicator_type: IndicatorType) -> str:
    return {IndicatorType.CVE: "a CVE", IndicatorType.IP: "an IP address", IndicatorType.DOMAIN: "a domain",
            IndicatorType.HASH: "a file hash", IndicatorType.THREAT: "a threat name or software weakness"}[indicator_type]


def _why_sources(indicator_type: IndicatorType) -> str:
    return {
        IndicatorType.CVE: "For a vulnerability: official details and severity (NVD), confirmed real-world "
                           "exploitation (CISA KEV), and exploit likelihood (EPSS).",
        IndicatorType.IP: "For an IP: community abuse reports (AbuseIPDB), vendor scanners (VirusTotal), "
                          "threat reports (OTX), and malware infrastructure lists (ThreatFox, URLhaus).",
        IndicatorType.DOMAIN: "For a domain: vendor scanners (VirusTotal), threat reports (OTX), and malware "
                              "infrastructure lists (ThreatFox, URLhaus).",
        IndicatorType.HASH: "For a file hash: vendor scanners (VirusTotal), a malware sample database "
                            "(MalwareBazaar), threat reports (OTX), and malware IOC lists (ThreatFox).",
    }[indicator_type]


async def _indicator_steps(indicator: Indicator, settings: Settings, store, client: httpx2.AsyncClient,
                           trace: Trace, status: Callable[[str], None] = _quiet
                           ) -> tuple[Verdict, list[Signal], list[SourceResult]]:
    """Steps 2 to 5 for a CVE, IP, domain, or hash."""
    # 2. Known-good checks
    good = None
    if indicator.type == IndicatorType.IP:
        good = kg.check_ip(indicator.value)
    elif indicator.type == IndicatorType.DOMAIN:
        good = kg.check_domain(indicator.value)
    if good and (good.reason or good.caution):
        title = ("Private address: no outside lookups" if good.skip_external_lookup
                 else "Matched a known-good list" if good.is_known_good
                 else "Hosted on a shared content platform")
        trace.add("decide", title, reason=good.reason or good.caution)

    # 3. Choose sources
    sources = [] if (good and good.skip_external_lookup) else sources_for(indicator.type, settings)
    usable = [s for s in sources if s.is_configured()]
    missing = [s.name for s in sources if not s.is_configured()]
    if sources:
        trace.add("decide", f"Chose {len(usable)} source(s) for {_article(indicator.type)}",
                  reason=_why_sources(indicator.type),
                  detail={"sources": [s.name for s in usable], "skipped_missing_key": missing})

    # 4. Ask all sources at the same time
    results: list[SourceResult] = []
    if sources:
        status(f"Waiting for {len(sources)} source{'s' if len(sources) != 1 else ''} to answer…")
        waiting = [len(sources)]

        async def ask(source: Source) -> SourceResult:
            # Recorded the moment this source answers, so the live view shows slow sources as slow
            result = await _lookup_with_cache(source, indicator, client, store, settings)
            what = {
                SourceStatus.OK: "found data", SourceStatus.NOT_FOUND: "had no record",
                SourceStatus.SKIPPED: "skipped", SourceStatus.TIMEOUT: "timed out",
                SourceStatus.RATE_LIMITED: "hit its rate limit", SourceStatus.ERROR: "failed",
            }[result.status]
            trace.add("fetch", f"{result.source} {what}" + (" (cached)" if result.cached else ""),
                      reason=result.message, status=result.status.value,
                      duration_ms=None if result.cached else result.duration_ms,
                      detail={"link": result.link, "cached": result.cached})
            waiting[0] -= 1
            if waiting[0]:
                status(f"Waiting for {waiting[0]} more source{'s' if waiting[0] != 1 else ''}…")
            return result

        # gather keeps the sources in their usual order, whatever order they answer in
        results = list(await asyncio.gather(*[ask(s) for s in sources]))
        if indicator.type == IndicatorType.CVE:
            await _name_weaknesses(results, store)

    # 5. Score
    with trace.timed("score", "Calculated the risk score") as step:
        if indicator.type == IndicatorType.CVE:
            verdict, signals = score_cve(indicator, results)
        else:
            verdict, signals = score_ioc(indicator, results, good)
        step.reason = "Transparent formula: each signal below adds or removes points, capped between 0 and 100."
        step.detail = {"signals": [{"label": s.label, "points": s.points, "source": s.source} for s in signals],
                       "rules_applied": verdict.rules_applied}

    return verdict, signals, results


async def _threat_steps(indicator: Indicator, store, trace: Trace):
    """Steps 2 to 5 for a threat name or weakness: search ATT&CK and CWE, pick a match, load its profile."""
    with trace.timed("decide", f"Searched MITRE ATT&CK and CWE for \"{indicator.value}\"") as step:
        lookup = await threats.look_up(indicator, store)
        step.reason = ("By ID, name, alias, similar spelling, and description, across groups, malware, tools, "
                       "campaigns, techniques, and software weaknesses.")
        step.detail = {"candidates": [f"{c.external_id} {c.name} ({c.matched_on})" for c in lookup.candidates]}

    results: list[SourceResult] = []
    if lookup.status == "matched":
        entity = lookup.profile.entity
        trace.add("decide", f"Matched {entity.name} ({entity.external_id}) by {lookup.matched_on}",
                  reason=("An exact match." if not lookup.matched_on.startswith("similar") else
                          "The closest match, clearly ahead of the others. Other close matches are listed in case it's wrong."))
        indicator.notes.append(f"You searched for \"{indicator.value}\"; matched {entity.name} by {lookup.matched_on}.")
        indicator.value, indicator.subtype = entity.name, entity.kind
        results = [threats.as_source(lookup)]
        if entity.kind == "weakness":
            found = (f"{len(entity.details.get('consequences') or [])} consequences, "
                     f"{len(entity.details.get('mitigations') or [])} ways to prevent it.")
        else:
            found = (f"{len(lookup.profile.techniques)} techniques, "
                     f"{len(lookup.profile.mitigations)} ranked defenses.")
        trace.add("fetch", f"{threats.source_name(entity)} found data", detail={"link": entity.url, "cached": False},
                  reason=f"Profile of {entity.name}: {found}")
    elif lookup.status == "ambiguous":
        trace.add("decide", "Several entries could match", status="skipped",
                  reason="None is clearly ahead, so ThreatLens asks instead of guessing.")
    elif lookup.status == "not_found":
        trace.add("decide", "No ATT&CK or CWE entry matched", status="skipped")
    else:
        trace.add("decide", "Knowledge base unavailable", status="error",
                  reason="Threat names are looked up in the database, which isn't connected.")
    return threats.verdict_for(lookup), [], results, lookup
