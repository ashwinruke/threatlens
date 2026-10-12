"""The research agent's tools. All read-only, all validated, none ever contacts an indicator.

Every tool takes one text input and returns a ToolResult:
- ok: whether it found something useful
- title and summary: plain text for the decision trail
- data: a compact result for the AI report writer (size-capped, because every
  character is sent to the AI and counts toward free-tier limits)
- link: where a human can verify it
"""
import asyncio
import json
import re
from dataclasses import dataclass, field
from typing import Awaitable, Callable

from app.detection import ATTACK_ID_RE, DetectionError, detect
from app.knowledge.repository import KnowledgeRepository
from app.knowledge.search import search
from app.models import Indicator, IndicatorType, SourceStatus

MAX_DATA_CHARS = 1500
EXACT_SCORE = 190  # an exact ID, name or alias match in knowledge search
MAX_MENTIONS = 8
SENTENCE_RE = re.compile(r"(?<=[.!?])\s+")

TOOLS = {
    "search_attack": "Find MITRE ATT&CK entries by name or alias. Input: a name, e.g. Mirai or Cozy Bear.",
    "attack_profile": "Open one ATT&CK entry: who uses it, its software, campaigns, techniques and best defenses. "
                      "Input: an ATT&CK ID, e.g. G0016, S0002, C0022, T1003.001.",
    "attack_mentions": "Find where ATT&CK's text mentions something, e.g. which groups exploited a CVE. "
                       "Input: a CVE ID, product, tool or file name (3 to 60 characters).",
    "investigate_indicator": "Run ThreatLens's source checks on one related CVE, IP, domain or hash that appears "
                             "in the evidence. Uses outside services, so it is limited per investigation.",
}

TITLES = {
    "search_attack": "Searched ATT&CK for \"{input}\"",
    "attack_profile": "Opened the ATT&CK entry {input}",
    "attack_mentions": "Looked for ATT&CK mentions of \"{input}\"",
    "investigate_indicator": "Investigated the related indicator {input}",
}


@dataclass
class ToolResult:
    ok: bool
    summary: str
    data: dict = field(default_factory=dict)
    link: str | None = None


@dataclass
class ToolContext:
    store: object
    original: Indicator  # the indicator being investigated, so it isn't looked up again
    run_indicator: Callable[[Indicator], Awaitable[tuple]]  # returns (verdict, signals, source results)
    lookups_left: int = 1


def cap(data: dict, limit: int = MAX_DATA_CHARS) -> dict:
    """Shorten the longest lists until the result fits the size limit."""
    data = json.loads(json.dumps(data, default=str))
    while len(json.dumps(data)) > limit:
        lists = [(k, v) for k, v in data.items() if isinstance(v, list) and len(v) > 1]
        if not lists:
            for key, value in data.items():
                if isinstance(value, str) and len(value) > 200:
                    data[key] = value[: max(200, len(value) // 2)] + "…"
                    break
            else:
                break
            continue
        key, value = max(lists, key=lambda kv: len(json.dumps(kv[1])))
        data[key] = value[: len(value) - 1]
        data[f"{key}_shortened"] = True
    return data


def _has_db(ctx: ToolContext) -> bool:
    return hasattr(ctx.store, "connection")


async def search_attack(text: str, ctx: ToolContext) -> ToolResult:
    if not 2 <= len(text) <= 80:
        return ToolResult(False, "Input must be a name of 2 to 80 characters.")
    if not _has_db(ctx):
        return ToolResult(False, "The knowledge base isn't available.")
    results = await search(ctx.store, text, limit=5)
    exact = [r for r in results if r.score >= EXACT_SCORE]
    if not exact:
        # Similar spelling is NOT the same threat: "Mirai" scores 40 against MirageFox, an unrelated
        # malware. So the agent only gets exact matches, and is told plainly when there are none.
        close = [f"{r.name} ({r.external_id})" for r in results if r.matched_on.startswith("similar")][:3]
        hint = f" Similar names, probably different threats: {', '.join(close)}." if close else ""
        return ToolResult(False, f"ATT&CK has no entry named \"{text}\".{hint}")
    top = exact[0]
    return ToolResult(
        True, f"{top.name} ({top.external_id}, {top.kind}), matched by {top.matched_on}.",
        cap({"matches": [f"{r.external_id} {r.name} ({r.kind}, matched by {r.matched_on})" for r in exact]}),
        top.url,
    )


async def attack_profile(text: str, ctx: ToolContext) -> ToolResult:
    if not ATTACK_ID_RE.match(text):
        return ToolResult(False, "Input must be an ATT&CK ID like G0016, S0002, C0022 or T1003.001.")
    if not _has_db(ctx):
        return ToolResult(False, "The knowledge base isn't available.")
    profile = await KnowledgeRepository(ctx.store).profile(text)
    if not profile:
        return ToolResult(False, f"There is no ATT&CK entry {text.upper()}.")
    entity = profile.entity
    data = {
        "id": entity.external_id, "name": entity.name, "kind": entity.kind, "aliases": entity.aliases[:8],
        "about": " ".join(SENTENCE_RE.split(entity.description)[:2])[:400],
    }
    for group in profile.related:
        if group.label != "Techniques used":
            data[group.label.lower().replace(" ", "_")] = [f"{i.external_id} {i.name}" for i in group.items[:10]]
    if profile.techniques:
        data["technique_count"] = len(profile.techniques)
        data["top_tactics"] = [f"{t.name}: {t.count}" for t in profile.tactics[:5]]
    if profile.mitigations:
        data["top_defenses"] = [f"{m.external_id} {m.name} (covers {m.covers})" for m in profile.mitigations[:5]]
    counts = ", ".join(f"{len(g.items)} {g.label.lower()}" for g in profile.related[:3])
    return ToolResult(True, f"{entity.name} ({entity.external_id}, {entity.kind}): {counts}.", cap(data), entity.url)


def _escape_like(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _sentence(text: str, term: str) -> str:
    for sentence in SENTENCE_RE.split(text):
        if term.lower() in sentence.lower():
            sentence = " ".join(sentence.split())
            return sentence if len(sentence) <= 220 else sentence[:219] + "…"
    return ""


async def attack_mentions(text: str, ctx: ToolContext) -> ToolResult:
    if not 3 <= len(text) <= 60:
        return ToolResult(False, "Input must be 3 to 60 characters.")
    if not _has_db(ctx):
        return ToolResult(False, "The knowledge base isn't available.")
    pattern = f"%{_escape_like(text)}%"

    def run():
        with ctx.store.connection() as conn:
            rels = conn.execute(
                "SELECT s.external_id AS sid, s.name AS sname, s.url, t.external_id AS tid, t.name AS tname, "
                "r.description FROM relationships r JOIN entities s ON s.id = r.source_id "
                "JOIN entities t ON t.id = r.target_id WHERE r.description ILIKE %s "
                "ORDER BY s.external_id, t.external_id LIMIT 40", (pattern,)).fetchall()
            ents = conn.execute(
                "SELECT external_id AS sid, name AS sname, url, description FROM entities "
                "WHERE description ILIKE %s ORDER BY external_id LIMIT 20", (pattern,)).fetchall()
            return rels, ents

    rels, ents = await asyncio.to_thread(run)
    mentions, who = [], []
    for row in list(ents) + list(rels):
        sentence = _sentence(row["description"], text)
        if not sentence:
            continue
        where = f"{row['sname']} ({row['sid']})" + (f" → {row['tname']} ({row['tid']})" if "tid" in row else "")
        mentions.append(f"{where}: {sentence}")
        if row["sname"] not in who:
            who.append(row["sname"])
    if not mentions:
        return ToolResult(False, f"ATT&CK's text doesn't mention \"{text}\".")
    first = (list(ents) + list(rels))[0]
    return ToolResult(
        True, f"Mentioned {len(mentions)} time(s), by {', '.join(who[:6])}{'…' if len(who) > 6 else ''}.",
        cap({"term": text, "entries_mentioning_it": who[:12], "mentions": mentions[:MAX_MENTIONS]}), first["url"],
    )


async def investigate_indicator(text: str, ctx: ToolContext) -> ToolResult:
    if ctx.lookups_left <= 0:
        return ToolResult(False, "No related-indicator lookups left for this investigation.")
    try:
        indicator = detect(text)
    except DetectionError as exc:
        return ToolResult(False, f"Not a valid indicator: {exc}")
    if indicator.type == IndicatorType.THREAT:
        return ToolResult(False, "That's a name, not an indicator. Use search_attack for names.")
    if indicator.type == ctx.original.type and indicator.value == ctx.original.value:
        return ToolResult(False, "That's the indicator already being investigated.")
    ctx.lookups_left -= 1
    verdict, signals, results = await ctx.run_indicator(indicator)
    link = next((r.link for r in results if r.status == SourceStatus.OK and r.link), None)
    data = {
        "indicator": indicator.value, "type": indicator.type.value, "level": verdict.level, "score": verdict.score,
        "headline": verdict.headline,
        "signals": [f"{s.label} ({s.points:+d})" for s in signals],
        "sources": {r.source: r.status.value for r in results},
    }
    return ToolResult(verdict.level != "UNKNOWN", f"{indicator.value}: {verdict.level}, {verdict.headline}", cap(data), link)


RUNNERS = {
    "search_attack": search_attack,
    "attack_profile": attack_profile,
    "attack_mentions": attack_mentions,
    "investigate_indicator": investigate_indicator,
}


async def run_tool(name: str, text: str, ctx: ToolContext) -> ToolResult:
    runner = RUNNERS.get(name)
    if not runner:
        return ToolResult(False, f"There is no tool called \"{name}\".")
    try:
        return await runner(" ".join(str(text).split()), ctx)
    except Exception as exc:  # a broken tool ends that step, never the investigation
        return ToolResult(False, f"The tool failed ({type(exc).__name__}).")


def title(name: str, text: str) -> str:
    return TITLES.get(name, "Tried an unknown tool \"{input}\"").format(input=text)
