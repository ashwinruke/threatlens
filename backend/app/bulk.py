"""Bulk lookup: investigate many indicators at once.

Paste anything: a plain list (one per line), a spreadsheet column, or a whole alert or threat
report written in sentences. ThreatLens pulls out the indicators, removes repeats, and
investigates each one.

How text becomes a list of things to investigate (plain rules, no AI):
  1. A plain list, where every line is a short entry: each line is one item, so threat names
     like "Volt Typhoon" work too.
  2. Anything else (sentences, tables, logs): only structured indicators are picked out:
     CVEs, IPs, domains, URLs (their host), email addresses (their domain), file hashes and
     CWE IDs, including defanged ones like evil[.]com and hxxp://. Names are not guessed from
     sentences, because "the attackers used" isn't a threat name.
  3. Repeats are removed, and at most `bulk_max_items` are kept.

To save the free AI quota, bulk lookups skip the AI summary and the research agent. Each row
still gets the full score, evidence and decision trail, and links to its own report, where the
analyst can run a full investigation of anything worth a closer look.
"""
import asyncio
import re
import time
from datetime import datetime, timezone
from typing import Callable

from pydantic import BaseModel, Field

from app.config import Settings
from app.detection import CWE_RE, DetectionError, _detect_indicator, detect
from app.investigate import investigate
from app.models import Indicator, IndicatorType, Investigation, SourceStatus

LIST_MAX_WORDS = 5  # a line with more words than this is a sentence, not a list entry
BULLET_RE = re.compile(r"^\s*(?:[-*•>]|\d+[.)])\s+")
TOKEN_SPLIT_RE = re.compile(r"[\s,;|]+")
TRIM_CHARS = "()<>'\"`,;:!?{}"
# Look like domains but are file names in reports: "invoice.exe", "dropper.dll", "notes.txt"
FILE_EXTENSIONS = {
    "exe", "dll", "sys", "pdf", "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "rtf", "txt",
    "csv", "log", "json", "xml", "yml", "yaml", "ini", "cfg", "tmp", "dat", "bin", "bat", "cmd", "ps1", "psm1",
    "vbs", "vbe", "js", "jse", "hta", "lnk", "scr", "msi", "jar", "py", "sh", "elf", "so", "png", "jpg",
    "jpeg", "gif", "bmp", "svg", "html", "htm", "php", "aspx", "asp", "rar", "7z", "gz", "tar", "iso", "img",
    "vhd", "one", "eml", "md",
}
BULK_AI_MESSAGE = ("Bulk lookups skip the AI summary and the research agent to save the free AI quota. "
                   "Investigate this on its own to get both.")
TYPE_WORDS = {"cve": ("CVE", "CVEs"), "ip": ("IP address", "IP addresses"), "domain": ("domain", "domains"),
              "hash": ("file hash", "file hashes"), "threat": ("name or weakness", "names or weaknesses")}


class PlanItem(BaseModel):
    query: str  # what gets investigated: the clean indicator, e.g. "evil.com" for "hxxp://evil[.]com/x"
    type: IndicatorType
    original: str  # as it appeared in the pasted text


class Skipped(BaseModel):
    text: str
    reason: str


class Plan(BaseModel):
    mode: str  # "list" (one entry per line, names allowed) or "extract" (indicators picked out of text)
    items: list[PlanItem] = Field(default_factory=list)
    skipped: list[Skipped] = Field(default_factory=list)  # things that looked like indicators but weren't valid
    repeats: int = 0  # duplicates removed
    over_limit: int = 0  # valid items beyond the limit, not investigated
    summary: str = ""  # e.g. "Found 12: 5 IP addresses, 4 domains, 3 file hashes"


class BulkRow(BaseModel):
    index: int
    query: str
    type: IndicatorType
    investigation_id: str | None = None
    value: str | None = None  # the indicator as investigated (a name may resolve to its ATT&CK name)
    subtype: str | None = None  # e.g. "ipv4", "sha256", or for a name what it turned out to be: "group", "weakness"
    level: str | None = None
    score: int | None = None
    confidence: str | None = None
    headline: str | None = None
    top_signals: list[str] = Field(default_factory=list)  # e.g. ["Listed in CISA KEV (+30)"]
    sources_ok: int = 0  # sources that answered
    sources_total: int = 0
    duration_ms: int | None = None
    error: str | None = None


class Batch(BaseModel):
    id: str | None = None
    created_at: datetime
    mode: str
    rows: list[BulkRow]
    skipped: list[Skipped] = Field(default_factory=list)
    repeats: int = 0
    over_limit: int = 0
    duration_ms: int = 0


class BulkRequest(BaseModel):
    text: str = Field(min_length=1, max_length=20_000)


def _clean_line(line: str) -> str:
    return " ".join(BULLET_RE.sub("", line).split())


def _is_list(lines: list[str]) -> bool:
    """True when every line is a short entry, not a sentence or a table row."""
    for line in lines:
        if len(line.split()) > LIST_MAX_WORDS or any(sep in line for sep in (",", ";", "\t", "|")):
            return False
        if line.endswith((".", "!", "?", ":")) and not _structured(line.rstrip(".!?:")):
            return False
    return True


def _structured(token: str) -> Indicator | None:
    """A CVE, IP, domain, URL host, email domain, hash or CWE ID. None for anything else."""
    cwe = CWE_RE.match(token)
    if cwe:
        return Indicator(type=IndicatorType.THREAT, value=f"CWE-{int(cwe.group(1))}", original=token)
    try:
        indicator = _detect_indicator(token, token)
    except DetectionError:
        return None
    if indicator and indicator.type == IndicatorType.DOMAIN:
        if indicator.value.rsplit(".", 1)[-1] in FILE_EXTENSIONS:
            return None  # "invoice.exe" is a file name, not a domain
    return indicator


def _tokens(text: str) -> list[str]:
    found = []
    for raw in TOKEN_SPLIT_RE.split(text):
        token = raw.strip(TRIM_CHARS)
        token = token.rstrip(".")  # a sentence ending right after an indicator: "... from evil.com."
        if token:
            found.append(token)
    return found


def plan(text: str, limit: int) -> Plan:
    """Turn pasted text into a de-duplicated list of things to investigate."""
    lines = [_clean_line(line) for line in text.splitlines()]
    lines = [line for line in lines if line]
    result = Plan(mode="list" if lines and _is_list(lines) else "extract")
    seen: set[tuple[str, str]] = set()
    candidates: list[PlanItem] = []

    def add(indicator: Indicator, original: str) -> None:
        key = (indicator.type.value, indicator.value.lower())
        if key in seen:
            result.repeats += 1
            return
        seen.add(key)
        candidates.append(PlanItem(query=indicator.value, type=indicator.type, original=original))

    for line in lines:
        if result.mode == "list":
            try:
                add(detect(line), line)
            except DetectionError as exc:
                result.skipped.append(Skipped(text=line[:120], reason=str(exc)))
            continue
        for token in _tokens(line):
            indicator = _structured(token)
            if indicator:
                add(indicator, token)
            elif re.fullmatch(r"[0-9a-fA-F]{24,}", token) and len(token) not in (32, 40, 64):
                result.skipped.append(Skipped(text=token[:120], reason=(
                    f"Looks like a hash, but has {len(token)} characters (MD5 has 32, SHA-1 40, SHA-256 64).")))

    result.items = candidates[:limit]
    result.over_limit = max(0, len(candidates) - limit)
    counts: dict[str, int] = {}
    for item in result.items:
        counts[item.type.value] = counts.get(item.type.value, 0) + 1
    parts = [f"{n} {TYPE_WORDS[t][0] if n == 1 else TYPE_WORDS[t][1]}" for t, n in counts.items()]
    result.summary = f"Found {len(result.items)}: {', '.join(parts)}" if result.items else "Found nothing to investigate"
    return result


def row_for(index: int, item: PlanItem, investigation: Investigation) -> BulkRow:
    answered = [s for s in investigation.sources if s.status in (SourceStatus.OK, SourceStatus.NOT_FOUND)]
    top = sorted(investigation.signals, key=lambda s: -abs(s.points))[:3]
    verdict = investigation.verdict
    return BulkRow(
        index=index, query=item.query, type=item.type, investigation_id=investigation.id,
        value=investigation.indicator.value, subtype=investigation.indicator.subtype, level=verdict.level,
        score=None if verdict.level == "PROFILE" else verdict.score, confidence=verdict.confidence,
        headline=verdict.headline, top_signals=[f"{s.label} ({s.points:+d})" for s in top if s.points],
        sources_ok=len(answered), sources_total=len(investigation.sources), duration_ms=investigation.duration_ms,
    )


async def run_bulk(planned: Plan, settings: Settings, store, client,
                   on_row: Callable[[BulkRow], None] | None = None) -> Batch:
    """Investigate every planned item, a few at a time. A failed item becomes an error row, never a failed batch."""
    started = time.perf_counter()
    gate = asyncio.Semaphore(max(1, settings.bulk_concurrency))
    rows: list[BulkRow | None] = [None] * len(planned.items)

    async def one(index: int, item: PlanItem) -> None:
        async with gate:
            try:
                investigation = await investigate(item.query, settings, store, client, write_ai_report=False,
                                                  ai_skipped_message=BULK_AI_MESSAGE)
                row = row_for(index, item, investigation)
            except DetectionError as exc:
                row = BulkRow(index=index, query=item.query, type=item.type, error=str(exc))
            except Exception:
                row = BulkRow(index=index, query=item.query, type=item.type,
                              error="This one failed unexpectedly. Try investigating it on its own.")
        rows[index] = row
        if on_row:
            try:
                on_row(row)
            except Exception:
                pass  # a broken listener never stops the batch

    await asyncio.gather(*(one(i, item) for i, item in enumerate(planned.items)))
    batch = Batch(created_at=datetime.now(timezone.utc), mode=planned.mode, rows=[r for r in rows if r],
                  skipped=planned.skipped, repeats=planned.repeats, over_limit=planned.over_limit,
                  duration_ms=round((time.perf_counter() - started) * 1000))
    try:
        batch.id = await store.save_batch(batch.model_dump(mode="json", exclude={"id"}))
    except Exception:
        batch.id = None  # the rows are still shown; only the shareable link is missing
    return batch

