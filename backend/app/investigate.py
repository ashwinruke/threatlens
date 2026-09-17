import asyncio
import time
from datetime import datetime, timedelta, timezone

import httpx2

from app import known_good as kg
from app.config import Settings
from app.detection import detect
from app.models import Indicator, IndicatorType, Investigation, SourceResult, SourceStatus
from app.scoring import score_cve, score_ioc
from app.sources import Source, run_source, sources_for
from app.trace import Trace

CACHEABLE = {SourceStatus.OK, SourceStatus.NOT_FOUND}


async def _lookup_with_cache(source: Source, indicator: Indicator, client: httpx2.AsyncClient,
                             store, settings: Settings) -> SourceResult:
    hours = settings.cache_hours_cve if indicator.type == IndicatorType.CVE else settings.cache_hours_ioc
    max_age = timedelta(hours=hours)
    try:
        cached = await store.get_cached(source.name, indicator, max_age)
    except Exception:
        cached = None  # a cache problem should never stop an investigation
    if cached:
        return cached

    result = await run_source(source, indicator, client, settings.source_timeout_seconds)
    if result.status in CACHEABLE:
        try:
            await store.put_cache(indicator, result)
        except Exception:
            pass
    return result


async def investigate(query: str, settings: Settings, store, client: httpx2.AsyncClient) -> Investigation:
    """Raises DetectionError (with a friendly message) if the input isn't understood."""
    started = time.perf_counter()
    created_at = datetime.now(timezone.utc)
    trace = Trace()

    # 1. Detect
    with trace.timed("detect", "Identified the input") as step:
        indicator = detect(query)
        step.title = f"Identified the input as {_article(indicator.type)}" + (
            f" ({indicator.subtype})" if indicator.subtype else "")
        step.reason = "Matched by pattern rules, not AI, so the result is predictable and explainable."
        step.detail = {"value": indicator.value, "notes": indicator.notes}

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
        results = await asyncio.gather(*[
            _lookup_with_cache(s, indicator, client, store, settings) for s in sources
        ])
        for r in results:
            what = {
                SourceStatus.OK: "found data", SourceStatus.NOT_FOUND: "had no record",
                SourceStatus.SKIPPED: "skipped", SourceStatus.TIMEOUT: "timed out",
                SourceStatus.RATE_LIMITED: "hit its rate limit", SourceStatus.ERROR: "failed",
            }[r.status]
            trace.add("fetch", f"{r.source} {what}" + (" (cached)" if r.cached else ""),
                      reason=r.message, status=r.status.value, duration_ms=None if r.cached else r.duration_ms,
                      detail={"link": r.link, "cached": r.cached})

    # 5. Score
    with trace.timed("score", "Calculated the risk score") as step:
        if indicator.type == IndicatorType.CVE:
            verdict, signals = score_cve(indicator, results)
        else:
            verdict, signals = score_ioc(indicator, results, good)
        step.reason = "Transparent formula: each signal below adds or removes points, capped between 0 and 100."
        step.detail = {"signals": [{"label": s.label, "points": s.points, "source": s.source} for s in signals],
                       "rules_applied": verdict.rules_applied}

    trace.add("verdict", f"{verdict.level} risk, score {verdict.score}/100, {verdict.confidence} confidence",
              reason=verdict.headline)

    investigation = Investigation(
        query=query, indicator=indicator, verdict=verdict, signals=signals, sources=results,
        trace=trace.steps, created_at=created_at, duration_ms=round((time.perf_counter() - started) * 1000),
    )

    # 6. Save
    try:
        await store.save(investigation)
        trace.add("save", "Saved the investigation", detail={"id": investigation.id})
    except Exception as exc:
        trace.add("save", "Couldn't save the investigation", status="error", reason=type(exc).__name__)
    investigation.trace = trace.steps
    return investigation


def _article(indicator_type: IndicatorType) -> str:
    return {IndicatorType.CVE: "a CVE", IndicatorType.IP: "an IP address",
            IndicatorType.DOMAIN: "a domain", IndicatorType.HASH: "a file hash"}[indicator_type]


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
