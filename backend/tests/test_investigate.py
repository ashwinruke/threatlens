"""End-to-end investigations with fake sources: scoring, trace, caching, saving."""
import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from app.investigate import investigate
from app.models import SourceStatus
from app.sources import kev
from app.store import MemoryStore
from tests import fakes


@pytest.fixture(autouse=True)
def clear_kev():
    kev.reset_catalog()


def go(query, client=None, store=None, **settings):
    store = store or MemoryStore()
    return asyncio.run(investigate(query, fakes.test_settings(**settings), store, client or fakes.router()))


def signal_ids(result):
    return {s.id for s in result.signals}


def test_log4shell_is_critical_with_explained_points():
    result = go(fakes.LOG4SHELL)
    assert result.verdict.level == "CRITICAL" and result.verdict.score == 95
    assert signal_ids(result) == {"cvss", "kev_listed", "kev_ransomware", "epss"}
    assert sum(s.points for s in result.signals) == 95
    assert result.verdict.confidence == "high"
    assert "actively exploited" in result.verdict.headline


def test_kev_floor_rule():
    low_cvss = {"totalResults": 1, "vulnerabilities": [{"cve": {
        **fakes.NVD_LOG4SHELL["vulnerabilities"][0]["cve"],
        "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 4.0, "baseSeverity": "MEDIUM"}}]}}}]}
    result = go(fakes.LOG4SHELL, fakes.router({"nvd": (200, low_cvss), "epss": (200, {"data": []})}))
    assert result.verdict.score == 60 and result.verdict.level == "HIGH"
    assert "at least HIGH" in result.verdict.rules_applied[0]


def test_unknown_cve():
    result = go("CVE-2099-0001")
    assert result.verdict.level == "UNKNOWN" and "wasn't found" in result.verdict.headline


def test_malicious_ip_combines_sources():
    result = go(fakes.BAD_IP, fakes.router({"urlhaus": (200, fakes.NO_RESULT)}))
    ids = signal_ids(result)
    assert {"vt_malicious", "abuseipdb", "threatfox", "otx", "corroborated", "recent_activity"} <= ids
    assert result.verdict.level == "CRITICAL"
    assert "reported by" in result.verdict.headline


def test_old_evidence_lowers_score():
    old = (datetime.now(timezone.utc) - timedelta(days=500)).isoformat()
    fresh = go(fakes.BAD_IP, fakes.router({"virustotal": (200, fakes.VT_CLEAN), "urlhaus": (200, fakes.NO_RESULT)}))
    stale = go(fakes.BAD_IP, fakes.router({"virustotal": (200, fakes.VT_CLEAN), "urlhaus": (200, fakes.NO_RESULT),
                                           "threatfox": (200, fakes.NO_RESULT)}, recent=old))
    assert "stale_evidence" in signal_ids(stale)
    assert stale.verdict.score < fresh.verdict.score


def test_clean_known_good_ip():
    clean = {"virustotal": (200, fakes.VT_CLEAN), "otx": (200, fakes.OTX_EMPTY), "threatfox": (200, fakes.NO_RESULT),
             "urlhaus": (200, fakes.NO_RESULT),
             "abuseipdb": (200, {"data": {"abuseConfidenceScore": 0, "totalReports": 0, "isWhitelisted": True}})}
    result = go("8.8.8.8", fakes.router(clean))
    assert result.verdict.score == 0 and result.verdict.level == "LOW"
    assert "appears legitimate" in result.verdict.headline
    assert "known_good" in signal_ids(result)


def test_private_ip_is_never_sent_out():
    calls: list[str] = []
    result = go("192.168.1.20", fakes.router(calls=calls))
    assert calls == [] and result.sources == []
    assert result.verdict.level == "UNKNOWN"
    assert any("Private address" in step.title for step in result.trace)


def test_malware_hash_floor():
    result = go(fakes.BAD_SHA256, fakes.router({"virustotal": (404, {}), "otx": (200, fakes.OTX_EMPTY),
                                                "threatfox": (200, fakes.NO_RESULT)}))
    assert result.verdict.score == 70 and result.verdict.level == "HIGH"
    assert "confirmed malware" in result.verdict.rules_applied[0]


def test_user_content_platform_caution():
    result = go("login-update.github.io", fakes.router({"virustotal": (200, fakes.VT_CLEAN), "otx": (200, fakes.OTX_EMPTY),
                                                         "threatfox": (200, fakes.NO_RESULT), "urlhaus": (200, fakes.NO_RESULT)}))
    assert any("anyone can publish" in r for r in result.verdict.rules_applied)
    assert "known_good" not in signal_ids(result)


def test_every_source_down_is_unknown_not_safe():
    down = {k: (500, {}) for k in ["abuseipdb", "virustotal", "otx", "threatfox", "urlhaus"]}
    result = go(fakes.BAD_IP, fakes.router(down))
    assert result.verdict.level == "UNKNOWN" and result.verdict.confidence == "low"


def test_partial_failure_still_produces_result():
    result = go(fakes.BAD_IP, fakes.router({"virustotal": (429, {}), "otx": (500, {})}))
    statuses = {s.source: s.status for s in result.sources}
    assert statuses["VirusTotal"] == SourceStatus.RATE_LIMITED
    assert result.verdict.level in {"HIGH", "CRITICAL"}
    assert result.verdict.confidence == "medium"


def test_trace_records_decisions_in_order():
    result = go(fakes.BAD_IP)
    kinds = [step.kind for step in result.trace]
    assert kinds[0] == "detect" and kinds[1] == "decide"
    assert kinds.count("fetch") == 5
    assert kinds[-3:] == ["score", "verdict", "save"]
    assert [s.step for s in result.trace] == list(range(1, len(result.trace) + 1))


def test_second_lookup_uses_cache_and_is_saved():
    store = MemoryStore()
    calls: list[str] = []
    first = go(fakes.BAD_IP, fakes.router(calls=calls), store)
    count = len(calls)
    second = go(fakes.BAD_IP, fakes.router(calls=calls), store)
    assert len(calls) == count  # nothing fetched again
    assert all(s.cached for s in second.sources)
    assert second.verdict.score == first.verdict.score
    assert asyncio.run(store.get(first.id)) is not None
    assert len(asyncio.run(store.recent(10))) == 2


def test_errors_are_not_cached():
    store = MemoryStore()
    go(fakes.BAD_IP, fakes.router({"virustotal": (429, {})}), store)
    retry = go(fakes.BAD_IP, fakes.router(), store)
    vt = next(s for s in retry.sources if s.source == "VirusTotal")
    assert vt.status == SourceStatus.OK and not vt.cached
