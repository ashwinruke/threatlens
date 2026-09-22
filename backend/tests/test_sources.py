"""Each source turns its service's response into normalized facts, and fails safely."""
import asyncio

import httpx2
import pytest

from app.detection import detect
from app.models import SourceStatus
from app.sources import kev, run_source
from app.sources.abusech import MalwareBazaarSource, ThreatFoxSource, URLhausSource
from app.sources.abuseipdb import AbuseIPDBSource
from app.sources.epss import EPSSSource
from app.sources.kev import KEVSource
from app.sources.nvd import NVDSource
from app.sources.otx import OTXSource
from app.sources.virustotal import VirusTotalSource
from tests import fakes


@pytest.fixture(autouse=True)
def clear_kev():
    kev.reset_catalog()


def run(source_cls, query, client, **settings):
    source = source_cls(fakes.test_settings(**settings))
    return asyncio.run(run_source(source, detect(query), client, timeout=5))


def test_nvd_normalizes_cve():
    result = run(NVDSource, fakes.LOG4SHELL, fakes.router())
    assert result.status == SourceStatus.OK
    assert result.facts["cvss"]["score"] == 10.0 and result.facts["cvss"]["version"] == "3.1"
    assert result.facts["weaknesses"] == ["CWE-20", "CWE-502"]
    assert result.facts["affected_products"] == ["apache log4j"]
    assert result.facts["references"][0]["tags"] == ["Vendor Advisory"]
    assert result.facts["nvd_lists_exploit_reference"]
    assert result.link == "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"


def test_nvd_unknown_cve_is_not_found():
    assert run(NVDSource, "CVE-2099-0001", fakes.router()).status == SourceStatus.NOT_FOUND


def test_kev_and_epss():
    client = fakes.router()
    kev_result = run(KEVSource, fakes.LOG4SHELL, client)
    assert kev_result.facts["known_ransomware_use"] is True
    assert run(KEVSource, "CVE-2099-0001", client).status == SourceStatus.NOT_FOUND
    epss = run(EPSSSource, fakes.LOG4SHELL, client)
    assert epss.facts["probability"] == pytest.approx(0.99999)


def test_kev_catalog_downloaded_once():
    calls: list[str] = []
    client = fakes.router(calls=calls)
    run(KEVSource, fakes.LOG4SHELL, client)
    run(KEVSource, "CVE-2099-0001", client)
    assert sum("known_exploited" in c for c in calls) == 1


def test_abuseipdb():
    result = run(AbuseIPDBSource, fakes.BAD_IP, fakes.router())
    assert result.facts["abuse_confidence"] == 100 and result.facts["total_reports"] == 812


def test_virustotal_ip_and_not_found():
    result = run(VirusTotalSource, fakes.BAD_IP, fakes.router())
    assert result.facts["malicious"] == 14 and result.facts["engines_total"] == 94
    missing = run(VirusTotalSource, fakes.BAD_SHA256, fakes.router({"virustotal": (404, {})}))
    assert missing.status == SourceStatus.NOT_FOUND


def test_otx_pulses_and_empty():
    result = run(OTXSource, fakes.BAD_IP, fakes.router())
    assert result.facts["malware_families"] == ["Mirai"]
    assert result.facts["attack_techniques"] == ["T1071 - Application Layer Protocol"]
    empty = run(OTXSource, fakes.BAD_IP, fakes.router({"otx": (200, fakes.OTX_EMPTY)}))
    assert empty.status == SourceStatus.NOT_FOUND


def test_threatfox_only_keeps_exact_matches():
    result = run(ThreatFoxSource, fakes.BAD_IP, fakes.router())
    assert result.facts["ioc_count"] == 1  # "45.95.147.23:80" must not match 45.95.147.236
    assert result.facts["malware_families"] == ["Mirai"]
    none = run(ThreatFoxSource, fakes.BAD_IP, fakes.router({"threatfox": (200, fakes.NO_RESULT)}))
    assert none.status == SourceStatus.NOT_FOUND


def test_urlhaus_and_malwarebazaar():
    urlhaus = run(URLhausSource, fakes.BAD_DOMAIN, fakes.router())
    assert urlhaus.facts["urls_online"] == 1 and urlhaus.facts["url_count"] == 3
    bazaar = run(MalwareBazaarSource, fakes.BAD_SHA256, fakes.router())
    assert bazaar.facts["malware_family"] == "AgentTesla"
    missing = run(MalwareBazaarSource, fakes.BAD_SHA256, fakes.router({"malwarebazaar": (200, {"query_status": "hash_not_found"})}))
    assert missing.status == SourceStatus.NOT_FOUND


@pytest.mark.parametrize("override, status", [
    ((429, {}), SourceStatus.RATE_LIMITED),
    ((401, {}), SourceStatus.ERROR),
    ((500, {}), SourceStatus.ERROR),
    ((200, {"unexpected": "shape"}), SourceStatus.ERROR),
    (httpx2.ConnectTimeout("slow"), SourceStatus.TIMEOUT),
    (httpx2.ConnectError("down"), SourceStatus.ERROR),
])
def test_failures_never_raise(override, status):
    result = run(AbuseIPDBSource, fakes.BAD_IP, fakes.router({"abuseipdb": override}))
    assert result.status == status and result.message


def test_missing_key_is_skipped_without_calling():
    calls: list[str] = []
    result = run(VirusTotalSource, fakes.BAD_IP, fakes.router(calls=calls), virustotal_api_key="")
    assert result.status == SourceStatus.SKIPPED and calls == []
