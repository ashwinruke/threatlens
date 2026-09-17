"""Realistic fake responses for every source, so tests never call real APIs.

Shapes follow each service's documented response format.
"""
import json
from datetime import datetime, timedelta, timezone

import httpx2

from app.config import Settings

LOG4SHELL = "CVE-2021-44228"
BAD_IP = "45.95.147.236"
BAD_DOMAIN = "malicious-example.xyz"
BAD_SHA256 = "a" * 64


def test_settings(**overrides) -> Settings:
    values = dict(
        nvd_api_key="k", abuseipdb_api_key="k", otx_api_key="k", virustotal_api_key="k",
        abusech_auth_key="k", database_url="", source_timeout_seconds=5,
    )
    values.update(overrides)
    return Settings(_env_file=None, **values)


NVD_LOG4SHELL = {
    "totalResults": 1,
    "vulnerabilities": [{"cve": {
        "id": LOG4SHELL, "vulnStatus": "Analyzed", "published": "2021-12-10T10:15:09.143",
        "lastModified": "2025-02-04T15:15:13.773",
        "descriptions": [{"lang": "en", "value": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP."}],
        "metrics": {"cvssMetricV31": [
            {"source": "nvd@nist.gov", "type": "Primary",
             "cvssData": {"version": "3.1", "baseScore": 10.0, "baseSeverity": "CRITICAL",
                          "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}}]},
        "weaknesses": [{"description": [{"lang": "en", "value": "CWE-502"}, {"lang": "en", "value": "CWE-20"}]}],
        "configurations": [{"nodes": [{"cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"},
            {"vulnerable": False, "criteria": "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*"}]}]}],
        "references": [{"url": "https://logging.apache.org/log4j/2.x/security.html", "tags": ["Vendor Advisory"]},
                       {"url": "http://packetstormsecurity.com/files/165225", "tags": ["Exploit", "Third Party Advisory"]}],
    }}],
}

KEV_CATALOG = {"vulnerabilities": [{
    "cveID": LOG4SHELL, "vendorProject": "Apache", "product": "Log4j2",
    "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability", "dateAdded": "2021-12-10",
    "shortDescription": "Log4j2 contains a vulnerability...", "requiredAction": "Apply updates per vendor instructions.",
    "dueDate": "2021-12-24", "knownRansomwareCampaignUse": "Known",
}]}

EPSS_LOG4SHELL = {"status": "OK", "data": [{"cve": LOG4SHELL, "epss": "0.999990000", "percentile": "1.000000000", "date": "2026-09-17"}]}

ABUSEIPDB_BAD = {"data": {
    "ipAddress": BAD_IP, "isPublic": True, "abuseConfidenceScore": 100, "countryCode": "NL", "usageType": "Data Center/Web Hosting/Transit",
    "isp": "Example Hosting", "domain": "example-hosting.nl", "isTor": False, "isWhitelisted": False,
    "totalReports": 812, "numDistinctUsers": 190, "lastReportedAt": "RECENT",
}}

VT_IP_BAD = {"data": {"attributes": {
    "last_analysis_stats": {"malicious": 14, "suspicious": 2, "harmless": 50, "undetected": 28, "timeout": 0},
    "reputation": -30, "country": "NL", "as_owner": "Example Hosting", "asn": 64500, "last_analysis_date": 1789000000,
}}}

VT_CLEAN = {"data": {"attributes": {
    "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 60, "undetected": 30, "timeout": 0},
    "reputation": 500, "country": "US", "as_owner": "GOOGLE",
}}}

OTX_BAD = {"pulse_info": {"count": 6, "pulses": [
    {"name": "Mirai botnet C2 servers", "tags": ["mirai", "botnet"], "modified": "RECENT",
     "malware_families": [{"id": "Mirai", "display_name": "Mirai"}],
     "attack_ids": [{"id": "T1071", "name": "Application Layer Protocol", "display_name": "T1071 - Application Layer Protocol"}],
     "adversary": ""},
]}}
OTX_EMPTY = {"pulse_info": {"count": 0, "pulses": []}}

THREATFOX_BAD = {"query_status": "ok", "data": [
    {"ioc": f"{BAD_IP}:8080", "threat_type_desc": "Botnet C2 server", "malware_printable": "Mirai",
     "confidence_level": 100, "first_seen": "2026-08-01 10:00:00 UTC", "last_seen": None, "tags": ["mirai"]},
    {"ioc": "45.95.147.23:80", "threat_type_desc": "Botnet C2 server", "malware_printable": "Other",
     "confidence_level": 50, "first_seen": "2026-08-01 10:00:00 UTC", "last_seen": None, "tags": []},
]}
NO_RESULT = {"query_status": "no_result", "data": "Your search did not yield any results"}

URLHAUS_BAD = {"query_status": "ok", "firstseen": "2026-08-01 10:00:00 UTC", "url_count": "3",
               "blacklists": {"spamhaus_dbl": "not listed", "surbl": "not listed"},
               "urls": [{"url": f"http://{BAD_DOMAIN}/x.exe", "url_status": "online", "date_added": "RECENT", "threat": "malware_download", "tags": ["exe"]},
                        {"url": f"http://{BAD_DOMAIN}/y.exe", "url_status": "offline", "date_added": "2026-08-01 10:00:00 UTC", "threat": "malware_download", "tags": []}]}

BAZAAR_BAD = {"query_status": "ok", "data": [{
    "sha256_hash": BAD_SHA256, "file_name": "invoice.exe", "file_type": "exe", "signature": "AgentTesla",
    "first_seen": "2026-09-01 08:00:00", "last_seen": None, "delivery_method": "email_attachment", "tags": ["AgentTesla"],
}]}


def router(overrides: dict | None = None, *, recent: str | None = None, calls: list | None = None):
    """Build a fake transport. overrides maps a source key to (status_code, json) or an exception."""
    overrides = overrides or {}
    recent = recent or (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()

    def respond(key: str, default):
        value = overrides.get(key, default)
        if isinstance(value, Exception):
            raise value
        status, body = value
        text = json.dumps(body).replace("RECENT", recent)
        return httpx2.Response(status, content=text, headers={"content-type": "application/json"})

    def handler(request: httpx2.Request) -> httpx2.Response:
        url = str(request.url)
        if calls is not None:
            calls.append(url)
        if "services.nvd.nist.gov" in url:
            return respond("nvd", (200, NVD_LOG4SHELL if LOG4SHELL in url else {"totalResults": 0, "vulnerabilities": []}))
        if "known_exploited_vulnerabilities" in url:
            return respond("kev", (200, KEV_CATALOG))
        if "api.first.org" in url:
            return respond("epss", (200, EPSS_LOG4SHELL if LOG4SHELL in url else {"status": "OK", "data": []}))
        if "abuseipdb.com" in url:
            return respond("abuseipdb", (200, ABUSEIPDB_BAD))
        if "virustotal.com" in url:
            return respond("virustotal", (200, VT_IP_BAD))
        if "otx.alienvault.com" in url:
            return respond("otx", (200, OTX_BAD))
        if "threatfox-api.abuse.ch" in url:
            return respond("threatfox", (200, THREATFOX_BAD))
        if "urlhaus-api.abuse.ch" in url:
            return respond("urlhaus", (200, URLHAUS_BAD))
        if "mb-api.abuse.ch" in url:
            return respond("malwarebazaar", (200, BAZAAR_BAD))
        return httpx2.Response(404)

    return httpx2.AsyncClient(transport=httpx2.MockTransport(handler))
