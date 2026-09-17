"""Check that every API key works, using one small, harmless request each.

Run from the backend folder:   python -m scripts.check_keys

It only prints "works" or the problem. It never prints your keys.
Test values are public and safe: Google's DNS IP (8.8.8.8) and Log4Shell (CVE-2021-44228).
"""
import httpx2

from app.config import get_settings

TIMEOUT = 20
settings = get_settings()


def nvd(client):
    r = client.get(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"cveId": "CVE-2021-44228"},
        headers={"apiKey": settings.nvd_api_key},
    )
    r.raise_for_status()
    return f"found {r.json().get('totalResults', 0)} result(s) for CVE-2021-44228"


def cisa_kev(client):
    r = client.get(
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    r.raise_for_status()
    return f"catalog has {len(r.json().get('vulnerabilities', []))} exploited vulnerabilities"


def epss(client):
    r = client.get("https://api.first.org/data/v1/epss", params={"cve": "CVE-2021-44228"})
    r.raise_for_status()
    data = r.json().get("data", [])
    return f"EPSS score {data[0]['epss']}" if data else "no EPSS data returned"


def abuseipdb(client):
    r = client.get(
        "https://api.abuseipdb.com/api/v2/check",
        params={"ipAddress": "8.8.8.8", "maxAgeInDays": 90},
        headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"},
    )
    r.raise_for_status()
    return f"8.8.8.8 abuse score {r.json()['data']['abuseConfidenceScore']}"


def otx(client):
    r = client.get(
        "https://otx.alienvault.com/api/v1/indicators/IPv4/8.8.8.8/general",
        headers={"X-OTX-API-KEY": settings.otx_api_key},
    )
    r.raise_for_status()
    return f"8.8.8.8 appears in {r.json().get('pulse_info', {}).get('count', 0)} pulses"


def virustotal(client):
    r = client.get(
        "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
        headers={"x-apikey": settings.virustotal_api_key},
    )
    r.raise_for_status()
    stats = r.json()["data"]["attributes"]["last_analysis_stats"]
    return f"8.8.8.8 flagged malicious by {stats.get('malicious', 0)} engines"


def abusech(client):
    r = client.post(
        "https://threatfox-api.abuse.ch/api/v1/",
        json={"query": "get_iocs", "days": 1},
        headers={"Auth-Key": settings.abusech_auth_key},
    )
    r.raise_for_status()
    body = r.json()
    if body.get("query_status") != "ok":
        raise RuntimeError(f"ThreatFox said: {body.get('query_status')}")
    return f"ThreatFox returned {len(body.get('data') or [])} IOCs from the last day"


def gemini(client):
    r = client.get(
        "https://generativelanguage.googleapis.com/v1beta/models",
        headers={"x-goog-api-key": settings.gemini_api_key},
    )
    r.raise_for_status()
    names = [m["name"].removeprefix("models/") for m in r.json().get("models", [])]
    flash = [n for n in names if "flash" in n]
    return "key works. Flash models: " + ", ".join(flash)


def groq(client):
    r = client.get(
        "https://api.groq.com/openai/v1/models",
        headers={"Authorization": f"Bearer {settings.groq_api_key}"},
    )
    r.raise_for_status()
    names = sorted(m["id"] for m in r.json().get("data", []))
    return "key works. Some models: " + ", ".join(names)


# (name, function, key needed or None if the source is keyless)
CHECKS = [
    ("NVD", nvd, settings.nvd_api_key),
    ("CISA KEV", cisa_kev, None),
    ("FIRST EPSS", epss, None),
    ("AbuseIPDB", abuseipdb, settings.abuseipdb_api_key),
    ("AlienVault OTX", otx, settings.otx_api_key),
    ("VirusTotal", virustotal, settings.virustotal_api_key),
    ("abuse.ch", abusech, settings.abusech_auth_key),
    ("Gemini", gemini, settings.gemini_api_key),
    ("Groq", groq, settings.groq_api_key),
]


def main():
    passed = 0
    with httpx2.Client(timeout=TIMEOUT, headers={"User-Agent": "ThreatLens/0.1"}) as client:
        for name, check, key in CHECKS:
            if key is not None and not key:
                print(f"[ MISSING ] {name}: add its key to backend/.env")
                continue
            try:
                print(f"[  WORKS  ] {name}: {check(client)}")
                passed += 1
            except httpx2.HTTPStatusError as exc:
                code = exc.response.status_code
                if key is None and code == 403:
                    hint = "request blocked, check your internet or firewall"
                else:
                    hint = {401: "key is wrong", 403: "key refused or not activated yet",
                            429: "rate limit hit, wait a minute"}.get(code, "see the provider's status page")
                print(f"[ PROBLEM ] {name}: HTTP {code} ({hint})")
            except Exception as exc:
                print(f"[ PROBLEM ] {name}: {type(exc).__name__}: {exc}")
    print(f"\n{passed} of {len(CHECKS)} sources are working.")


if __name__ == "__main__":
    main()
