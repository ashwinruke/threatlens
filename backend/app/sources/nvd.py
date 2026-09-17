"""NVD (National Vulnerability Database): official CVE details and CVSS severity."""
import httpx2

from app.models import Indicator, IndicatorType
from app.sources.base import NotFound, Source

URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _best_cvss(metrics: dict) -> dict | None:
    """Prefer the newest CVSS version, and NVD's own ("Primary") score when present."""
    for key, version in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"),
                         ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        entries = metrics.get(key) or []
        if not entries:
            continue
        entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = entry.get("cvssData", {})
        return {
            "version": version,
            "score": data.get("baseScore"),
            # CVSS v2 stores severity outside cvssData
            "severity": data.get("baseSeverity") or entry.get("baseSeverity"),
            "vector": data.get("vectorString"),
            "scored_by": entry.get("source"),
        }
    return None


def _products(configurations: list) -> list[str]:
    """Turn CPE names like cpe:2.3:a:apache:log4j:2.14.1:... into 'apache log4j'."""
    seen: list[str] = []
    for config in configurations or []:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable"):
                    continue
                parts = match.get("criteria", "").split(":")
                if len(parts) > 5:
                    name = f"{parts[3]} {parts[4]}".replace("_", " ")
                    if name not in seen:
                        seen.append(name)
    return seen[:15]


class NVDSource(Source):
    name = "NVD"
    supports = {IndicatorType.CVE}
    api_key_setting = "nvd_api_key"

    def link(self, indicator: Indicator) -> str:
        return f"https://nvd.nist.gov/vuln/detail/{indicator.value}"

    async def lookup(self, indicator: Indicator, client: httpx2.AsyncClient) -> dict:
        response = await client.get(URL, params={"cveId": indicator.value},
                                    headers={"apiKey": self.api_key})
        response.raise_for_status()
        vulnerabilities = response.json().get("vulnerabilities") or []
        if not vulnerabilities:
            raise NotFound("NVD has no record of this CVE. Check the ID, or it may not be published yet.")
        cve = vulnerabilities[0]["cve"]
        description = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), None)
        weaknesses = sorted({
            d["value"] for w in cve.get("weaknesses", []) for d in w.get("description", [])
            if d.get("value", "").startswith("CWE-")
        })
        references = [
            {"url": r.get("url"), "tags": r.get("tags", [])}
            for r in cve.get("references", [])
        ]
        # Put the most useful references first: advisories, patches, exploits
        priority = {"Vendor Advisory": 0, "Patch": 1, "Exploit": 2, "Mitigation": 3}
        references.sort(key=lambda r: min((priority.get(t, 9) for t in r["tags"]), default=9))
        return {
            "id": cve.get("id"),
            "status": cve.get("vulnStatus"),
            "published": cve.get("published"),
            "last_modified": cve.get("lastModified"),
            "description": description,
            "cvss": _best_cvss(cve.get("metrics", {})),
            "weaknesses": weaknesses,
            "affected_products": _products(cve.get("configurations", [])),
            "references": references[:10],
            "has_exploit_reference": any("Exploit" in r["tags"] for r in references),
        }
