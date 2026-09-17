"""VirusTotal: results from dozens of security vendors' scanners.

The free API is limited (a few requests per minute) and non-commercial,
which is one reason ThreatLens caches results.
"""
import httpx2

from app.models import Indicator, IndicatorType
from app.sources.base import NotFound, Source, unix_to_iso

BASE = "https://www.virustotal.com/api/v3"


class VirusTotalSource(Source):
    name = "VirusTotal"
    supports = {IndicatorType.IP, IndicatorType.DOMAIN, IndicatorType.HASH}
    api_key_setting = "virustotal_api_key"

    def link(self, indicator: Indicator) -> str:
        kind = {IndicatorType.IP: "ip-address", IndicatorType.DOMAIN: "domain", IndicatorType.HASH: "file"}[indicator.type]
        return f"https://www.virustotal.com/gui/{kind}/{indicator.value}"

    async def lookup(self, indicator: Indicator, client: httpx2.AsyncClient) -> dict:
        path = {IndicatorType.IP: "ip_addresses", IndicatorType.DOMAIN: "domains", IndicatorType.HASH: "files"}[indicator.type]
        response = await client.get(f"{BASE}/{path}/{indicator.value}", headers={"x-apikey": self.api_key})
        if response.status_code == 404:
            raise NotFound("VirusTotal has never seen this.")
        response.raise_for_status()
        attrs = response.json()["data"]["attributes"]
        stats = attrs.get("last_analysis_stats") or {}
        engines = sum(v for v in stats.values() if isinstance(v, int))

        facts = {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "engines_total": engines,
            "reputation": attrs.get("reputation"),
            "last_analysis": unix_to_iso(attrs.get("last_analysis_date")),
            "tags": (attrs.get("tags") or [])[:10],
        }
        if indicator.type == IndicatorType.IP:
            facts.update(country=attrs.get("country"), network_owner=attrs.get("as_owner"), asn=attrs.get("asn"))
        elif indicator.type == IndicatorType.DOMAIN:
            facts.update(registrar=attrs.get("registrar"), created=unix_to_iso(attrs.get("creation_date")))
        else:
            classification = attrs.get("popular_threat_classification") or {}
            facts.update(
                threat_label=classification.get("suggested_threat_label"),
                family_names=[n.get("value") for n in classification.get("popular_threat_name", [])][:5],
                file_type=attrs.get("type_description"),
                file_name=attrs.get("meaningful_name"),
                sha256=attrs.get("sha256"),
                first_seen=unix_to_iso(attrs.get("first_submission_date")),
            )
        return facts
