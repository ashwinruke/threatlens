"""abuse.ch projects. One Auth-Key works for all three:

- ThreatFox: IOCs (IPs, domains, hashes) linked to malware families
- URLhaus: websites and IPs used to spread malware
- MalwareBazaar: a database of real malware samples (by hash)
"""
import httpx2

from app.models import Indicator, IndicatorType
from app.sources.base import NotFound, Source

THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
URLHAUS_HOST_URL = "https://urlhaus-api.abuse.ch/v1/host/"
MALWAREBAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"


class _AbuseChSource(Source):
    api_key_setting = "abusech_auth_key"

    @property
    def headers(self) -> dict:
        return {"Auth-Key": self.api_key}


class ThreatFoxSource(_AbuseChSource):
    name = "ThreatFox"
    supports = {IndicatorType.IP, IndicatorType.DOMAIN, IndicatorType.HASH}

    def link(self, indicator: Indicator) -> str:
        prefix = "ioc" if indicator.type != IndicatorType.HASH else "hash"
        return f"https://threatfox.abuse.ch/browse.php?search={prefix}%3A{indicator.value}"

    @staticmethod
    def _matches(ioc: str, value: str) -> bool:
        # ThreatFox stores IPs as "1.2.3.4:443" and search is not always exact
        return ioc == value or ioc.startswith(value + ":") or f"//{value}" in ioc

    async def lookup(self, indicator: Indicator, client: httpx2.AsyncClient) -> dict:
        if indicator.type == IndicatorType.HASH:
            body = {"query": "search_hash", "hash": indicator.value}
        else:
            body = {"query": "search_ioc", "search_term": indicator.value}
        response = await client.post(THREATFOX_URL, json=body, headers=self.headers)
        response.raise_for_status()
        payload = response.json()
        if payload.get("query_status") != "ok" or not isinstance(payload.get("data"), list):
            raise NotFound("ThreatFox has no IOCs matching this.")

        rows = payload["data"]
        if indicator.type != IndicatorType.HASH:
            rows = [r for r in rows if self._matches(str(r.get("ioc", "")), indicator.value)]
        if not rows:
            raise NotFound("ThreatFox has no IOCs matching this.")

        first = sorted(r["first_seen"] for r in rows if r.get("first_seen"))
        last = sorted(r["last_seen"] or r.get("first_seen") for r in rows if r.get("last_seen") or r.get("first_seen"))
        return {
            "ioc_count": len(rows),
            "malware_families": list(dict.fromkeys(r["malware_printable"] for r in rows if r.get("malware_printable")))[:10],
            "threat_types": list(dict.fromkeys(r["threat_type_desc"] for r in rows if r.get("threat_type_desc")))[:5],
            "max_confidence": max((r.get("confidence_level") or 0) for r in rows),
            "first_seen": first[0] if first else None,
            "last_seen": last[-1] if last else None,
            "tags": list(dict.fromkeys(t for r in rows for t in (r.get("tags") or [])))[:10],
        }


class URLhausSource(_AbuseChSource):
    name = "URLhaus"
    supports = {IndicatorType.IP, IndicatorType.DOMAIN}

    def link(self, indicator: Indicator) -> str:
        return f"https://urlhaus.abuse.ch/host/{indicator.value}/"

    async def lookup(self, indicator: Indicator, client: httpx2.AsyncClient) -> dict:
        response = await client.post(URLHAUS_HOST_URL, data={"host": indicator.value}, headers=self.headers)
        response.raise_for_status()
        payload = response.json()
        if payload.get("query_status") != "ok":
            raise NotFound("URLhaus has no malware URLs on this host.")
        urls = payload.get("urls") or []
        online = [u for u in urls if u.get("url_status") == "online"]
        dates = sorted(u["date_added"] for u in urls if u.get("date_added"))
        return {
            "url_count": int(payload.get("url_count") or len(urls)),
            "urls_online": len(online),
            "first_seen": payload.get("firstseen"),
            "last_added": dates[-1] if dates else None,
            "threats": list(dict.fromkeys(u["threat"] for u in urls if u.get("threat")))[:5],
            "tags": list(dict.fromkeys(t for u in urls for t in (u.get("tags") or [])))[:10],
            "blocklists": payload.get("blacklists") or {},
        }


class MalwareBazaarSource(_AbuseChSource):
    name = "MalwareBazaar"
    supports = {IndicatorType.HASH}

    def link(self, indicator: Indicator) -> str:
        return f"https://bazaar.abuse.ch/browse.php?search={indicator.subtype}%3A{indicator.value}"

    async def lookup(self, indicator: Indicator, client: httpx2.AsyncClient) -> dict:
        response = await client.post(MALWAREBAZAAR_URL, data={"query": "get_info", "hash": indicator.value},
                                     headers=self.headers)
        response.raise_for_status()
        payload = response.json()
        if payload.get("query_status") != "ok" or not payload.get("data"):
            raise NotFound("MalwareBazaar has no sample with this hash.")
        sample = payload["data"][0]
        return {
            "malware_family": sample.get("signature"),
            "file_name": sample.get("file_name"),
            "file_type": sample.get("file_type"),
            "sha256": sample.get("sha256_hash"),
            "first_seen": sample.get("first_seen"),
            "last_seen": sample.get("last_seen"),
            "delivery_method": sample.get("delivery_method"),
            "tags": (sample.get("tags") or [])[:10],
        }
