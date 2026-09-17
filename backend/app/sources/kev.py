"""CISA KEV (Known Exploited Vulnerabilities): CVEs confirmed to be exploited in real attacks.

The whole catalog is one JSON file (about 1-2 MB). ThreatLens downloads it once,
keeps it in memory, and refreshes it every few hours instead of downloading it per search.
"""
import asyncio
import time

import httpx2

from app.models import Indicator, IndicatorType
from app.sources.base import NotFound, Source

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
REFRESH_SECONDS = 6 * 60 * 60

_catalog: dict[str, dict] = {}
_loaded_at: float = 0.0
_lock = asyncio.Lock()


async def get_catalog(client: httpx2.AsyncClient) -> dict[str, dict]:
    global _catalog, _loaded_at
    async with _lock:
        if _catalog and time.monotonic() - _loaded_at < REFRESH_SECONDS:
            return _catalog
        response = await client.get(URL)
        response.raise_for_status()
        entries = response.json().get("vulnerabilities", [])
        _catalog = {e["cveID"].upper(): e for e in entries if e.get("cveID")}
        _loaded_at = time.monotonic()
        return _catalog


def reset_catalog() -> None:
    """Used by tests."""
    global _catalog, _loaded_at
    _catalog, _loaded_at = {}, 0.0


class KEVSource(Source):
    name = "CISA KEV"
    supports = {IndicatorType.CVE}

    def link(self, indicator: Indicator) -> str:
        return f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={indicator.value}"

    async def lookup(self, indicator: Indicator, client: httpx2.AsyncClient) -> dict:
        catalog = await get_catalog(client)
        entry = catalog.get(indicator.value)
        if not entry:
            raise NotFound("Not in CISA's catalog of known exploited vulnerabilities.")
        return {
            "vulnerability_name": entry.get("vulnerabilityName"),
            "vendor": entry.get("vendorProject"),
            "product": entry.get("product"),
            "date_added": entry.get("dateAdded"),
            "due_date": entry.get("dueDate"),
            "required_action": entry.get("requiredAction"),
            "known_ransomware_use": entry.get("knownRansomwareCampaignUse") == "Known",
            "short_description": entry.get("shortDescription"),
        }
