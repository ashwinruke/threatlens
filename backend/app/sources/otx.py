"""AlienVault OTX: community "pulses" that link indicators to campaigns and malware."""
import httpx2

from app.models import Indicator, IndicatorType
from app.sources.base import NotFound, Source

BASE = "https://otx.alienvault.com/api/v1/indicators"


def _names(items: list) -> list[str]:
    """OTX sometimes returns plain strings and sometimes objects. Handle both."""
    out = []
    for item in items or []:
        name = item.get("display_name") or item.get("name") or item.get("id") if isinstance(item, dict) else item
        if name and name not in out:
            out.append(str(name))
    return out


class OTXSource(Source):
    name = "AlienVault OTX"
    supports = {IndicatorType.IP, IndicatorType.DOMAIN, IndicatorType.HASH}
    api_key_setting = "otx_api_key"

    def _section(self, indicator: Indicator) -> str:
        if indicator.type == IndicatorType.IP:
            return "IPv6" if indicator.subtype == "ipv6" else "IPv4"
        return "domain" if indicator.type == IndicatorType.DOMAIN else "file"

    def link(self, indicator: Indicator) -> str:
        kind = {IndicatorType.IP: "ip", IndicatorType.DOMAIN: "domain", IndicatorType.HASH: "file"}[indicator.type]
        return f"https://otx.alienvault.com/indicator/{kind}/{indicator.value}"

    async def lookup(self, indicator: Indicator, client: httpx2.AsyncClient) -> dict:
        url = f"{BASE}/{self._section(indicator)}/{indicator.value}/general"
        response = await client.get(url, headers={"X-OTX-API-KEY": self.api_key})
        if response.status_code == 404:
            raise NotFound("OTX has no record of this.")
        response.raise_for_status()
        pulse_info = response.json().get("pulse_info") or {}
        pulses = pulse_info.get("pulses") or []
        count = pulse_info.get("count", len(pulses))
        if not count:
            raise NotFound("No OTX community reports mention this.")

        families, techniques, adversaries, tags = [], [], [], []
        for pulse in pulses:
            families += _names(pulse.get("malware_families"))
            techniques += _names(pulse.get("attack_ids"))
            if pulse.get("adversary"):
                adversaries.append(pulse["adversary"])
            tags += [t for t in pulse.get("tags", []) if isinstance(t, str)]
        dates = sorted(p.get("modified") or p.get("created") for p in pulses if p.get("modified") or p.get("created"))

        def unique(values: list[str], limit: int) -> list[str]:
            return list(dict.fromkeys(values))[:limit]

        return {
            "pulse_count": count,
            "recent_pulses": [p.get("name") for p in pulses[:5] if p.get("name")],
            "malware_families": unique(families, 10),
            "attack_techniques": unique(techniques, 15),
            "adversaries": unique(adversaries, 5),
            "tags": unique(tags, 15),
            "last_pulse": dates[-1] if dates else None,
        }
