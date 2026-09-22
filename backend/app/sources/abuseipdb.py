"""AbuseIPDB: community reports of abusive IP addresses (scanning, brute force, spam...)."""
import httpx2

from app.models import Indicator, IndicatorType
from app.sources.base import Source

URL = "https://api.abuseipdb.com/api/v2/check"


class AbuseIPDBSource(Source):
    name = "AbuseIPDB"
    supports = {IndicatorType.IP}
    api_key_setting = "abuseipdb_api_key"

    def link(self, indicator: Indicator) -> str:
        return f"https://www.abuseipdb.com/check/{indicator.value}"

    async def lookup(self, indicator: Indicator, client: httpx2.AsyncClient) -> dict:
        response = await client.get(
            URL,
            params={"ipAddress": indicator.value, "maxAgeInDays": 90},
            headers={"Key": self.api_key, "Accept": "application/json"},
        )
        response.raise_for_status()
        data = response.json()["data"]
        return {
            "abuse_confidence": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "distinct_reporters": data.get("numDistinctUsers", 0),
            "last_reported": data.get("lastReportedAt"),
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "usage_type": data.get("usageType"),
            "domain": data.get("domain"),
            "is_tor": data.get("isTor", False),
            "is_allowlisted": bool(data.get("isWhitelisted")),
        }
