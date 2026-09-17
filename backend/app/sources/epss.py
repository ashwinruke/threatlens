"""FIRST EPSS: the estimated probability that a CVE will be exploited in the next 30 days."""
import httpx2

from app.models import Indicator, IndicatorType
from app.sources.base import NotFound, Source

URL = "https://api.first.org/data/v1/epss"


class EPSSSource(Source):
    name = "FIRST EPSS"
    supports = {IndicatorType.CVE}

    def link(self, indicator: Indicator) -> str:
        return f"https://api.first.org/data/v1/epss?cve={indicator.value}"

    async def lookup(self, indicator: Indicator, client: httpx2.AsyncClient) -> dict:
        response = await client.get(URL, params={"cve": indicator.value})
        response.raise_for_status()
        data = response.json().get("data") or []
        if not data:
            raise NotFound("EPSS has no score for this CVE yet.")
        row = data[0]
        return {
            "probability": float(row["epss"]),
            "percentile": float(row["percentile"]),
            "score_date": row.get("date"),
        }
