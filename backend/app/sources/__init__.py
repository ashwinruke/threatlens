"""All intelligence sources ThreatLens can use."""
from app.config import Settings
from app.models import IndicatorType
from app.sources.abusech import MalwareBazaarSource, ThreatFoxSource, URLhausSource
from app.sources.abuseipdb import AbuseIPDBSource
from app.sources.base import Source, run_source
from app.sources.epss import EPSSSource
from app.sources.kev import KEVSource
from app.sources.nvd import NVDSource
from app.sources.otx import OTXSource
from app.sources.virustotal import VirusTotalSource

ALL_SOURCES: list[type[Source]] = [
    NVDSource, KEVSource, EPSSSource,
    AbuseIPDBSource, VirusTotalSource, OTXSource, ThreatFoxSource, URLhausSource, MalwareBazaarSource,
]


def sources_for(indicator_type: IndicatorType, settings: Settings) -> list[Source]:
    return [cls(settings) for cls in ALL_SOURCES if indicator_type in cls.supports]


__all__ = ["Source", "run_source", "sources_for", "ALL_SOURCES"]
