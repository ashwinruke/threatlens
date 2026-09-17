import asyncio
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone

import httpx2

from app.config import Settings
from app.models import Indicator, IndicatorType, SourceResult, SourceStatus


class NotFound(Exception):
    """The source answered normally but has no data about this indicator."""


class Source(ABC):
    name: str = ""
    supports: set[IndicatorType] = set()
    api_key_setting: str | None = None

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    @property
    def api_key(self) -> str:
        return getattr(self.settings, self.api_key_setting, "") if self.api_key_setting else ""

    def is_configured(self) -> bool:
        return self.api_key_setting is None or bool(self.api_key)

    @abstractmethod
    def link(self, indicator: Indicator) -> str | None:
        """A web page where a human can verify this source's data."""

    @abstractmethod
    async def lookup(self, indicator: Indicator, client: httpx2.AsyncClient) -> dict:
        """Return normalized facts, or raise NotFound."""


async def run_source(source: Source, indicator: Indicator, client: httpx2.AsyncClient,
                     timeout: float) -> SourceResult:
    started = time.perf_counter()

    def done(status: SourceStatus, facts: dict | None = None, message: str | None = None) -> SourceResult:
        return SourceResult(
            source=source.name, status=status, link=source.link(indicator), facts=facts or {},
            message=message, duration_ms=round((time.perf_counter() - started) * 1000),
            fetched_at=datetime.now(timezone.utc),
        )

    if not source.is_configured():
        return done(SourceStatus.SKIPPED, message=f"No API key set for {source.name}.")

    try:
        facts = await asyncio.wait_for(source.lookup(indicator, client), timeout=timeout)
        return done(SourceStatus.OK, facts)
    except NotFound as exc:
        return done(SourceStatus.NOT_FOUND, message=str(exc) or f"{source.name} has no record of this.")
    except (asyncio.TimeoutError, httpx2.TimeoutException):
        return done(SourceStatus.TIMEOUT, message=f"{source.name} didn't answer within {timeout:.0f} seconds.")
    except httpx2.HTTPStatusError as exc:
        code = exc.response.status_code
        if code == 429:
            return done(SourceStatus.RATE_LIMITED, message=f"{source.name} rate limit reached. Try again later.")
        if code in (401, 403):
            return done(SourceStatus.ERROR, message=f"{source.name} refused the API key (HTTP {code}).")
        return done(SourceStatus.ERROR, message=f"{source.name} returned an error (HTTP {code}).")
    except httpx2.RequestError as exc:
        return done(SourceStatus.ERROR, message=f"Couldn't connect to {source.name} ({type(exc).__name__}).")
    except Exception as exc:  # unexpected data shape, etc. Never crash the investigation.
        return done(SourceStatus.ERROR, message=f"{source.name} returned data ThreatLens couldn't read ({type(exc).__name__}).")


def unix_to_iso(value: int | float | None) -> str | None:
    if not value:
        return None
    return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()
