"""Saving investigations and caching source answers.

Two interchangeable stores:
- PostgresStore: the real database (Neon), used when DATABASE_URL is set
- MemoryStore: keeps data in memory, used in tests or when no database is configured

The rest of ThreatLens doesn't care which one it's using.
"""
import asyncio
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

from app.models import Indicator, Investigation, InvestigationSummary, Report, SourceResult

SCHEMA_PATH = Path(__file__).with_name("schema.sql")


class MemoryStore:
    def __init__(self) -> None:
        self.investigations: dict[str, Investigation] = {}
        self.cache: dict[tuple[str, str, str], SourceResult] = {}
        self.reports: dict[str, tuple[datetime, Report]] = {}

    async def init(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def get_cached(self, source: str, indicator: Indicator, max_age: timedelta) -> SourceResult | None:
        result = self.cache.get((source, indicator.type, indicator.value))
        if result and result.fetched_at and datetime.now(timezone.utc) - result.fetched_at <= max_age:
            return result.model_copy(update={"cached": True})
        return None

    async def put_cache(self, indicator: Indicator, result: SourceResult) -> None:
        self.cache[(result.source, indicator.type, indicator.value)] = result

    async def get_report(self, key: str, max_age: timedelta) -> Report | None:
        entry = self.reports.get(key)
        if entry and datetime.now(timezone.utc) - entry[0] <= max_age:
            return entry[1]
        return None

    async def put_report(self, key: str, report: Report) -> None:
        self.reports[key] = (datetime.now(timezone.utc), report)

    async def save(self, investigation: Investigation) -> str:
        investigation.id = str(uuid.uuid4())
        self.investigations[investigation.id] = investigation
        return investigation.id

    async def get(self, investigation_id: str) -> Investigation | None:
        return self.investigations.get(investigation_id)

    async def recent(self, limit: int) -> list[InvestigationSummary]:
        items = sorted(self.investigations.values(), key=lambda i: i.created_at, reverse=True)[:limit]
        return [_summary(i) for i in items]


class PostgresStore:
    """Uses plain (non-async) psycopg inside worker threads.

    psycopg's async mode doesn't work with Windows' default event loop,
    so this keeps local development on Windows simple.

    A connection pool keeps a few connections open and reuses them. Opening a new
    secure connection to Neon for every query would add noticeable delay.
    """

    def __init__(self, database_url: str) -> None:
        self.database_url = database_url
        self.pool: ConnectionPool | None = None

    def _connect(self):
        if self.pool is None:
            raise RuntimeError("PostgresStore.init() must run before using the store.")
        return self.pool.connection()

    async def init(self) -> None:
        def run() -> None:
            self.pool = ConnectionPool(
                self.database_url,
                min_size=1,
                max_size=5,
                kwargs={"row_factory": dict_row, "connect_timeout": 15},
                # Neon closes idle connections when it sleeps; check each one before use
                check=ConnectionPool.check_connection,
                max_idle=240,
                open=False,
            )
            self.pool.open(wait=True, timeout=30)
            with self._connect() as conn:
                conn.execute(SCHEMA_PATH.read_text(encoding="utf-8"))
        await asyncio.to_thread(run)

    async def close(self) -> None:
        if self.pool is not None:
            await asyncio.to_thread(self.pool.close)

    async def get_cached(self, source: str, indicator: Indicator, max_age: timedelta) -> SourceResult | None:
        def run():
            with self._connect() as conn:
                return conn.execute(
                    "SELECT result FROM source_cache WHERE source = %s AND indicator_type = %s "
                    "AND indicator_value = %s AND fetched_at > now() - %s",
                    (source, indicator.type.value, indicator.value, max_age),
                ).fetchone()
        row = await asyncio.to_thread(run)
        return SourceResult.model_validate(row["result"]).model_copy(update={"cached": True}) if row else None

    async def put_cache(self, indicator: Indicator, result: SourceResult) -> None:
        def run() -> None:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO source_cache (source, indicator_type, indicator_value, result, fetched_at) "
                    "VALUES (%s, %s, %s, %s, now()) "
                    "ON CONFLICT (source, indicator_type, indicator_value) "
                    "DO UPDATE SET result = EXCLUDED.result, fetched_at = now()",
                    (result.source, indicator.type.value, indicator.value, Jsonb(result.model_dump(mode="json"))),
                )
        await asyncio.to_thread(run)

    async def get_report(self, key: str, max_age: timedelta) -> Report | None:
        def run():
            with self._connect() as conn:
                return conn.execute(
                    "SELECT report FROM ai_report_cache WHERE evidence_hash = %s AND created_at > now() - %s",
                    (key, max_age),
                ).fetchone()
        row = await asyncio.to_thread(run)
        return Report.model_validate(row["report"]) if row else None

    async def put_report(self, key: str, report: Report) -> None:
        def run() -> None:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO ai_report_cache (evidence_hash, report, created_at) VALUES (%s, %s, now()) "
                    "ON CONFLICT (evidence_hash) DO UPDATE SET report = EXCLUDED.report, created_at = now()",
                    (key, Jsonb(report.model_dump(mode="json"))),
                )
        await asyncio.to_thread(run)

    async def save(self, investigation: Investigation) -> str:
        def run() -> str:
            payload = investigation.model_dump(mode="json", exclude={"id"})
            with self._connect() as conn:
                row = conn.execute(
                    "INSERT INTO investigations (query, indicator_type, indicator_value, score, level, confidence, "
                    "result, duration_ms, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id",
                    (investigation.query, investigation.indicator.type.value, investigation.indicator.value,
                     investigation.verdict.score, investigation.verdict.level, investigation.verdict.confidence,
                     Jsonb(payload), investigation.duration_ms, investigation.created_at),
                ).fetchone()
            return str(row["id"])
        investigation.id = await asyncio.to_thread(run)
        return investigation.id

    async def get(self, investigation_id: str) -> Investigation | None:
        try:
            uuid.UUID(investigation_id)
        except ValueError:
            return None

        def run():
            with self._connect() as conn:
                return conn.execute("SELECT id, result FROM investigations WHERE id = %s", (investigation_id,)).fetchone()
        row = await asyncio.to_thread(run)
        if not row:
            return None
        return Investigation.model_validate({**row["result"], "id": str(row["id"])})

    async def recent(self, limit: int) -> list[InvestigationSummary]:
        def run():
            with self._connect() as conn:
                return conn.execute(
                    "SELECT id, query, indicator_type, indicator_value, score, level, created_at "
                    "FROM investigations ORDER BY created_at DESC LIMIT %s", (limit,),
                ).fetchall()
        rows = await asyncio.to_thread(run)
        return [InvestigationSummary(id=str(r["id"]), query=r["query"], indicator_type=r["indicator_type"],
                                     indicator_value=r["indicator_value"], score=r["score"], level=r["level"],
                                     created_at=r["created_at"]) for r in rows]


def _summary(i: Investigation) -> InvestigationSummary:
    return InvestigationSummary(id=i.id or "", query=i.query, indicator_type=i.indicator.type,
                                indicator_value=i.indicator.value, score=i.verdict.score,
                                level=i.verdict.level, created_at=i.created_at)
