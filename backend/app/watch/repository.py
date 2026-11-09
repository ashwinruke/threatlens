"""Saving and loading watchlists and alerts, in memory (tests, local runs) or in Postgres."""
import asyncio
import hashlib
import hmac
import uuid
from datetime import datetime

from psycopg.types.json import Jsonb

from app.watch.models import Alert, Watchlist


def hash_key(key: str) -> str:
    return hashlib.sha256(f"threatlens-watchlist:{key}".encode()).hexdigest()


def key_matches(key: str | None, key_hash: str) -> bool:
    return bool(key) and hmac.compare_digest(hash_key(key), key_hash)


def _valid_uuid(value: str) -> bool:
    try:
        uuid.UUID(value)
        return True
    except (ValueError, TypeError):
        return False


class MemoryWatchRepository:
    def __init__(self) -> None:
        self.watchlists: dict[str, tuple[str, Watchlist]] = {}
        self.alerts: dict[str, Alert] = {}

    async def create(self, watchlist: Watchlist, key_hash: str) -> Watchlist:
        watchlist.id = str(uuid.uuid4())
        self.watchlists[watchlist.id] = (key_hash, watchlist)
        return watchlist

    async def get(self, watchlist_id: str) -> tuple[str, Watchlist] | None:
        found = self.watchlists.get(watchlist_id)
        return (found[0], found[1].model_copy(deep=True)) if found else None

    async def update(self, watchlist: Watchlist) -> None:
        key_hash, _ = self.watchlists[watchlist.id]
        self.watchlists[watchlist.id] = (key_hash, watchlist.model_copy(deep=True))

    async def delete(self, watchlist_id: str) -> None:
        self.watchlists.pop(watchlist_id, None)
        self.alerts = {k: a for k, a in self.alerts.items() if a.watchlist_id != watchlist_id}

    async def all(self) -> list[Watchlist]:
        return [w.model_copy(deep=True) for _, w in self.watchlists.values()]

    async def add_alert(self, alert: Alert) -> Alert | None:
        """Saves a new alert; None if this watchlist already has one for that indicator."""
        if any(a.watchlist_id == alert.watchlist_id and a.indicator == alert.indicator for a in self.alerts.values()):
            return None
        alert.id = str(uuid.uuid4())
        self.alerts[alert.id] = alert.model_copy(deep=True)
        return alert

    async def find_alert(self, watchlist_id: str, indicator: str) -> Alert | None:
        return next((a.model_copy(deep=True) for a in self.alerts.values()
                     if a.watchlist_id == watchlist_id and a.indicator == indicator), None)

    async def get_alert(self, watchlist_id: str, alert_id: str) -> Alert | None:
        alert = self.alerts.get(alert_id)
        return alert.model_copy(deep=True) if alert and alert.watchlist_id == watchlist_id else None

    async def update_alert(self, alert: Alert) -> None:
        self.alerts[alert.id] = alert.model_copy(deep=True)

    async def alerts_for(self, watchlist_id: str, limit: int = 200) -> list[Alert]:
        mine = [a for a in self.alerts.values() if a.watchlist_id == watchlist_id]
        return [a.model_copy(deep=True) for a in sorted(mine, key=lambda a: a.found_at, reverse=True)[:limit]]


class PostgresWatchRepository:
    def __init__(self, store) -> None:
        self.store = store

    async def _run(self, fn):
        return await asyncio.to_thread(fn)

    async def create(self, watchlist: Watchlist, key_hash: str) -> Watchlist:
        def run():
            with self.store.connection() as conn:
                return conn.execute("INSERT INTO watchlists (key_hash, data) VALUES (%s, %s) RETURNING id",
                                    (key_hash, Jsonb(watchlist.model_dump(mode="json", exclude={"id"})))).fetchone()
        watchlist.id = str((await self._run(run))["id"])
        return watchlist

    async def get(self, watchlist_id: str) -> tuple[str, Watchlist] | None:
        if not _valid_uuid(watchlist_id):
            return None

        def run():
            with self.store.connection() as conn:
                return conn.execute("SELECT id, key_hash, data FROM watchlists WHERE id = %s", (watchlist_id,)).fetchone()
        row = await self._run(run)
        return (row["key_hash"], Watchlist.model_validate({**row["data"], "id": str(row["id"])})) if row else None

    async def update(self, watchlist: Watchlist) -> None:
        def run():
            with self.store.connection() as conn:
                conn.execute("UPDATE watchlists SET data = %s, last_checked_at = %s WHERE id = %s",
                             (Jsonb(watchlist.model_dump(mode="json", exclude={"id"})), watchlist.last_checked_at, watchlist.id))
        await self._run(run)

    async def delete(self, watchlist_id: str) -> None:
        if not _valid_uuid(watchlist_id):
            return

        def run():
            with self.store.connection() as conn:
                conn.execute("DELETE FROM watchlists WHERE id = %s", (watchlist_id,))
        await self._run(run)

    async def all(self) -> list[Watchlist]:
        def run():
            with self.store.connection() as conn:
                return conn.execute("SELECT id, data FROM watchlists ORDER BY created_at").fetchall()
        return [Watchlist.model_validate({**r["data"], "id": str(r["id"])}) for r in await self._run(run)]

    async def add_alert(self, alert: Alert) -> Alert | None:
        def run():
            with self.store.connection() as conn:
                return conn.execute(
                    "INSERT INTO watch_alerts (watchlist_id, indicator, data, status, found_at) VALUES (%s, %s, %s, %s, %s) "
                    "ON CONFLICT (watchlist_id, indicator) DO NOTHING RETURNING id",
                    (alert.watchlist_id, alert.indicator, Jsonb(alert.model_dump(mode="json", exclude={"id"})),
                     alert.status, alert.found_at)).fetchone()
        row = await self._run(run)
        if not row:
            return None
        alert.id = str(row["id"])
        return alert

    def _alert(self, row) -> Alert:
        return Alert.model_validate({**row["data"], "id": str(row["id"]), "status": row["status"]})

    async def find_alert(self, watchlist_id: str, indicator: str) -> Alert | None:
        def run():
            with self.store.connection() as conn:
                return conn.execute("SELECT id, data, status FROM watch_alerts WHERE watchlist_id = %s AND indicator = %s",
                                    (watchlist_id, indicator)).fetchone()
        row = await self._run(run)
        return self._alert(row) if row else None

    async def get_alert(self, watchlist_id: str, alert_id: str) -> Alert | None:
        if not _valid_uuid(alert_id):
            return None

        def run():
            with self.store.connection() as conn:
                return conn.execute("SELECT id, data, status FROM watch_alerts WHERE watchlist_id = %s AND id = %s",
                                    (watchlist_id, alert_id)).fetchone()
        row = await self._run(run)
        return self._alert(row) if row else None

    async def update_alert(self, alert: Alert) -> None:
        def run():
            with self.store.connection() as conn:
                conn.execute("UPDATE watch_alerts SET data = %s, status = %s WHERE id = %s",
                             (Jsonb(alert.model_dump(mode="json", exclude={"id"})), alert.status, alert.id))
        await self._run(run)

    async def alerts_for(self, watchlist_id: str, limit: int = 200) -> list[Alert]:
        def run():
            with self.store.connection() as conn:
                return conn.execute("SELECT id, data, status FROM watch_alerts WHERE watchlist_id = %s "
                                    "ORDER BY found_at DESC LIMIT %s", (watchlist_id, limit)).fetchall()
        return [self._alert(r) for r in await self._run(run)]


def repository_for(store):
    """One repository per store, kept on the store object."""
    repo = getattr(store, "_watch_repository", None)
    if repo is None:
        repo = PostgresWatchRepository(store) if hasattr(store, "connection") else MemoryWatchRepository()
        store._watch_repository = repo
    return repo


def parse_time(value) -> datetime | None:
    if value is None or isinstance(value, datetime):
        return value
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
