"""The home-page numbers: visitors, investigations, bulk lookups, knowledge entries."""
import asyncio
import os
import uuid

import pytest
from fastapi.testclient import TestClient

from app import main
from app.store import MemoryStore
from tests import fakes


@pytest.fixture
def client(monkeypatch):
    main.limiter.reset()
    main._numbers.update(at=0.0, data=None)
    monkeypatch.setattr(main, "settings", fakes.test_settings())
    test_client = TestClient(main.app)
    test_client.__enter__()
    main.app.state.http = fakes.router()
    main.app.state.store = MemoryStore()
    yield test_client
    test_client.__exit__(None, None, None)
    main._numbers.update(at=0.0, data=None)


def hello(client, visitor, address="1.2.3.4"):
    return client.post("/api/numbers/visitor", json={"visitor": visitor}, headers={"x-forwarded-for": address})


def test_numbers_start_at_zero(client):
    assert client.get("/api/numbers").json() == {
        "visitors": 0, "investigations": 0, "bulk_lookups": 0, "knowledge_entries": 0}


def test_same_browser_counts_once(client):
    me = str(uuid.uuid4())
    assert hello(client, me).json()["visitors"] == 1
    assert hello(client, me).json()["visitors"] == 1
    assert hello(client, me.upper()).json()["visitors"] == 1
    assert hello(client, str(uuid.uuid4())).json()["visitors"] == 2


def test_only_a_hash_is_stored(client):
    me = str(uuid.uuid4())
    hello(client, me)
    stored = next(iter(main.app.state.store.visitors))
    assert me not in stored and len(stored) == 64


def test_investigations_are_counted(client):
    client.post("/api/investigations", json={"query": fakes.LOG4SHELL})
    assert hello(client, str(uuid.uuid4())).json()["investigations"] == 1


@pytest.mark.parametrize("bad", ["", "1.2.3.4", "<script>alert(1)</script>", "x" * 36, "a" * 200])
def test_rejects_anything_but_a_random_id(client, bad):
    assert hello(client, bad).status_code == 422


def test_one_address_cannot_inflate_the_count(client):
    limit = main.settings.visitor_ids_per_hour_per_address
    for _ in range(limit + 5):
        hello(client, str(uuid.uuid4()))
    assert client.get("/api/numbers").json()["visitors"] == limit
    # A different address still counts
    assert hello(client, str(uuid.uuid4()), address="5.6.7.8").json()["visitors"] == limit + 1


@pytest.mark.skipif(not os.environ.get("TEST_DATABASE_URL"), reason="set TEST_DATABASE_URL")
def test_numbers_in_the_database():
    from app.store import PostgresStore
    store = PostgresStore(os.environ["TEST_DATABASE_URL"])
    asyncio.run(store.init())
    try:
        before = asyncio.run(store.site_numbers())
        id_hash = uuid.uuid4().hex * 2
        asyncio.run(store.note_visitor(id_hash))
        asyncio.run(store.note_visitor(id_hash))
        after = asyncio.run(store.site_numbers())
        assert after["visitors"] == before["visitors"] + 1
        assert set(after) == {"visitors", "investigations", "bulk_lookups", "knowledge_entries"}
        with store.connection() as conn:
            conn.execute("DELETE FROM site_visitors WHERE id_hash = %s", (id_hash,))
    finally:
        asyncio.run(store.close())
