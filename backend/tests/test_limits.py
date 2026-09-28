"""Usage limits that protect the free tiers, and the pinned example investigations."""
import pytest
from fastapi.testclient import TestClient

from app import main
from app.sources import kev
from app.store import MemoryStore
from tests import fakes

AI_KEYS = {"gemini_api_key": "g", "groq_api_key": "q"}


@pytest.fixture
def make_client(monkeypatch):
    kev.reset_catalog()
    main.limiter.reset()

    def build(**overrides):
        monkeypatch.setattr(main, "settings", fakes.test_settings(**{**AI_KEYS, **overrides}))
        client = TestClient(main.app)
        client.__enter__()
        main.app.state.http = fakes.router()
        main.app.state.store = MemoryStore()
        return client

    yield build


def investigate(client, query=fakes.LOG4SHELL, visitor="1.2.3.4"):
    return client.post("/api/investigations", json={"query": query}, headers={"x-forwarded-for": visitor})


def test_visitor_limit_blocks_and_explains(make_client):
    client = make_client(investigations_per_hour_per_visitor=2)
    assert investigate(client).status_code == 200
    assert investigate(client).status_code == 200
    blocked = investigate(client)
    assert blocked.status_code == 429
    assert "2 investigations allowed per hour" in blocked.json()["detail"]
    assert blocked.headers["retry-after"]


def test_limit_is_per_visitor(make_client):
    client = make_client(investigations_per_hour_per_visitor=1)
    assert investigate(client, visitor="1.1.1.1").status_code == 200
    assert investigate(client, visitor="1.1.1.1").status_code == 429
    assert investigate(client, visitor="2.2.2.2").status_code == 200


def test_detect_limit(make_client):
    client = make_client(detects_per_minute_per_visitor=2)
    for _ in range(2):
        assert client.post("/api/detect", json={"query": "8.8.8.8"}).status_code == 200
    assert client.post("/api/detect", json={"query": "8.8.8.8"}).status_code == 429


def test_daily_investigation_cap(make_client):
    client = make_client(daily_investigation_cap=1)
    assert investigate(client).status_code == 200
    stopped = investigate(client, query="CVE-2024-3094")
    assert stopped.status_code == 429 and "daily investigation limit" in stopped.json()["detail"]


def test_daily_ai_cap_keeps_the_investigation(make_client):
    client = make_client(daily_ai_report_cap=0)
    body = investigate(client).json()
    assert body["verdict"]["level"] == "CRITICAL"  # scoring is unaffected
    assert body["report"]["status"] == "unavailable"
    assert "daily AI summary limit" in body["report"]["message"]
    assert any(step["kind"] == "report" and step["status"] == "error" for step in body["trace"])


def test_ai_cap_counts_only_new_reports(make_client):
    client = make_client(daily_ai_report_cap=1)
    first = investigate(client).json()
    assert first["report"]["status"] == "ready" and not first["report"]["cached"]
    # The same evidence reuses the saved report, so it mustn't use up the daily allowance
    second = investigate(client).json()
    assert second["report"]["cached"] and second["report"]["status"] == "ready"
    third = investigate(client, query="CVE-2024-3094").json()
    assert third["report"]["status"] == "unavailable"


def test_examples_endpoint(make_client):
    client = make_client()
    assert client.get("/api/examples").json() == []
    created = investigate(client).json()
    main.app.state.store.pinned["log4shell"] = {
        "slot": "log4shell", "label": "Log4Shell", "note": "The 2021 flaw.", "position": 0,
        "investigation_id": created["id"],
    }
    examples = client.get("/api/examples").json()
    assert len(examples) == 1
    assert examples[0]["indicator_value"] == fakes.LOG4SHELL
    assert examples[0]["level"] == "CRITICAL" and examples[0]["label"] == "Log4Shell"
