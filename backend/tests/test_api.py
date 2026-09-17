import pytest
from fastapi.testclient import TestClient

from app import main
from app.sources import kev
from app.store import MemoryStore
from tests import fakes


@pytest.fixture
def client(monkeypatch):
    kev.reset_catalog()
    monkeypatch.setattr(main, "settings", fakes.test_settings())
    with TestClient(main.app) as test_client:
        main.app.state.http = fakes.router()
        main.app.state.store = MemoryStore()
        yield test_client


def test_detect_endpoint(client):
    response = client.post("/api/detect", json={"query": "hxxps://evil[.]com"})
    assert response.status_code == 200
    assert response.json()["type"] == "domain" and response.json()["value"] == "evil.com"


def test_detect_rejects_gibberish(client):
    response = client.post("/api/detect", json={"query": "not a thing"})
    assert response.status_code == 422
    assert "more than one" in response.json()["detail"]


def test_investigation_roundtrip(client):
    created = client.post("/api/investigations", json={"query": fakes.LOG4SHELL})
    assert created.status_code == 200
    body = created.json()
    assert body["verdict"]["level"] == "CRITICAL" and body["id"]

    fetched = client.get(f"/api/investigations/{body['id']}")
    assert fetched.status_code == 200 and fetched.json()["verdict"]["score"] == body["verdict"]["score"]

    history = client.get("/api/investigations").json()
    assert history[0]["indicator_value"] == fakes.LOG4SHELL


def test_missing_investigation(client):
    assert client.get("/api/investigations/does-not-exist").status_code == 404


def test_query_length_limit(client):
    assert client.post("/api/investigations", json={"query": "a" * 501}).status_code == 422
