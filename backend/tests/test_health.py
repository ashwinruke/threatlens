from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_root():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["name"] == "ThreatLens API"


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_health_db_without_database(monkeypatch):
    # With no DATABASE_URL, the endpoint should report it clearly, not crash
    monkeypatch.setattr("app.db.get_settings", lambda: type("S", (), {"database_url": ""})())
    response = client.get("/health/db")
    assert response.status_code == 503
    assert response.json()["status"] == "not_configured"


import pytest


@pytest.mark.parametrize("origin, allowed", [
    ("http://localhost:5173", True),  # the default CORS_ORIGINS
    ("https://threatlens-xi.vercel.app", True),  # production on Vercel
    ("https://threatlens-git-main-ashwinruke.vercel.app", True),  # a branch deployment
    ("https://threatlens-8f3k2j1-ashwinrukes-projects.vercel.app", True),  # a single deployment's own address
    ("http://127.0.0.1:4173", True),  # local preview
    ("https://evil.example", False),
    ("https://threatlens-xi.vercel.app.evil.example", False),
    ("https://notthreatlens.vercel.app", False),
])
def test_which_websites_may_read_the_api(origin, allowed):
    # The browser only lets a website read the answer when this header names it
    response = client.get("/health", headers={"Origin": origin})
    assert (response.headers.get("access-control-allow-origin") == origin) is allowed
    preflight = client.options("/api/investigations", headers={
        "Origin": origin, "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type"})
    assert (preflight.status_code == 200) is allowed
