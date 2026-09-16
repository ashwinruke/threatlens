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
