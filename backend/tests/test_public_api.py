"""The public API: keys, authentication, allowances, lookups, rules and STIX."""
import asyncio
import json
import os

import pytest
import stix2
from fastapi.testclient import TestClient

from app import main, public_api
from app.store import MemoryStore
from tests import fakes


@pytest.fixture
def api(monkeypatch):
    main.limiter.reset()
    monkeypatch.setattr(main, "settings", fakes.test_settings(public_site_url="https://threatlens.example"))
    client = TestClient(main.app)
    client.__enter__()
    main.app.state.http = fakes.router()
    main.app.state.store = MemoryStore()
    yield client
    client.__exit__(None, None, None)


def new_key(api, name="SOC enrichment"):
    response = api.post("/api/keys", json={"name": name})
    assert response.status_code == 201, response.text
    return response.json()


def auth(key):
    return {"Authorization": f"Bearer {key['key']}"}


# ---------- Keys ----------

def test_a_key_is_shown_once_and_stored_hashed(api):
    key = new_key(api)
    assert key["key"].startswith("tl_") and len(key["key"]) > 40
    assert key["prefix"] == key["key"][:10] and key["daily_limit"] == main.settings.api_daily_units
    stored = main.app.state.store._api_keys.keys
    assert key["key"] not in json.dumps({k: v.__dict__ for k, v in stored.items()}, default=str)


def test_making_keys_is_limited(api):
    for _ in range(main.settings.api_keys_per_day_per_visitor):
        new_key(api)
    assert api.post("/api/keys", json={"name": "one more"}).status_code == 429


@pytest.mark.parametrize("headers,message", [
    ({}, "Send your API key"),
    ({"Authorization": "Bearer not-a-key"}, "isn't a ThreatLens API key"),
    ({"Authorization": "Bearer tl_made_up_key_that_was_never_issued"}, "doesn't exist"),
])
def test_requests_without_a_valid_key_are_refused(api, headers, message):
    response = api.get("/v1/usage", headers=headers)
    assert response.status_code == 401 and message in response.json()["detail"]
    assert "threatlens-xi.vercel.app/developers" in response.json()["detail"]
    assert response.headers["www-authenticate"] == "Bearer"


def test_x_api_key_header_also_works(api):
    key = new_key(api)
    assert api.get("/v1/usage", headers={"X-API-Key": key["key"]}).status_code == 200


def test_revoked_keys_stop_working(api):
    key = new_key(api)
    assert api.delete("/v1/key", headers=auth(key)).status_code == 204
    assert api.get("/v1/usage", headers=auth(key)).status_code == 401


# ---------- Lookups ----------

def test_lookup_returns_the_stable_shape(api):
    key = new_key(api)
    response = api.post("/v1/lookup", headers=auth(key), json={"indicator": fakes.LOG4SHELL})
    assert response.status_code == 200
    data = response.json()
    assert set(data) == {"id", "indicator", "verdict", "signals", "sources", "ai_summary", "threat", "report_url", "links", "created_at"}
    assert data["indicator"] == {"type": "cve", "value": "CVE-2021-44228", "subtype": None}
    assert data["verdict"]["level"] == "CRITICAL" and data["signals"][0]["points"] > 0
    assert {s["name"] for s in data["sources"]} >= {"NVD", "CISA KEV"}
    assert data["ai_summary"] is None  # not asked for
    assert data["report_url"] == f"https://threatlens.example/i/{data['id']}"
    assert data["links"]["rules"] == f"/v1/investigations/{data['id']}/rules"
    assert response.headers["x-ratelimit-remaining"] == str(main.settings.api_daily_units - 1)


def test_api_lookups_stay_out_of_the_public_history(api):
    key = new_key(api)
    api.post("/v1/lookup", headers=auth(key), json={"indicator": fakes.BAD_IP})
    assert api.get("/api/investigations").json() == []


def test_lookup_with_ai_summary(api):
    main.settings.gemini_api_key = "g"
    main.app.state.http = fakes.router({"gemini": (200, fakes.gemini_body(fakes.GOOD_REPORT))})
    key = new_key(api)
    data = api.post("/v1/lookup", headers=auth(key), json={"indicator": fakes.LOG4SHELL, "ai_summary": True}).json()
    assert data["ai_summary"]["status"] == "ready" and data["ai_summary"]["summary"]


def test_bad_input_is_a_clear_422(api):
    key = new_key(api)
    response = api.post("/v1/lookup", headers=auth(key), json={"indicator": "8.8.8.8 and 1.1.1.1"})
    assert response.status_code == 422


def test_batch_keeps_order_and_reports_bad_items(api):
    key = new_key(api)
    data = api.post("/v1/lookup/batch", headers=auth(key),
                    json={"indicators": [fakes.BAD_IP, "8.8.8.8 and 1.1.1.1", fakes.LOG4SHELL]}).json()
    assert data["count"] == 3
    assert [r["ok"] for r in data["results"]] == [True, False, True]
    assert data["results"][2]["result"]["indicator"]["value"] == "CVE-2021-44228"
    usage = api.get("/v1/usage", headers=auth(key)).json()
    assert usage["used_today"] == 3


def test_batch_size_is_capped(api):
    key = new_key(api)
    assert api.post("/v1/lookup/batch", headers=auth(key), json={"indicators": ["8.8.8.8"] * 21}).status_code == 422


# ---------- Allowances ----------

def test_daily_allowance(api, monkeypatch):
    monkeypatch.setattr(main.settings, "api_daily_units", 2)
    key = new_key(api)
    assert api.post("/v1/lookup", headers=auth(key), json={"indicator": fakes.BAD_IP}).status_code == 200
    assert api.post("/v1/lookup/batch", headers=auth(key), json={"indicators": ["8.8.8.8", "1.1.1.1"]}).status_code == 429
    assert api.post("/v1/lookup", headers=auth(key), json={"indicator": fakes.LOG4SHELL}).status_code == 200
    refused = api.post("/v1/lookup", headers=auth(key), json={"indicator": fakes.LOG4SHELL})
    assert refused.status_code == 429 and "midnight UTC" in refused.json()["detail"]
    assert api.get("/v1/usage", headers=auth(key)).json()["remaining_today"] == 0
    other = new_key(api, "another tool")  # each key has its own allowance
    assert api.post("/v1/lookup", headers=auth(other), json={"indicator": fakes.BAD_IP}).status_code == 200


def test_per_minute_limit(api, monkeypatch):
    monkeypatch.setattr(main.settings, "api_requests_per_minute", 3)
    key = new_key(api)
    codes = [api.get("/v1/usage", headers=auth(key)).status_code for _ in range(4)]
    assert codes == [200, 200, 200, 429]


def test_the_api_shares_the_sites_daily_ceiling(api, monkeypatch):
    monkeypatch.setattr(main.settings, "daily_investigation_cap", 1)
    key = new_key(api)
    assert api.post("/v1/lookup", headers=auth(key), json={"indicator": fakes.BAD_IP}).status_code == 200
    assert api.post("/v1/lookup", headers=auth(key), json={"indicator": fakes.LOG4SHELL}).status_code == 503


# ---------- Reports, rules, STIX ----------

def test_fetch_report_rules_and_stix(api):
    key = new_key(api)
    found = api.post("/v1/lookup", headers=auth(key), json={"indicator": fakes.BAD_IP}).json()
    again = api.get(f"/v1/investigations/{found['id']}", headers=auth(key)).json()
    assert again["verdict"] == found["verdict"]
    rules = api.get(f"/v1/investigations/{found['id']}/rules", headers=auth(key)).json()
    assert fakes.BAD_IP in rules["sigma"] and rules["rules"][0]["elastic"]
    bundle = api.get(f"/v1/investigations/{found['id']}/stix", headers=auth(key))
    assert bundle.headers["content-type"].startswith("application/stix+json")
    stix2.parse(bundle.text, allow_custom=True)  # ThreatLens adds x_threatlens_ properties, as STIX allows
    assert api.get("/v1/investigations/does-not-exist", headers=auth(key)).status_code == 404
    assert api.get(f"/v1/investigations/{found['id']}").status_code == 401  # the key is needed here too


def test_interactive_docs_list_the_api_with_its_key(api):
    schema = api.get("/openapi.json").json()
    assert {"/v1/lookup", "/v1/lookup/batch", "/v1/usage", "/v1/investigations/{investigation_id}/rules"} <= set(schema["paths"])
    assert schema["components"]["securitySchemes"]["HTTPBearer"]["scheme"] == "bearer"


@pytest.mark.skipif(not os.environ.get("TEST_DATABASE_URL"), reason="set TEST_DATABASE_URL")
def test_postgres_keys():
    from app.store import PostgresStore

    async def go():
        store = PostgresStore(os.environ["TEST_DATABASE_URL"])
        await store.init()
        keys = public_api.PostgresKeys(store)
        try:
            made = await keys.create(public_api.hash_key("tl_secret"), "db test", "tl_secret")
            found = await keys.find(public_api.hash_key("tl_secret"))
            assert found.id == made.id and found.name == "db test" and not found.revoked
            await keys.touch(found)
            await keys.revoke(found)
            assert (await keys.find(public_api.hash_key("tl_secret"))).revoked
            assert await keys.find(public_api.hash_key("tl_other")) is None
        finally:
            with store.connection() as conn:
                conn.execute("DELETE FROM api_keys WHERE name = 'db test'")
            await store.close()
    asyncio.run(go())
