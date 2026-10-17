"""Bulk lookup: finding indicators in pasted text, investigating them, streaming rows, saved batches."""
import asyncio

import pytest
from fastapi.testclient import TestClient

from app import main
from app.bulk import BULK_AI_MESSAGE, plan, run_bulk
from app.sources import kev
from app.store import MemoryStore
from tests import fakes
from tests.test_stream import events

ALERT = """ALERT: Host WS-042 beaconed to hxxp://update-check[.]xyz/gate.php and 45.95.147.236:8080.
The dropper invoice.exe (SHA256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855) exploited CVE-2021-44228.
Contact soc@corp-example.com. Bad hash: deadbeefdeadbeefdeadbeefdeadbeef00. See e.g. report.pdf and version 2.14.1."""


def found(text, limit=20):
    return [(i.type.value, i.query) for i in plan(text, limit).items]


# ---------------------------------------------------------------- finding indicators

def test_a_plain_list_is_one_entry_per_line_names_included():
    result = plan("CVE-2021-44228\n8.8.8.8\n- evil[.]com\n1) Volt Typhoon\ncwe 79\n8.8.8.8\n", 20)
    assert result.mode == "list"
    assert found("CVE-2021-44228\n8.8.8.8\n- evil[.]com\n1) Volt Typhoon\ncwe 79\n8.8.8.8\n") == [
        ("cve", "CVE-2021-44228"), ("ip", "8.8.8.8"), ("domain", "evil.com"), ("threat", "Volt Typhoon"),
        ("threat", "CWE-79")]
    assert result.repeats == 1
    assert result.summary == "Found 5: 1 CVE, 1 IP address, 1 domain, 2 names or weaknesses"


def test_indicators_are_picked_out_of_sentences():
    result = plan(ALERT, 20)
    assert result.mode == "extract"
    assert found(ALERT) == [("domain", "update-check.xyz"), ("ip", "45.95.147.236"),
                            ("hash", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
                            ("cve", "CVE-2021-44228"), ("domain", "corp-example.com")]
    # file names, "e.g.", version numbers and words like "ALERT" are not indicators
    assert [s.text for s in result.skipped] == ["deadbeefdeadbeefdeadbeefdeadbeef00"]
    assert "34 characters" in result.skipped[0].reason


def test_names_are_never_guessed_from_sentences():
    assert found("The attackers used Cobalt Strike to reach 8.8.4.4 last week.") == [("ip", "8.8.4.4")]


def test_tables_and_csv():
    assert found("indicator,type\n1.2.3.4,ip\nexample.org,domain") == [("ip", "1.2.3.4"), ("domain", "example.org")]
    assert found("1.2.3.4\texample.org\nCVE-2024-3400 | critical") == [
        ("ip", "1.2.3.4"), ("domain", "example.org"), ("cve", "CVE-2024-3400")]


def test_bad_list_entries_are_skipped_with_a_reason():
    result = plan("8.8.8.8\nhttp://\n", 20)
    assert found("8.8.8.8\nhttp://\n") == [("ip", "8.8.8.8")]
    assert result.skipped[0].text == "http://" and result.skipped[0].reason


def test_the_limit():
    text = "\n".join(f"10.0.0.{i}" for i in range(1, 26))
    result = plan(text, 20)
    assert len(result.items) == 20 and result.over_limit == 5


def test_nothing_found():
    assert plan("hello, this has nothing in it.", 20).summary == "Found nothing to investigate"


# ---------------------------------------------------------------- running a batch

@pytest.fixture(autouse=True)
def clear_kev():
    kev.reset_catalog()


def test_every_item_becomes_a_row_and_the_batch_is_saved():
    calls: list[str] = []
    store = MemoryStore()
    rows = []
    batch = asyncio.run(run_bulk(plan(f"{fakes.LOG4SHELL}\n{fakes.BAD_IP}\n8.8.8.8", 20),
                                 fakes.test_settings(gemini_api_key="g", groq_api_key="q", research_enabled=True),
                                 store, fakes.router(calls=calls), on_row=rows.append))
    assert [r.query for r in batch.rows] == [fakes.LOG4SHELL, fakes.BAD_IP, "8.8.8.8"]  # in the pasted order
    assert len(rows) == 3  # each one was announced as it finished
    cve = batch.rows[0]
    assert cve.level == "CRITICAL" and cve.score == 95 and cve.sources_ok == 3 == cve.sources_total
    assert cve.top_signals[0] == "CVSS 3.1 severity 10.0 (CRITICAL) (+40)"
    assert batch.rows[1].subtype == "ipv4"
    saved = asyncio.run(store.get(cve.investigation_id))
    assert saved.report.message == BULK_AI_MESSAGE and saved.research is None
    assert not [c for c in calls if "googleapis" in c or "groq.com" in c]  # no AI quota used
    assert asyncio.run(store.get_batch(batch.id))["rows"][0]["investigation_id"] == cve.investigation_id


def test_one_failure_doesnt_stop_the_batch(monkeypatch):
    from app import bulk

    async def flaky(query, *args, **kwargs):
        if query == "8.8.8.8":
            raise RuntimeError("boom")
        return await bulk_investigate(query, *args, **kwargs)

    bulk_investigate = bulk.investigate
    monkeypatch.setattr(bulk, "investigate", flaky)
    batch = asyncio.run(run_bulk(plan(f"{fakes.LOG4SHELL}\n8.8.8.8", 20), fakes.test_settings(), MemoryStore(),
                                 fakes.router()))
    assert batch.rows[0].level == "CRITICAL"
    assert batch.rows[1].error and batch.rows[1].level is None


# ---------------------------------------------------------------- the API

@pytest.fixture
def client(monkeypatch):
    main.limiter.reset()
    monkeypatch.setattr(main, "settings", fakes.test_settings())
    test_client = TestClient(main.app)
    test_client.__enter__()
    main.app.state.http = fakes.router()
    main.app.state.store = MemoryStore()
    yield test_client
    test_client.__exit__(None, None, None)


def post(client, path, text, visitor="1.2.3.4"):
    return client.post(path, json={"text": text}, headers={"x-forwarded-for": visitor})


def test_parse_endpoint(client):
    body = post(client, "/api/bulk/parse", ALERT).json()
    assert body["mode"] == "extract" and len(body["items"]) == 5


def test_stream_sends_the_plan_then_rows_then_the_saved_batch(client):
    response = post(client, "/api/bulk/stream", f"{fakes.LOG4SHELL}\n{fakes.BAD_IP}")
    assert response.status_code == 200
    found_events = events(response)
    kinds = [k for k, _ in found_events]
    assert kinds[0] == "plan" and kinds.count("row") == 2 and kinds[-1] == "done"
    batch = found_events[-1][1]
    assert batch["id"] and len(batch["rows"]) == 2
    again = client.get(f"/api/bulk/{batch['id']}").json()
    assert [r["query"] for r in again["rows"]] == [fakes.LOG4SHELL, fakes.BAD_IP]
    assert client.get("/api/bulk/not-a-batch").status_code == 404


def test_each_item_counts_toward_the_daily_limit(client):
    post(client, "/api/bulk/stream", f"{fakes.LOG4SHELL}\n{fakes.BAD_IP}")
    assert asyncio.run(main.app.state.store.count_today("investigations", add=0)) == 2


def test_nothing_to_investigate_is_refused_before_streaming(client):
    response = post(client, "/api/bulk/stream", "no indicators here.")
    assert response.status_code == 422 and "No indicators found" in response.json()["detail"]


def test_bulk_lookups_per_hour(client):
    for _ in range(3):
        assert post(client, "/api/bulk/stream", "8.8.8.8").status_code == 200
    refused = post(client, "/api/bulk/stream", "8.8.8.8")
    assert refused.status_code == 429 and "3 bulk lookups allowed per hour" in refused.json()["detail"]
    assert post(client, "/api/bulk/stream", "8.8.8.8", visitor="5.6.7.8").status_code == 200


def test_daily_limit_counts_the_whole_batch(client, monkeypatch):
    monkeypatch.setattr(main, "settings", fakes.test_settings(daily_investigation_cap=2))
    refused = post(client, "/api/bulk/stream", "8.8.8.8\n1.1.1.1\n9.9.9.9")
    assert refused.status_code == 429 and "daily investigation limit" in refused.json()["detail"]


@pytest.mark.skipif(not __import__("os").environ.get("TEST_DATABASE_URL"), reason="set TEST_DATABASE_URL")
def test_batches_are_saved_in_the_database():
    import os

    from app.store import PostgresStore
    store = PostgresStore(os.environ["TEST_DATABASE_URL"])
    asyncio.run(store.init())
    try:
        batch = asyncio.run(run_bulk(plan(f"{fakes.LOG4SHELL}\n8.8.8.8", 20), fakes.test_settings(), store,
                                     fakes.router()))
        saved = asyncio.run(store.get_batch(batch.id))
        assert saved["id"] == batch.id and [r["query"] for r in saved["rows"]] == [fakes.LOG4SHELL, "8.8.8.8"]
        assert asyncio.run(store.get_batch("not-a-uuid")) is None
    finally:
        asyncio.run(store.close())
