"""The live view: decision-trail steps streamed as they happen (Server-Sent Events)."""
import asyncio
import json

import pytest
from fastapi.testclient import TestClient

from app import main
from app.sources import kev
from app.store import MemoryStore
from app.trace import Trace
from tests import fakes
from tests.test_agent import FINISH, agent_router, step


@pytest.fixture
def make_client(monkeypatch):
    kev.reset_catalog()
    main.limiter.reset()
    monkeypatch.setattr("app.agent.runner.RETRY_DELAY_SECONDS", 0)

    def build(http=None, **overrides):
        monkeypatch.setattr(main, "settings", fakes.test_settings(**overrides))
        client = TestClient(main.app)
        client.__enter__()
        main.app.state.http = http or fakes.router()
        main.app.state.store = MemoryStore()
        return client

    yield build


def events(response) -> list[tuple[str, dict | None]]:
    """Parse a Server-Sent Events body into (event, data) pairs; comment lines become ("comment", None)."""
    found = []
    for block in response.text.split("\n\n"):
        if not block.strip():
            continue
        if block.startswith(":"):
            found.append(("comment", None))
            continue
        lines = dict(line.split(": ", 1) for line in block.split("\n"))
        found.append((lines["event"], json.loads(lines["data"])))
    return found


def stream(client, query, visitor="1.2.3.4"):
    return client.post("/api/investigations/stream", json={"query": query}, headers={"x-forwarded-for": visitor})


def test_steps_arrive_before_the_finished_result(make_client):
    client = make_client()
    response = stream(client, fakes.LOG4SHELL)
    assert response.status_code == 200 and response.headers["content-type"].startswith("text/event-stream")
    found = events(response)
    kinds = [kind for kind, _ in found]
    assert kinds[0] == "step" and found[0][1]["kind"] == "detect"
    assert kinds[-1] == "done" and kinds.count("done") == 1
    assert ("status", {"text": "Waiting for 3 sources to answer…"}) in found
    countdown = [d["text"] for k, d in found if k == "status" and "more source" in d["text"]]
    assert countdown == ["Waiting for 2 more sources…", "Waiting for 1 more source…"]

    done = found[-1][1]
    streamed = [data for kind, data in found if kind == "step"]
    assert [s["title"] for s in streamed] == [s["title"] for s in done["trace"]]  # nothing missing or extra
    assert done["verdict"]["level"] == "CRITICAL"
    saved = client.get(f"/api/investigations/{done['id']}").json()
    assert saved["verdict"] == done["verdict"]


def test_each_source_is_recorded_as_it_answers(make_client):
    found = events(stream(make_client(), fakes.BAD_IP))
    fetches = [data["title"] for kind, data in found if kind == "step" and data["kind"] == "fetch"]
    assert len(fetches) == 5
    done = found[-1][1]
    # whatever order they answer in, the result lists sources in their usual order
    assert [s["source"] for s in done["sources"]] == ["AbuseIPDB", "VirusTotal", "AlienVault OTX", "ThreatFox", "URLhaus"]


def test_bad_input_is_refused_before_streaming(make_client):
    client = make_client(daily_investigation_cap=1)
    response = stream(client, "8.8.8.8 1.1.1.1")
    assert response.status_code == 422 and "more than one" in response.json()["detail"]
    # ...and doesn't use up the daily allowance
    assert stream(client, fakes.LOG4SHELL).status_code == 200


def test_limits_apply_before_streaming(make_client):
    client = make_client(investigations_per_hour_per_visitor=1)
    assert stream(client, fakes.LOG4SHELL).status_code == 200
    blocked = stream(client, fakes.LOG4SHELL)
    assert blocked.status_code == 429 and "investigations allowed per hour" in blocked.json()["detail"]


def test_research_steps_stream_live(make_client):
    http = agent_router([step("investigate_indicator", fakes.BAD_IP, "Check the related botnet address."), FINISH])
    found = events(stream(make_client(http=http, gemini_api_key="g", groq_api_key="q", research_enabled=True),
                          fakes.LOG4SHELL))
    labels = [(kind, data.get("title") or data.get("text")) for kind, data in found if kind in ("step", "status")]
    research_step = next(i for i, (k, t) in enumerate(labels) if k == "step" and t.startswith("R1:"))
    choosing = labels.index(("status", "The research agent is choosing step 1 of up to 3…"))
    writing = labels.index(("status", "Writing the summary with AI…"))
    assert choosing < research_step < writing
    assert found[-1][1]["research"]["steps"][0]["why"] == "Check the related botnet address."


def test_keeps_a_quiet_connection_alive(make_client, monkeypatch):
    monkeypatch.setattr(main, "KEEPALIVE_SECONDS", 0.01)
    real = main.investigate

    async def slow(*args, **kwargs):
        await asyncio.sleep(0.1)
        return await real(*args, **kwargs)

    monkeypatch.setattr(main, "investigate", slow)
    found = events(stream(make_client(), fakes.LOG4SHELL))
    assert ("comment", None) in found and found[-1][0] == "done"


def test_unexpected_failure_becomes_an_error_event(make_client, monkeypatch):
    async def broken(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(main, "investigate", broken)
    found = events(stream(make_client(), fakes.LOG4SHELL))
    assert found == [("error", {"detail": "The investigation failed unexpectedly. Please try again."})]


# ---------------------------------------------------------------- the trace listener

def test_listener_hears_timed_steps_when_they_finish():
    heard = []
    trace = Trace(listener=lambda s: heard.append((s.title, s.duration_ms)))
    with trace.timed("score", "Calculating") as current:
        assert heard == []  # not announced while still running
        current.title = "Calculated the risk score"
    trace.add("verdict", "HIGH")
    assert heard[0][0] == "Calculated the risk score" and heard[0][1] is not None
    assert heard[1] == ("HIGH", None)


def test_a_broken_listener_never_breaks_an_investigation():
    def broken(step):
        raise ConnectionError("tab closed")

    trace = Trace(listener=broken)
    trace.add("detect", "Identified the input")
    assert len(trace.steps) == 1


def test_closing_the_tab_doesnt_lose_the_investigation(make_client):
    from starlette.requests import Request

    from app.models import InvestigateRequest

    make_client()  # sets up the app, its fake services, and an empty store

    async def scenario():
        scope = {"type": "http", "method": "POST", "path": "/api/investigations/stream", "headers": [],
                 "client": ("1.2.3.4", 1234), "app": main.app}
        response = await main.stream_investigation(InvestigateRequest(query=fakes.LOG4SHELL), Request(scope))
        body = response.body_iterator
        first = await body.__anext__()
        await body.aclose()  # the browser went away after the first step
        await asyncio.gather(*list(main.app.state.tasks))
        return first, await main.app.state.store.recent(5)

    first, saved = asyncio.run(scenario())
    assert first.startswith("event: step")
    assert [s.indicator_value for s in saved] == [fakes.LOG4SHELL]
