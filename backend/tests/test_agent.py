"""The research agent: leads, tools, the decision loop's limits, safety rules, and how its
results reach the AI summary. The AI is scripted: each test says exactly which decisions it makes.
"""
import asyncio
import copy
import json
import os

import httpx2
import pytest

from app.agent import leads as lead_finder
from app.agent import tools
from app.ai.prompt import build_evidence
from app.detection import detect
from app.investigate import investigate
from app.knowledge.attack import SOURCE, parse_bundle
from app.sources import kev
from app.store import MemoryStore
from tests import fakes
from tests.attack_sample import BUNDLE


@pytest.fixture(autouse=True)
def reset(monkeypatch):
    kev.reset_catalog()
    monkeypatch.setattr("app.agent.runner.RETRY_DELAY_SECONDS", 0)
    monkeypatch.setattr("app.ai.report.RETRY_DELAY_SECONDS", 0)


def step(action, text, why="Following a lead in the evidence."):
    return {"why": why, "action": action, "input": text}


FINISH = step("finish", "Enough is known.")


def agent_router(decisions, overrides=None, calls=None):
    """The normal fake services, except that AI requests from the research planner get scripted decisions.

    A decision can be a dict (sent as the AI's answer), a (status, body) tuple, or raw text.
    """
    inner = fakes.router(overrides, calls=calls)._transport.handler
    script = list(decisions)

    def handler(request):
        url = str(request.url)
        if ("googleapis" in url or "groq.com" in url) and b"research planner" in request.content:
            if calls is not None:
                calls.append("agent " + url)
            answer = script.pop(0) if script else FINISH
            if isinstance(answer, tuple):
                return httpx2.Response(answer[0], json=answer[1])
            text = answer if isinstance(answer, str) else json.dumps(answer)
            body = fakes.gemini_body(text) if "googleapis" in url else fakes.groq_body(text)
            return httpx2.Response(200, json=body)
        return inner(request)

    return httpx2.AsyncClient(transport=httpx2.MockTransport(handler))


def settings(**overrides):
    values = {"gemini_api_key": "g", "groq_api_key": "q", "research_enabled": True}
    return fakes.test_settings(**{**values, **overrides})


def go(query, decisions, store=None, overrides=None, calls=None, **options):
    allowed = options.pop("research_allowed", True)
    return asyncio.run(investigate(query, settings(**options), store or MemoryStore(),
                                   agent_router(decisions, overrides, calls), research_allowed=allowed))


def agent_calls(calls):
    return sum(c.startswith("agent ") for c in calls)


# ---------------------------------------------------------------- leads

def test_leads_from_an_ip_investigation():
    result = go(fakes.BAD_IP, [FINISH])
    assert result.research.leads == [
        "Mirai (malware family, from ThreatFox)",
        "T1071 (ATT&CK technique, from AlienVault OTX)",
    ]  # Mirai from OTX is the same lead, so it isn't repeated


def test_leads_from_a_cve():
    result = go(fakes.LOG4SHELL, [FINISH])
    assert result.research.leads[0].startswith("CVE-2021-44228 (the CVE itself")
    assert "Apache Log4j2 (affected product, from CISA KEV)" in result.research.leads


def test_placeholder_family_names_are_not_leads():
    leads, seen = [], set()
    for name in ["Generic", "unknown", "", "trojan"]:
        lead_finder._add(leads, seen, name, "malware family", "VirusTotal")
    assert leads == []


# ---------------------------------------------------------------- the loop

def test_follows_a_lead_and_finishes():
    calls = []
    result = go(fakes.LOG4SHELL, [step("investigate_indicator", fakes.BAD_IP), FINISH], calls=calls)
    run = result.research
    assert run.status == "done" and run.reason == "Enough is known." and run.ai_calls == 2
    assert [(s.id, s.tool, s.ok) for s in run.steps] == [("R1", "investigate_indicator", True)]
    assert run.steps[0].data["level"] == "CRITICAL"
    assert run.steps[0].why == "Following a lead in the evidence."
    assert result.verdict.score == 95  # research never changes the score
    titles = [s.title for s in result.trace if s.kind == "research"]
    assert titles == [f"R1: Investigated the related indicator {fakes.BAD_IP}", "Research finished"]


def test_research_becomes_a_citable_source():
    result = go(fakes.LOG4SHELL, [step("investigate_indicator", fakes.BAD_IP), FINISH])
    packet, citations = build_evidence(result)
    research = [c for c in citations if c.source.startswith("Research R1")]
    assert len(research) == 1 and research[0].link  # links come from ThreatLens's own source data
    assert any(s.get("source") == "ThreatLens research" for s in packet["sources"])


def test_step_budget_and_lookup_limit():
    decisions = [step("investigate_indicator", fakes.BAD_IP), step("investigate_indicator", fakes.BAD_DOMAIN),
                 step("investigate_indicator", fakes.BAD_SHA256), step("investigate_indicator", "8.8.8.8")]
    calls = []
    run = go(fakes.LOG4SHELL, decisions, calls=calls, agent_max_steps=3, agent_max_lookups=1).research
    assert len(run.steps) == 3 and run.ai_calls == 3 and agent_calls(calls) == 3
    assert run.reason == "Used all 3 research steps."
    assert [s.ok for s in run.steps] == [True, False, False]
    assert "No related-indicator lookups left" in run.steps[1].summary


def test_repeated_and_unknown_actions_are_not_run():
    decisions = [step("investigate_indicator", fakes.BAD_IP), step("investigate_indicator", fakes.BAD_IP),
                 step("delete_everything", "now"), FINISH]
    run = go(fakes.LOG4SHELL, decisions, agent_max_lookups=2, agent_max_steps=4).research
    assert [s.summary for s in run.steps[1:]] == [
        "Already done; repeated steps are not run again.", 'There is no tool called "delete_everything".']


def test_cannot_look_up_the_same_indicator_or_a_name():
    run = go(fakes.LOG4SHELL, [step("investigate_indicator", "cve-2021-44228"),
                               step("investigate_indicator", "Volt Typhoon"), FINISH]).research
    assert "already being investigated" in run.steps[0].summary
    assert "That's a name" in run.steps[1].summary


def test_private_addresses_are_never_sent_out_even_if_the_agent_asks():
    # Even a manipulated agent can't make ThreatLens send an internal address to outside services
    calls = []
    run = go(fakes.LOG4SHELL, [step("investigate_indicator", "192.168.1.10"), FINISH], calls=calls).research
    assert run.steps[0].ok is False
    assert not any("192.168.1.10" in c for c in calls)


def test_backup_provider_takes_over():
    # Gemini is busy (and still busy on the retry), so Groq makes the decision
    run = go(fakes.LOG4SHELL, [(503, {}), (503, {}), FINISH]).research
    assert run.status == "done" and run.provider == "Groq" and run.ai_calls == 1


def test_unusable_ai_answers_stop_research_but_not_the_investigation():
    result = go(fakes.LOG4SHELL, ["not json", '{"no": "decision"}'])
    assert result.research.status == "unavailable" and "valid decision" in result.research.reason
    assert result.report.status == "ready" and result.verdict.level == "CRITICAL"
    assert any(s.title == "Research unavailable" for s in result.trace)


def test_time_limit():
    run = go(fakes.LOG4SHELL, [], agent_timeout_seconds=0).research
    assert run.status == "stopped" and "time limit" in run.reason and run.ai_calls == 0


# ---------------------------------------------------------------- when it doesn't run

def test_skipped_for_low_risk():
    calls = []
    clean = {"virustotal": (200, fakes.VT_CLEAN), "otx": (200, fakes.OTX_EMPTY), "threatfox": (200, fakes.NO_RESULT),
             "urlhaus": (200, fakes.NO_RESULT),
             "abuseipdb": (200, {"data": {"abuseConfidenceScore": 0, "totalReports": 0, "isWhitelisted": True}})}
    result = go("8.8.8.8", [step("investigate_indicator", "1.1.1.1")], overrides=clean, calls=calls)
    assert result.research.status == "skipped" and agent_calls(calls) == 0
    assert any(s.title == "No further research" for s in result.trace)


def test_skipped_when_the_daily_limit_is_reached():
    calls = []
    result = go(fakes.LOG4SHELL, [FINISH], calls=calls, research_allowed=False)
    assert result.research.status == "skipped" and "daily research limit" in result.research.reason
    assert agent_calls(calls) == 0


def test_turned_off_leaves_no_trace():
    result = asyncio.run(investigate(fakes.LOG4SHELL, settings(research_enabled=False), MemoryStore(),
                                     agent_router([])))
    assert result.research is None and not any(s.kind == "research" for s in result.trace)


def test_same_evidence_reuses_saved_research():
    store, calls = MemoryStore(), []
    first = go(fakes.LOG4SHELL, [step("investigate_indicator", fakes.BAD_IP), FINISH], store=store, calls=calls)
    used = agent_calls(calls)
    second = go(fakes.LOG4SHELL, [step("investigate_indicator", fakes.BAD_DOMAIN)], store=store, calls=calls)
    assert agent_calls(calls) == used
    assert second.research.cached and second.research.steps == first.research.steps


# ---------------------------------------------------------------- tools

def test_cap_keeps_results_small():
    data = tools.cap({"items": [f"item number {i} with some text" for i in range(500)], "name": "x"}, limit=400)
    assert len(json.dumps(data)) <= 400 and data["items_shortened"] and data["name"] == "x"


@pytest.mark.parametrize("name, text, message", [
    ("attack_profile", "APT29", "ATT&CK ID"),
    ("attack_mentions", "ab", "3 to 60"),
    ("search_attack", "x", "2 to 80"),
])
def test_tool_inputs_are_validated(name, text, message):
    ctx = tools.ToolContext(store=object(), original=detect("8.8.8.8"), run_indicator=None)
    result = asyncio.run(tools.run_tool(name, text, ctx))
    assert result.ok is False and message in result.summary


# ---------------------------------------------------------------- with the sample ATT&CK data

DB_URL = os.environ.get("TEST_DATABASE_URL")
needs_db = pytest.mark.skipif(not DB_URL, reason="set TEST_DATABASE_URL to run database tests")


@pytest.fixture
def store():
    from app.knowledge.repository import KnowledgeRepository
    from app.store import PostgresStore

    store = PostgresStore(DB_URL)
    asyncio.run(store.init())
    version, entities, relationships, redirects = parse_bundle(copy.deepcopy(BUNDLE))
    KnowledgeRepository(store).import_source(SOURCE, version, entities, relationships, redirects)
    yield store
    asyncio.run(store.close())


def ctx_for(store):
    return tools.ToolContext(store=store, original=detect("8.8.8.8"), run_indicator=None)


@needs_db
def test_search_attack_only_accepts_exact_matches(store):
    ok = asyncio.run(tools.search_attack("VersaMem", ctx_for(store)))
    assert ok.ok and ok.summary.startswith("VersaMem (S1154")
    near = asyncio.run(tools.search_attack("Versa", ctx_for(store)))
    assert near.ok is False and "no entry named" in near.summary


@needs_db
def test_attack_mentions_finds_the_sentence(store):
    result = asyncio.run(tools.attack_mentions("LSASS", ctx_for(store)))
    assert result.ok
    assert "Volt Typhoon (G1017) → LSASS Memory (T1003.001): Volt Typhoon dumped LSASS." in result.data["mentions"]


@needs_db
def test_attack_mentions_treats_wildcards_as_text(store):
    assert asyncio.run(tools.attack_mentions("%%%", ctx_for(store))).ok is False


@needs_db
def test_attack_profile(store):
    result = asyncio.run(tools.attack_profile("g1017", ctx_for(store)))
    assert result.ok and result.data["name"] == "Volt Typhoon" and result.data["technique_count"] == 1
    assert result.link == "https://attack.mitre.org/groups/G1017"


@needs_db
def test_threat_profile_research(store):
    calls = []
    result = go("Volt Typhoon", [step("attack_profile", "S1154"), FINISH], store=store, calls=calls)
    run = result.research
    assert "C0035 KV Botnet Activity (campaigns attributed to this group, from MITRE ATT&CK)" in run.leads
    assert run.steps[0].ok and run.steps[0].data["name"] == "VersaMem"
    assert result.verdict.level == "PROFILE"
