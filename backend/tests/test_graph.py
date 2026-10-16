"""The investigation graph: the decision map (why this verdict) and the connections graph.

Most tests build investigations with the fake sources. Tests that match names to ATT&CK and
CWE entries use the small sample knowledge base and need TEST_DATABASE_URL.
"""
import asyncio
import copy
import os

import pytest

from app.graph import build_graph, decision_map
from app.investigate import investigate
from app.models import ResearchRun, ResearchStep
from app.sources import kev
from app.store import MemoryStore
from tests import fakes


@pytest.fixture(autouse=True)
def clear_kev():
    kev.reset_catalog()


def go(query, client=None, store=None, **settings):
    store = store or MemoryStore()
    settings.setdefault("gemini_api_key", "g")
    return asyncio.run(investigate(query, fakes.test_settings(**settings), store, client or fakes.router()))


def graph(result, store=None):
    return asyncio.run(build_graph(result, store or MemoryStore()))


def edges(g):
    return {(e.source, e.target): e for e in g.edges}


def behind(g, node_id):
    """Everything a node depends on: what lights up when you click it."""
    found, todo = set(), [node_id]
    while todo:
        current = todo.pop()
        for e in g.edges:
            if e.target == current and e.source not in found:
                found.add(e.source)
                todo.append(e.source)
    return found


def research(*steps):
    return ResearchRun(status="done", steps=[
        ResearchStep(id=f"R{i}", tool=tool, input=text, why="Follow the lead.", ok=True,
                     title=f"Step {i}", summary="Found it.", data=data, link=f"https://example.org/{i}")
        for i, (tool, text, data) in enumerate(steps, start=1)])


# ---------------------------------------------------------------- the decision map

def test_every_point_has_a_source_and_reaches_the_verdict():
    result = go(fakes.LOG4SHELL)
    g = decision_map(result)
    links = edges(g)
    for signal in result.signals:
        assert (f"src:{signal.source}", f"sig:{signal.id}") in links
        assert links[(f"sig:{signal.id}", "verdict")].label == f"{signal.points:+d}"
    columns = {n.id: n.column for n in g.nodes}
    assert columns["src:NVD"] == "sources" and columns["sig:cvss"] == "evidence" and columns["verdict"] == "verdict"
    assert g.notes == []  # 40 + 30 + 5 + 20 = 95, exactly the score


def test_ai_statements_link_to_the_sources_they_cite():
    result = go(fakes.LOG4SHELL)
    g = decision_map(result)
    cite = {c.id: c.source for c in result.report.citations}
    statements = [n for n in g.nodes if n.kind == "statement"]
    assert [n.status for n in statements] == ["finding", "finding", "affected", "action-now"]
    action = next(n for n in statements if n.status == "action-now")
    assert {e.source for e in g.edges if e.target == action.id} == {f"src:{cite['S1']}", f"src:{cite['S2']}"}
    # Clicking the finding about KEV lights up KEV, but not the score's other sources
    finding = statements[0]
    assert behind(g, finding.id) == {"src:CISA KEV"}


def test_citing_the_score_reaches_back_through_every_signal():
    result = go(fakes.LOG4SHELL)
    result.report.findings[0].sources = ["S0"]
    g = decision_map(result)
    assert behind(g, "stmt:finding:0") == {"verdict", "sig:cvss", "sig:kev_listed", "sig:kev_ransomware", "sig:epss",
                                          "src:NVD", "src:CISA KEV", "src:FIRST EPSS"}


def test_combined_signals_come_from_the_signals_they_combine():
    result = go(fakes.BAD_IP)
    g = decision_map(result)
    into = {e.source for e in g.edges if e.target == "sig:corroborated"}
    assert into == {"sig:vt_malicious", "sig:abuseipdb", "sig:threatfox", "sig:urlhaus_online", "sig:otx"}
    assert "The signals add up to" in g.notes[0] and "scores stop at 100" in g.notes[0]


def test_sources_that_could_not_answer_are_shown_without_links():
    result = go(fakes.BAD_IP, fakes.router({"virustotal": (500, {})}))
    g = decision_map(result)
    vt = next(n for n in g.nodes if n.id == "src:VirusTotal")
    assert vt.status == "error" and vt.cite is None
    assert not [e for e in g.edges if "src:VirusTotal" in (e.source, e.target)]


def test_known_good_signals_come_from_threatlens_rules():
    clean = {"virustotal": (200, fakes.VT_CLEAN), "otx": (200, fakes.OTX_EMPTY), "threatfox": (200, fakes.NO_RESULT),
             "urlhaus": (200, fakes.NO_RESULT),
             "abuseipdb": (200, {"data": {"abuseConfidenceScore": 0, "totalReports": 0, "isWhitelisted": True}})}
    g = decision_map(go("8.8.8.8", fakes.router(clean)))
    assert ("src:ThreatLens", "sig:known_good") in edges(g)
    assert "never go below 0" in g.notes[0]


def test_without_an_ai_summary_the_map_ends_at_the_verdict():
    result = go(fakes.LOG4SHELL, gemini_api_key="", groq_api_key="")
    g = decision_map(result)
    assert not [n for n in g.nodes if n.kind == "statement"]
    assert "ends at the verdict" in g.notes[0]


def test_research_is_citable_but_never_feeds_the_verdict():
    result = go(fakes.LOG4SHELL)
    result.research = research(("attack_mentions", "CVE-2021-44228", {"term": "CVE-2021-44228", "mentions": []}))
    result.report.citations.append(result.report.citations[0].model_copy(
        update={"id": "S4", "source": "Research R1: Step 1"}))
    result.report.findings[0].sources = ["S4"]
    g = decision_map(result)
    assert next(n for n in g.nodes if n.id == "res:R1").cite == "S4"
    assert ("res:R1", "stmt:finding:0") in edges(g)
    assert not [e for e in g.edges if e.source == "res:R1" and e.target == "verdict"]
    assert any("never changes the score" in note for note in g.notes)


# ---------------------------------------------------------------- the connections graph

def test_cve_connects_to_its_weaknesses_and_products():
    g = graph(go(fakes.LOG4SHELL)).connections
    kinds = {n.id: n.kind for n in g.nodes}
    assert kinds["subject"] == "cve"
    assert kinds["id:CWE-502"] == "weakness" and kinds["id:CWE-20"] == "weakness"
    assert kinds["product:apache log4j"] == "product"
    assert edges(g)[("subject", "id:CWE-502")].label == "has the weakness"


def test_the_same_malware_from_two_sources_is_one_node():
    g = graph(go(fakes.BAD_IP)).connections
    mirai = [n for n in g.nodes if n.label == "Mirai"]
    assert len(mirai) == 1 and set(mirai[0].seen_in) == {"AlienVault OTX", "ThreatFox"}
    assert any(n.id == "id:T1071" for n in g.nodes)


def test_placeholder_names_are_left_out():
    result = go(fakes.BAD_SHA256)
    result.sources = [s for s in result.sources if s.source != "VirusTotal"]
    for s in result.sources:
        if s.source == "MalwareBazaar":
            s.facts["malware_family"] = "Generic"
    g = graph(result).connections
    assert not [n for n in g.nodes if n.label.lower() == "generic"]


def test_research_findings_join_the_graph():
    result = go(fakes.LOG4SHELL)
    result.research = research(
        ("attack_mentions", "CVE-2021-44228", {"term": "CVE-2021-44228", "mentions": [
            "Magic Hound (G0059): Magic Hound has exploited CVE-2021-44228.",
            "Sea Turtle (G1041) → Log4Shell tool (S9998): used CVE-2021-44228."]}),
        ("attack_profile", "G0059", {"id": "G0059", "name": "Magic Hound", "kind": "group", "aliases": ["APT35"],
                                     "malware_used": ["S0001 PowerLess", "S0002 Mimikatz"], "top_defenses": ["M1 x"]}),
        ("investigate_indicator", "45.95.147.236", {"indicator": "45.95.147.236", "type": "ip", "level": "CRITICAL",
                                                    "score": 100, "headline": "Reported by 5 sources."}),
    )
    g = graph(result).connections
    nodes = {n.id: n for n in g.nodes}
    links = edges(g)
    assert ("subject", "id:G0059") in links and ("subject", "id:G1041") in links
    assert set(nodes["id:G0059"].seen_in) == {"Research R1", "Research R2"}  # mentioned, then opened: one node
    assert nodes["id:S0001"].depth == 2 and links[("id:G0059", "id:S0001")].label == "malware used"
    assert "id:M1" not in nodes  # top_defenses are summaries, not connections
    assert nodes["ind:45.95.147.236"].level == "CRITICAL" and nodes["ind:45.95.147.236"].kind == "ip"


def test_failed_research_steps_add_nothing():
    result = go(fakes.LOG4SHELL)
    result.research = research(("search_attack", "Nothing", {"matches": ["G9999 Ghost (group, matched by name)"]}))
    result.research.steps[0].ok = False
    assert not [n for n in graph(result).connections.nodes if "Ghost" in n.label]


def test_nothing_connected_says_so():
    quiet = {"virustotal": (200, fakes.VT_CLEAN), "otx": (200, fakes.OTX_EMPTY), "threatfox": (200, fakes.NO_RESULT),
             "urlhaus": (200, fakes.NO_RESULT)}
    g = graph(go("8.8.8.8", fakes.router(quiet))).connections
    assert len(g.nodes) == 1 and "didn't report anything" in g.notes[0]


# ---------------------------------------------------------------- the API

def test_graph_endpoint():
    from fastapi.testclient import TestClient

    from app import main
    with TestClient(main.app) as client:
        store = MemoryStore()
        main.app.state.store = store
        saved = asyncio.run(store.save(go(fakes.LOG4SHELL)))
        saved_id = saved.id if hasattr(saved, "id") else saved
        body = client.get(f"/api/investigations/{saved_id}/graph").json()
        assert body["investigation_id"] == saved_id
        assert {"decision", "connections"} <= set(body)
        assert any(n["id"] == "verdict" for n in body["decision"]["nodes"])
        assert client.get("/api/investigations/nope/graph").status_code == 404


# ---------------------------------------------------------------- with the knowledge base

DB_URL = os.environ.get("TEST_DATABASE_URL")
needs_db = pytest.mark.skipif(not DB_URL, reason="set TEST_DATABASE_URL to run database tests")


@pytest.fixture
def store():
    from app.knowledge import attack, cwe
    from app.knowledge.repository import KnowledgeRepository
    from app.store import PostgresStore
    from tests.attack_sample import BUNDLE
    from tests.cwe_sample import zipped

    store = PostgresStore(DB_URL)
    asyncio.run(store.init())
    repository = KnowledgeRepository(store)
    repository.import_source(attack.SOURCE, *attack.parse_bundle(copy.deepcopy(BUNDLE)))
    version, entities, relationships = cwe.parse_catalog(cwe.read_file(zipped()))
    repository.import_source(cwe.SOURCE, version, entities, relationships, [])
    yield store
    asyncio.run(store.close())


@needs_db
def test_feed_names_are_matched_to_attack_entries(store):
    otx = copy.deepcopy(fakes.OTX_BAD)
    otx["pulse_info"]["pulses"][0].update(adversary="Vanguard Panda",
                                          malware_families=[{"id": "VersaMem", "display_name": "VersaMem"}])
    result = go(fakes.BAD_IP, fakes.router({"otx": (200, otx)}), store=MemoryStore())
    result.research = research(("search_attack", "Volt Typhoon",
                                {"matches": ["G1017 Volt Typhoon (group, matched by name)"]}))
    g = graph(result, store).connections
    nodes = {n.id: n for n in g.nodes}
    volt = nodes["id:G1017"]
    assert volt.label == "Volt Typhoon (G1017)" and volt.link
    assert set(volt.seen_in) == {"AlienVault OTX", "Research R1"}  # the alias and the research found the same group
    assert 'Reported as "Vanguard Panda"' in volt.detail
    assert nodes["id:S1154"].kind == "malware"
    assert "group:vanguard panda" not in nodes


@needs_db
def test_similar_names_are_not_matched(store):
    otx = copy.deepcopy(fakes.OTX_BAD)
    otx["pulse_info"]["pulses"][0]["malware_families"] = [{"id": "VersaMemm", "display_name": "VersaMemm"}]
    g = graph(go(fakes.BAD_IP, fakes.router({"otx": (200, otx)})), store).connections
    assert "malware:versamemm" in {n.id for n in g.nodes}
    assert "id:S1154" not in {n.id for n in g.nodes}


@needs_db
def test_ids_get_names_and_links(store):
    g = graph(go(fakes.LOG4SHELL, store=store), store).connections
    cwe502 = next(n for n in g.nodes if n.id == "id:CWE-502")
    assert cwe502.label == "Deserialization of Untrusted Data (CWE-502)"
    assert cwe502.link == "https://cwe.mitre.org/data/definitions/502.html"


@needs_db
def test_a_threat_profile_connects_to_what_attack_links_it_to(store):
    result = go("Volt Typhoon", store=store)
    result.research = research(("attack_profile", "G1017", {"id": "G1017", "name": "Volt Typhoon", "kind": "group"}))
    g = graph(result, store)
    nodes = {n.id: n for n in g.connections.nodes}
    assert nodes["subject"].label == "Volt Typhoon (G1017)"
    assert "id:G1017" not in nodes  # researching itself doesn't add a second Volt Typhoon
    assert {"id:S1154", "id:C0035"} <= set(nodes)
    assert any("technique" in note for note in g.connections.notes)
    assert ("src:MITRE ATT&CK", "verdict") in edges(g.decision)


def test_long_product_lists_are_trimmed_with_a_note():
    result = go(fakes.LOG4SHELL)
    nvd = next(s for s in result.sources if s.source == "NVD")
    nvd.facts["affected_products"] = [f"siemens model {i}" for i in range(9)]
    g = graph(result).connections
    assert len([n for n in g.nodes if n.kind == "product" and n.seen_in == ["NVD"]]) == 4
    assert any("NVD lists 5 more affected products" in note for note in g.notes)


def test_campaigns_named_by_their_id_read_cleanly():
    result = go(fakes.LOG4SHELL)
    result.research = research(("attack_mentions", "CVE-2021-44228", {"term": "CVE-2021-44228", "mentions": [
        "C0017 (C0017): During C0017, APT41 exploited CVE-2021-44228."]}))
    labels = {n.id: n.label for n in graph(result).connections.nodes}
    assert labels["id:C0017"] == "Campaign C0017"
