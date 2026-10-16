"""The ATT&CK map: techniques by stage of attack, why each is there, defenses, and the Navigator layer.

Uses the small sample knowledge base (tests/attack_sample.py): Volt Typhoon (G1017) uses LSASS Memory
(T1003.001) and the tool Mimikatz (S0002), which also uses T1003.001. Credential Access Protection
(M1043) mitigates T1003.001. Needs TEST_DATABASE_URL, except the first test.
"""
import asyncio
import copy
import os

import pytest

from app.attack_map import build_attack_map, navigator_layer
from app.investigate import investigate
from app.models import ResearchRun, ResearchStep
from app.sources import kev
from app.store import MemoryStore
from tests import fakes

DB_URL = os.environ.get("TEST_DATABASE_URL")
needs_db = pytest.mark.skipif(not DB_URL, reason="set TEST_DATABASE_URL to run database tests")


@pytest.fixture(autouse=True)
def clear_kev():
    kev.reset_catalog()


def go(query, client=None, store=None):
    return asyncio.run(investigate(query, fakes.test_settings(), store or MemoryStore(), client or fakes.router()))


def mapped(attack_map):
    return {t.external_id: (tactic.id, t) for tactic in attack_map.tactics for t in tactic.techniques}


def otx_with(techniques=(), adversary=""):
    otx = copy.deepcopy(fakes.OTX_BAD)
    otx["pulse_info"]["pulses"][0].update(
        attack_ids=[{"id": t, "name": t, "display_name": t} for t in techniques], adversary=adversary)
    return fakes.router({"otx": (200, otx)})


def test_without_the_knowledge_base_it_says_so():
    result = asyncio.run(build_attack_map(go(fakes.LOG4SHELL), MemoryStore()))
    assert result.status == "unavailable" and "knowledge base" in result.notes[0]


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


def build(result, store):
    return asyncio.run(build_attack_map(result, store))


@needs_db
def test_stages_come_from_the_loaded_attack_data(store):
    result = build(go("Volt Typhoon", store=store), store)
    # The sample has one tactic; names, IDs and short names come from the data, not a fixed list
    assert [(t.id, t.name, t.shortname) for t in result.tactics] == [("TA0006", "Credential Access", "credential-access")]
    assert result.tactics[0].about == "Stealing passwords and keys"


def test_attack_order_includes_the_v19_stages():
    from app.attack_map import STAGE_TEXT, TACTIC_ORDER
    assert TACTIC_ORDER.index("TA0005") + 1 == TACTIC_ORDER.index("TA0112")  # Stealth, then Defense Impairment
    assert TACTIC_ORDER[0] == "TA0043" and TACTIC_ORDER[-1] == "TA0040"  # Reconnaissance ... Impact
    assert set(STAGE_TEXT) == set(TACTIC_ORDER)


@needs_db
def test_a_group_profile_maps_its_own_techniques_and_its_software(store):
    result = build(go("Volt Typhoon", store=store), store)
    tactic, lsass = mapped(result)["T1003.001"]
    assert tactic == "TA0006" and lsass.name == "LSASS Memory"
    assert lsass.strength == "reported"
    assert lsass.evidence[0].text == "ATT&CK records Volt Typhoon using this technique."
    assert lsass.linked_threats == ["Mimikatz (S0002)"]  # its tool uses the same technique
    assert {t.external_id for t in result.linked} == {"S0002", "S1154", "C0035"}
    assert result.technique_count == 1 and result.reported_count == 1


@needs_db
def test_techniques_reported_by_a_source(store):
    result = build(go(fakes.BAD_IP, otx_with(["T1003.001", "T1071"])), store)
    _, lsass = mapped(result)["T1003.001"]
    assert lsass.strength == "reported" and lsass.evidence[0].source == "AlienVault OTX"
    assert any("T1071 is not in the loaded ATT&CK version" in note for note in result.notes)


@needs_db
def test_techniques_of_linked_threats_are_marked_as_linked(store):
    result = build(go(fakes.BAD_IP, otx_with(adversary="Vanguard Panda")), store)
    _, lsass = mapped(result)["T1003.001"]
    assert lsass.strength == "linked"
    assert lsass.linked_threats == ["Volt Typhoon (G1017)"]
    assert "linked to this investigation through AlienVault OTX" in lsass.evidence[0].text
    assert any("not something this indicator was seen doing" in note for note in result.notes)


@needs_db
def test_research_findings_count_as_linked(store):
    result = go(fakes.LOG4SHELL)
    result.research = ResearchRun(status="done", steps=[ResearchStep(
        id="R1", tool="search_attack", input="Volt Typhoon", why="Lead.", ok=True, title="Searched",
        summary="Found.", data={"matches": ["G1017 Volt Typhoon (group, matched by name)"]})])
    result_map = build(result, store)
    _, lsass = mapped(result_map)["T1003.001"]
    assert lsass.strength == "linked" and "Research R1" in lsass.evidence[0].source


@needs_db
def test_defenses_cover_the_mapped_techniques(store):
    result = build(go("Volt Typhoon", store=store), store)
    assert [(d.external_id, d.covers) for d in result.defenses] == [("M1043", 1)]


@needs_db
def test_a_weakness_explains_why_there_is_no_map(store):
    result = build(go("XSS", store=store), store)
    assert result.status == "empty" and "doesn't map them to ATT&CK" in result.notes[0]


@needs_db
def test_a_technique_maps_itself(store):
    result = build(go("T1003", store=store), store)
    assert list(mapped(result)) == ["T1003"]


@needs_db
def test_nothing_to_map(store):
    quiet = {"virustotal": (200, fakes.VT_CLEAN), "otx": (200, fakes.OTX_EMPTY), "threatfox": (200, fakes.NO_RESULT),
             "urlhaus": (200, fakes.NO_RESULT)}
    result = build(go("8.8.8.8", fakes.router(quiet)), store)
    assert result.status == "empty" and result.technique_count == 0


@needs_db
def test_navigator_layer(store):
    result = build(go(fakes.BAD_IP, otx_with(["T1003.001"], adversary="Vanguard Panda")), store)
    layer = navigator_layer(result, fakes.BAD_IP)
    assert layer["versions"]["layer"] == "4.5" and layer["domain"] == "enterprise-attack"
    assert layer["name"] == f"ThreatLens: {fakes.BAD_IP}"
    technique = layer["techniques"][0]
    assert technique["techniqueID"] == "T1003.001" and technique["tactic"] == "credential-access"
    assert technique["score"] == 4  # reported (3) + one linked threat (1)
    assert "AlienVault OTX" in technique["comment"]


@needs_db
def test_api(store):
    from fastapi.testclient import TestClient

    from app import main
    with TestClient(main.app) as client:
        main.app.state.store = store
        group_id = go("Volt Typhoon", store=store).id
        body = client.get(f"/api/investigations/{group_id}/attack").json()
        assert body["status"] == "ok" and body["technique_count"] == 1
        layer = client.get(f"/api/investigations/{group_id}/attack/layer")
        assert layer.status_code == 200
        assert 'filename="threatlens-Volt_Typhoon-attack-layer.json"' in layer.headers["content-disposition"]
        assert layer.json()["techniques"][0]["techniqueID"] == "T1003.001"
        weakness_id = go("XSS", store=store).id
        assert client.get(f"/api/investigations/{weakness_id}/attack/layer").status_code == 404
        assert client.get("/api/investigations/nope/attack").status_code == 404
