"""Investigating a threat by name: choosing a match, the profile, the verdict, and the full flow.

Logic tests always run. Database tests use the small sample ATT&CK file and need
TEST_DATABASE_URL (see tests/test_knowledge.py).
"""
import asyncio
import copy
import os

import pytest

from app import threats
from app.investigate import investigate
from app.knowledge.attack import SOURCE, parse_bundle
from app.knowledge.models import (Entity, EntitySummary, MitigationCoverage, RelatedGroup, SearchResult,
                                  TacticCount, TechniqueRef, ThreatLookup, ThreatProfile)
from app.models import SourceStatus
from app.store import MemoryStore
from tests import fakes
from tests.attack_sample import BUNDLE


def result(external_id, score, matched_on="similar name"):
    return SearchResult(external_id=external_id, name=external_id, kind="group", url=None, snippet="",
                        matched_on=matched_on, score=score)


# ---------------------------------------------------------------- choosing a match

def test_exact_match_always_wins():
    assert threats.choose([result("G1017", 208, "name"), result("G1045", 200, "name")]) == ("matched", result("G1017", 208, "name"))


def test_clear_spelling_match_wins():
    status, chosen = threats.choose([result("G1017", 90), result("G1045", 55)])
    assert status == "matched" and chosen.external_id == "G1017"


def test_close_race_asks_instead_of_guessing():
    # "cobalt": Cobalt Group 95.9 vs Cobalt Strike 93.9
    assert threats.choose([result("G0080", 95.9), result("S0154", 93.9)]) == ("ambiguous", None)


def test_description_matches_are_never_picked_automatically():
    assert threats.choose([result("T1486", 80, "description")]) == ("ambiguous", None)


def test_nothing_found():
    assert threats.choose([]) == ("not_found", None)


def test_weak_matches_are_dropped():
    kept = threats.useful([result("S0130", 40.4, "some description words"), result("G0066", 21, "similar name"),
                           result("S0179", 38, "description"), result("G1017", 208, "name")])
    assert [r.external_id for r in kept] == ["S0179", "G1017"]


# ---------------------------------------------------------------- verdict and AI source

def sample_lookup(matched_on="name", kind="group"):
    entity = Entity(id="intrusion-set--volt", kind=kind, external_id="G1017", name="Volt Typhoon",
                    aliases=["Vanguard Panda"], description="A state-sponsored actor.",
                    url="https://attack.mitre.org/groups/G1017", source=SOURCE)
    related = [
        RelatedGroup(label="Malware used", relationship="uses",
                     items=[EntitySummary(external_id="S1154", name="VersaMem", kind="malware", url=None)]),
        RelatedGroup(label="Tools used", relationship="uses",
                     items=[EntitySummary(external_id="S0002", name="Mimikatz", kind="tool", url=None)]),
        RelatedGroup(label="Campaigns attributed to this group", relationship="attributed-to",
                     items=[EntitySummary(external_id="C0035", name="KV Botnet Activity", kind="campaign", url=None)]),
        RelatedGroup(label="Techniques used", relationship="uses",
                     items=[EntitySummary(external_id="T1003.001", name="LSASS Memory", kind="technique", url=None)]),
    ]
    profile = ThreatProfile(
        entity=entity, related=related,
        techniques=[TechniqueRef(external_id="T1003.001", name="LSASS Memory", url=None, tactics=["Credential Access"])],
        tactics=[TacticCount(name="Credential Access", count=1)],
        mitigations=[MitigationCoverage(external_id="M1043", name="Credential Access Protection", url=None, covers=1)],
    )
    return ThreatLookup(query="volt typhoon", status="matched", matched_on=matched_on, profile=profile)


def test_profile_verdict_has_no_score():
    verdict = threats.verdict_for(sample_lookup())
    assert verdict.level == "PROFILE" and verdict.score == 0 and verdict.confidence == "high"
    assert verdict.headline == ("Volt Typhoon (G1017) is a threat group in MITRE ATT&CK, documented with "
                                "1 technique, 2 pieces of software and 1 campaign.")
    assert verdict.rules_applied == []


def test_closest_match_is_flagged():
    verdict = threats.verdict_for(sample_lookup(matched_on="similar name"))
    assert verdict.confidence == "medium" and "closest match" in verdict.rules_applied[0]


@pytest.mark.parametrize("status, words", [
    ("not_found", "No group, malware"), ("ambiguous", "Several ATT&CK or CWE entries"), ("unavailable", "isn't available"),
])
def test_no_single_match_is_unknown(status, words):
    verdict = threats.verdict_for(ThreatLookup(query="x", status=status))
    assert verdict.level == "UNKNOWN" and words in verdict.headline


def test_profile_becomes_a_citable_source():
    source = threats.as_source(sample_lookup())
    assert source.source == "MITRE ATT&CK" and source.status == SourceStatus.OK
    assert source.link == "https://attack.mitre.org/groups/G1017"
    assert source.facts["techniques_used"] == ["T1003.001 LSASS Memory (Credential Access)"]
    assert source.facts["malware_used"] == ["S1154 VersaMem"]
    assert source.facts["technique_count"] == 1
    assert source.facts["defenses_covering_most_techniques"] == [
        "M1043 Credential Access Protection: helps against 1 of its techniques"]


def test_without_a_database_names_are_unavailable():
    result = asyncio.run(investigate("Volt Typhoon", fakes.test_settings(), MemoryStore(), fakes.router()))
    assert result.threat.status == "unavailable" and result.verdict.level == "UNKNOWN"
    assert result.report.status == "unavailable"


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


def go(query, store):
    settings = fakes.test_settings(gemini_api_key="g", groq_api_key="q")
    return asyncio.run(investigate(query, settings, store, fakes.router()))


@needs_db
def test_profile_from_the_database(store):
    from app.knowledge.repository import KnowledgeRepository
    profile = asyncio.run(KnowledgeRepository(store).profile("G1017"))
    assert [t.external_id for t in profile.techniques] == ["T1003.001"]
    assert profile.techniques[0].tactics == ["Credential Access"]
    assert [(t.name, t.count) for t in profile.tactics] == [("Credential Access", 1)]
    assert [(m.external_id, m.covers) for m in profile.mitigations] == [("M1043", 1)]


@needs_db
@pytest.mark.parametrize("query, matched_on", [
    ("Volt Typhoon", "name"), ("vanguard panda", "alias: Vanguard Panda"), ("G1017", "ID"), ("volt typhon", "similar name"),
])
def test_threat_investigation(store, query, matched_on):
    result = go(query, store)
    assert result.threat.status == "matched" and result.threat.matched_on == matched_on
    assert result.indicator.value == "Volt Typhoon" and result.indicator.subtype == "group"
    assert result.verdict.level == "PROFILE" and result.signals == []
    assert [s.source for s in result.sources] == ["MITRE ATT&CK"]
    assert result.report.status == "ready"
    assert [s.kind for s in result.trace] == ["detect", "decide", "decide", "fetch", "verdict", "report", "save"]


@needs_db
def test_unknown_name_skips_the_ai(store):
    calls = []
    result = asyncio.run(investigate("zzqq nothing", fakes.test_settings(gemini_api_key="g"), store,
                                     fakes.router(calls=calls)))
    assert result.threat.status == "not_found" and result.verdict.level == "UNKNOWN"
    assert result.report.status == "unavailable"
    assert not any("googleapis" in c for c in calls)


@needs_db
def test_saved_threat_investigation_reloads(store):
    result = go("Volt Typhoon", store)
    loaded = asyncio.run(store.get(result.id))
    assert loaded.threat.profile.entity.external_id == "G1017"
    assert loaded.indicator.type.value == "threat"


@needs_db
def test_every_spelling_shares_one_ai_report(store):
    calls = []
    settings = fakes.test_settings(gemini_api_key="g", groq_api_key="q")
    first = asyncio.run(investigate("Volt Typhoon", settings, store, fakes.router(calls=calls)))
    ai_calls = sum("googleapis" in c for c in calls)
    for spelling in ("vanguard panda", "volt typhon", "G1017"):
        again = asyncio.run(investigate(spelling, settings, store, fakes.router(calls=calls)))
        assert again.report.cached and again.report.summary == first.report.summary, spelling
    assert sum("googleapis" in c for c in calls) == ai_calls  # no new AI calls at all
