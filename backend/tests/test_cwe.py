"""CWE (Common Weakness Enumeration): parsing MITRE's catalog, searching it, weakness profiles,
and naming the weaknesses NVD lists for a CVE.

Parsing and detection tests always run. Database tests use the small sample catalog and need
TEST_DATABASE_URL (see tests/test_knowledge.py).
"""
import asyncio
import copy
import os

import pytest

from app.detection import detect
from app.investigate import investigate
from app.knowledge import attack, cwe
from app.models import IndicatorType
from app.sources import kev
from tests import fakes
from tests.attack_sample import BUNDLE
from tests.cwe_sample import CWE_XML, zipped


def parsed():
    return cwe.parse_catalog(cwe.read_file(zipped()))


# ---------------------------------------------------------------- parsing

def test_keeps_weaknesses_only():
    version, entities, _ = parsed()
    assert version == "4.18"
    assert [e.external_id for e in entities] == ["CWE-707", "CWE-74", "CWE-79", "CWE-89", "CWE-20", "CWE-502"]
    assert {e.kind for e in entities} == {"weakness"}  # no deprecated CWE-1, no category, no view


def test_weakness_details():
    _, entities, _ = parsed()
    xss = next(e for e in entities if e.external_id == "CWE-79")
    assert xss.aliases == ["XSS", "HTML Injection"]
    assert xss.url == "https://cwe.mitre.org/data/definitions/79.html"
    assert xss.description.endswith("There are many flavors of XSS: Reflected XSS Stored XSS")  # XHTML flattened
    assert xss.details["abstraction"] == "Base" and xss.details["likelihood_of_exploit"] == "High"
    assert xss.details["consequences"] == [{"scope": ["Access Control", "Confidentiality"],
                                            "impact": ["Bypass Protection Mechanism", "Read Application Data"]}]
    assert xss.details["mitigations"][0] == {
        "phase": ["Architecture and Design"], "effectiveness": None,
        "description": "Use a vetted library or framework that does not allow this weakness to occur."}
    assert xss.details["platforms"] == ["Web Based"]  # "Not Language-Specific" isn't a platform
    assert xss.details["capec"] == ["CAPEC-63", "CAPEC-588"]


def test_relationships_from_the_main_hierarchy_only():
    _, _, relationships = parsed()
    assert sorted((r.source_id, r.type, r.target_id) for r in relationships) == [
        ("cwe--20", "can-precede", "cwe--89"),
        ("cwe--20", "childof", "cwe--707"),
        ("cwe--74", "childof", "cwe--707"),
        ("cwe--79", "childof", "cwe--74"),  # once, though it's listed in two views
        ("cwe--89", "childof", "cwe--74"),
    ]  # parents missing from the file (943, 913) and PeerOf links are left out


def test_plain_xml_works_too():
    assert len(cwe.parse_catalog(cwe.read_file(CWE_XML))[1]) == 6


def test_rejects_other_files():
    with pytest.raises(ValueError, match="CWE catalog"):
        cwe.parse_catalog(b"<bundle/>")


@pytest.mark.parametrize("raw", ["CWE-79", "cwe-79", "CWE 79", "CWE079"])
def test_cwe_ids_are_recognized(raw):
    indicator = detect(raw)
    assert indicator.type == IndicatorType.THREAT and indicator.value == "CWE-79"


# ---------------------------------------------------------------- with the database

DB_URL = os.environ.get("TEST_DATABASE_URL")
needs_db = pytest.mark.skipif(not DB_URL, reason="set TEST_DATABASE_URL to run database tests")


@pytest.fixture
def store():
    from app.knowledge.repository import KnowledgeRepository
    from app.store import PostgresStore

    kev.reset_catalog()
    store = PostgresStore(DB_URL)
    asyncio.run(store.init())
    repository = KnowledgeRepository(store)
    version, entities, relationships, redirects = attack.parse_bundle(copy.deepcopy(BUNDLE))
    repository.import_source(attack.SOURCE, version, entities, relationships, redirects)
    version, entities, relationships = parsed()
    repository.import_source(cwe.SOURCE, version, entities, relationships, [])
    yield store
    asyncio.run(store.close())


def go(query, store):
    return asyncio.run(investigate(query, fakes.test_settings(gemini_api_key="g"), store, fakes.router()))


@needs_db
@pytest.mark.parametrize("query, expected, reason", [
    ("CWE-79", "CWE-79", "ID"),
    ("XSS", "CWE-79", "alias: XSS"),
    ("sql injection", "CWE-89", "alias: SQL injection"),
    ("SQLi", "CWE-89", "alias: SQLi"),
    ("Deserialization of Untrusted Data", "CWE-502", "name"),
])
def test_search_finds_weaknesses(store, query, expected, reason):
    from app.knowledge.search import search
    top = asyncio.run(search(store, query))[0]
    assert (top.external_id, top.matched_on) == (expected, reason)


@needs_db
def test_weakness_profile(store):
    result = go("XSS", store)
    assert result.threat.status == "matched" and result.indicator.subtype == "weakness"
    assert result.verdict.level == "PROFILE"
    assert result.verdict.headline == (
        "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') (CWE-79) is a "
        "software weakness in MITRE CWE, with a high likelihood of exploit.")
    source = result.sources[0]
    assert source.source == "MITRE CWE" and source.link == "https://cwe.mitre.org/data/definitions/79.html"
    assert source.facts["how_to_prevent"][1] == (
        "Implementation: Use and specify an output encoding that can be handled by the downstream component.")
    assert source.facts["broader_weakness"] == ["CWE-74 Improper Neutralization of Special Elements in Output "
                                                "Used by a Downstream Component ('Injection')"]
    assert result.report.status == "ready"


@needs_db
def test_weakness_hierarchy_both_ways(store):
    from app.knowledge.repository import KnowledgeRepository
    view = asyncio.run(KnowledgeRepository(store).view("CWE-74"))
    groups = {g.label: [i.external_id for i in g.items] for g in view.related}
    assert groups == {"Broader weakness": ["CWE-707"], "More specific weaknesses": ["CWE-79", "CWE-89"]}
    view89 = asyncio.run(KnowledgeRepository(store).view("CWE-89"))
    assert {g.label for g in view89.related} == {"Broader weakness", "Can result from"}


@needs_db
def test_cve_reports_name_their_weaknesses(store):
    result = go(fakes.LOG4SHELL, store)
    nvd = next(s for s in result.sources if s.source == "NVD")
    assert nvd.facts["weaknesses"] == ["CWE-20 Improper Input Validation", "CWE-502 Deserialization of Untrusted Data"]


@needs_db
def test_cached_nvd_answer_keeps_plain_ids(store):
    with store.connection() as conn:  # an answer cached by an earlier test run would be reused and not refreshed
        conn.execute("DELETE FROM source_cache")
    go(fakes.LOG4SHELL, store)  # fills the source cache
    from datetime import timedelta
    from app.sources.nvd import NVDSource
    cached = asyncio.run(store.get_cached(NVDSource.name, detect(fakes.LOG4SHELL), timedelta(hours=1)))
    assert cached.facts["weaknesses"] == ["CWE-20", "CWE-502"]


@needs_db
def test_reimport_removes_deprecated_weaknesses(store):
    from app.knowledge.repository import KnowledgeRepository
    smaller = CWE_XML.replace(b'ID="502" Name="Deserialization of Untrusted Data" Abstraction="Base" '
                              b'Structure="Simple" Status="Draft"',
                              b'ID="502" Name="Deserialization of Untrusted Data" Abstraction="Base" '
                              b'Structure="Simple" Status="Deprecated"')
    version, entities, relationships = cwe.parse_catalog(smaller)
    result = KnowledgeRepository(store).import_source(cwe.SOURCE, version, entities, relationships, [])
    assert result["removed_entities"] == 1
    assert asyncio.run(KnowledgeRepository(store).view("CWE-502")) is None
    assert asyncio.run(KnowledgeRepository(store).view("G1017")) is not None  # ATT&CK untouched


@needs_db
def test_stats_per_source(store):
    from fastapi.testclient import TestClient

    from app import main
    with TestClient(main.app) as client:
        main.app.state.store = store
        cwe_stats = client.get("/api/knowledge/stats", params={"source": "mitre-cwe"}).json()
        assert cwe_stats["version"] == "4.18" and cwe_stats["entities"] == {"weakness": 6}
        assert client.get("/api/knowledge/stats").json()["source"] == "mitre-attack"
        assert client.get("/api/knowledge/stats", params={"source": "nope"}).status_code == 422


@needs_db
def test_broad_weakness_headline_counts_specific_ones(store):
    result = go("CWE-74", store)
    assert result.verdict.headline.endswith(
        "(CWE-74) is a software weakness in MITRE CWE, with 2 more specific weaknesses under it.")
