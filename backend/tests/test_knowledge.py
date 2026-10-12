"""The ATT&CK knowledge graph: parsing MITRE's file, importing it, and looking things up.

Parsing tests always run. Database tests run when TEST_DATABASE_URL points at a PostgreSQL
database you don't mind being written to (they create and replace ATT&CK tables' contents).
"""
import asyncio
import copy
import os

import pytest

from app.knowledge.attack import SOURCE, clean_text, parse_bundle
from tests.attack_sample import BUNDLE


def parsed(bundle=BUNDLE):
    return parse_bundle(copy.deepcopy(bundle))


# ---------------------------------------------------------------- parsing

def test_keeps_live_objects_with_plain_kinds():
    version, entities, _, _ = parsed()
    assert version == "19.2"
    kinds = {e.external_id: e.kind for e in entities}
    assert kinds == {"TA0006": "tactic", "T1003": "technique", "T1003.001": "technique", "G1017": "group",
                     "S1154": "malware", "S0002": "tool", "C0035": "campaign", "M1043": "mitigation"}


def test_aliases_exclude_the_name_itself():
    _, entities, _, _ = parsed()
    group = next(e for e in entities if e.external_id == "G1017")
    assert group.aliases == ["BRONZE SILHOUETTE", "Vanguard Panda"]
    assert next(e for e in entities if e.external_id == "S1154").aliases == []


def test_technique_details():
    _, entities, _, _ = parsed()
    sub = next(e for e in entities if e.external_id == "T1003.001")
    assert sub.details["is_subtechnique"] is True
    assert sub.details["tactics"] == [{"id": "TA0006", "name": "Credential Access"}]
    assert sub.url == "https://attack.mitre.org/techniques/T1003/001"
    assert sub.details["references"] == [{"title": "Example Report", "url": "https://example.org/report"}]


def test_descriptions_are_cleaned():
    _, entities, relationships, _ = parsed()
    sub = next(e for e in entities if e.external_id == "T1003.001")
    assert sub.description == "Tools like Mimikatz run `sekurlsa::logonpasswords` or `net user <username>`."
    parent = next(e for e in entities if e.external_id == "T1003")
    assert "Citation" not in parent.description and parent.description.endswith("dump credentials.")
    uses = next(r for r in relationships if r.id == "relationship--2")
    assert uses.description == "Volt Typhoon dumped LSASS."


def test_relationships_skip_deprecated_and_unknown_ends():
    _, _, relationships, _ = parsed()
    assert sorted(r.id.split("--")[1] for r in relationships) == ["1", "2", "3", "4", "5", "6", "7"]


def test_retired_ids_follow_the_replacement_chain():
    _, _, _, redirects = parsed()
    targets = {r.old_external_id: r.entity_id for r in redirects}
    assert targets == {"G0074": "intrusion-set--volt", "G0075": "intrusion-set--volt"}


def test_clean_text_edge_cases():
    assert clean_text(None) == ""
    assert clean_text("A  (Citation: X)  B") == "A B"
    assert clean_text("see [T1003](https://attack.mitre.org/techniques/T1003) now") == "see T1003 now"
    assert clean_text("<b>bold</b> and <DOMAIN>") == "bold and <DOMAIN>"


# ---------------------------------------------------------------- database

DB_URL = os.environ.get("TEST_DATABASE_URL")
needs_db = pytest.mark.skipif(not DB_URL, reason="set TEST_DATABASE_URL to run database tests")


@pytest.fixture
def repo():
    from app.knowledge.repository import KnowledgeRepository
    from app.store import PostgresStore

    store = PostgresStore(DB_URL)
    asyncio.run(store.init())
    repository = KnowledgeRepository(store)
    version, entities, relationships, redirects = parsed()
    repository.import_source(SOURCE, version, entities, relationships, redirects)
    yield repository
    asyncio.run(store.close())


@needs_db
def test_view_groups_connections(repo):
    view = asyncio.run(repo.view("g1017"))
    assert view.entity.name == "Volt Typhoon" and view.redirected_from is None
    groups = {g.label: [i.external_id for i in g.items] for g in view.related}
    assert groups == {"Campaigns attributed to this group": ["C0035"], "Malware used": ["S1154"],
                      "Tools used": ["S0002"], "Techniques used": ["T1003.001"]}


@needs_db
def test_view_from_the_technique_side(repo):
    groups = {g.label: [i.external_id for i in g.items] for g in asyncio.run(repo.view("T1003.001")).related}
    assert groups == {"Parent technique": ["T1003"], "Used by groups": ["G1017"],
                      "Used by tools": ["S0002"], "Mitigations": ["M1043"]}
    tactic = {g.label: [i.external_id for i in g.items] for g in asyncio.run(repo.view("TA0006")).related}
    assert tactic == {"Techniques in this tactic": ["T1003", "T1003.001"]}


@needs_db
def test_retired_id_redirects(repo):
    view = asyncio.run(repo.view("G0074"))
    assert view.entity.external_id == "G1017" and view.redirected_from == "G0074"
    assert asyncio.run(repo.view("G9999")) is None


@needs_db
def test_reimport_removes_what_mitre_retired(repo):
    smaller = copy.deepcopy(BUNDLE)
    smaller["objects"] = [o for o in smaller["objects"] if o.get("id") != "malware--versamem"]
    version, entities, relationships, redirects = parse_bundle(smaller)
    result = repo.import_source(SOURCE, version, entities, relationships, redirects)
    assert result["removed_entities"] == 1
    assert asyncio.run(repo.view("S1154")) is None
    groups = {g.label for g in asyncio.run(repo.view("G1017")).related}
    assert "Malware used" not in groups  # its relationship went with it


@needs_db
def test_stats(repo):
    stats = asyncio.run(repo.stats(SOURCE))
    assert stats.version == "19.2" and stats.entities["technique"] == 2 and stats.relationships == 7


def test_api_explains_when_there_is_no_database():
    from fastapi.testclient import TestClient

    from app import main
    from app.store import MemoryStore
    with TestClient(main.app) as client:
        main.app.state.store = MemoryStore()
        response = client.get("/api/knowledge/entities/G1017")
        assert response.status_code == 503 and "needs the database" in response.json()["detail"]


# ---------------------------------------------------------------- search

from app.knowledge.search import first_sentence, score  # noqa: E402


def row(**values):
    base = {"exact_id": False, "exact_name": False, "exact_alias": None, "name_similarity": 0.0,
            "alias_similarity": 0.0, "best_alias": None, "has_all_words": False, "text_rank": 0.0}
    return {**base, **values}


def test_exact_matches_always_outrank_partial_ones():
    best_partial, _ = score(row(name_similarity=1.0, alias_similarity=1.0, has_all_words=True, text_rank=1.0))
    exact_alias, reason = score(row(exact_alias="Cozy Bear"))
    assert exact_alias > best_partial and reason == "alias: Cozy Bear"
    assert score(row(exact_name=True))[0] > exact_alias
    assert score(row(exact_id=True))[0] > score(row(exact_name=True, text_rank=1.0, has_all_words=True))[0]


def test_names_ignoring_spaces_count_as_exact():
    assert score(row(compact_name=True)) == (195.0, "name, ignoring spaces")
    assert score(row(compact_alias=True))[0] >= 190
    from app.knowledge.search import compact
    assert compact("Agent Tesla") == compact("AgentTesla") == compact("win.agent_tesla") == "agenttesla"
    assert compact("--") is None and compact("ab") is None


def test_match_reasons():
    assert score(row(name_similarity=0.8))[1] == "similar name"
    assert score(row(alias_similarity=0.9, best_alias="WanaCry"))[1] == "similar alias: WanaCry"
    assert score(row(text_rank=0.5, has_all_words=True))[1] == "description"
    assert score(row(text_rank=0.5))[1] == "some description words"


def test_first_sentence():
    assert first_sentence("One. Two.") == "One."
    assert first_sentence("no full stop here") == "no full stop here"
    long = "word " * 100
    assert first_sentence(long).endswith("…") and len(first_sentence(long)) <= 220


def run_search(repo, query, **kwargs):
    from app.knowledge.search import search
    return asyncio.run(search(repo.store, query, **kwargs))


@needs_db
@pytest.mark.parametrize("query, expected, reason", [
    ("G1017", "G1017", "ID"),
    ("volt typhoon", "G1017", "name"),
    ("Vanguard Panda", "G1017", "alias: Vanguard Panda"),
    ("volt typhon", "G1017", "similar name"),
    ("mimikatz", "S0002", "name"),
    ("lsass", "T1003.001", "similar name"),
    ("KV Botnet", "C0035", "similar name"),
])
def test_search_finds_the_right_entry(repo, query, expected, reason):
    results = run_search(repo, query)
    assert results[0].external_id == expected and results[0].matched_on == reason


@needs_db
def test_search_kind_filter_and_limits(repo):
    assert {r.kind for r in run_search(repo, "credential", kinds=["technique"])} == {"technique"}
    assert run_search(repo, "   ") == []
    assert len(run_search(repo, "a", limit=1)) <= 1
    assert run_search(repo, "zzzzqqqq") == []
