"""Draft detection rules: every Sigma rule must load in pySigma, every YARA rule must compile and match."""
import hashlib
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
import yaml
import yara
from fastapi.testclient import TestClient
from sigma.collection import SigmaCollection

from app import main, rules
from app.models import Indicator, IndicatorType, Investigation, Verdict
from app.store import MemoryStore
from tests import fakes

SAMPLE = b"pretend this is a malware sample\n"


def inv(kind, value, level="CRITICAL", subtype=None, id_="inv-1"):
    return Investigation(
        id=id_, query=value, indicator=Indicator(type=kind, value=value, original=value, subtype=subtype),
        verdict=Verdict(score={"CRITICAL": 95, "HIGH": 70, "MEDIUM": 45, "LOW": 10, "UNKNOWN": 0}[level], level=level,
                        confidence="high", headline=f"This is {level} risk."),
        signals=[], sources=[], trace=[], created_at=datetime.now(timezone.utc), duration_ms=1)


def sigma_rules(text):
    collection = SigmaCollection.from_yaml(text)
    for rule in collection.rules:
        assert rule.errors == [], rule.errors
    return collection.rules


def test_ip_rules_are_valid_and_convert():
    result = rules.build([inv(IndicatorType.IP, "45.95.147.236")], "https://site.example")
    parsed = sigma_rules(result.sigma)
    assert [r.logsource.category for r in parsed] == ["network_connection", "firewall"]
    assert all(str(r.level) == "critical" or r.level.name == "CRITICAL" for r in parsed)
    assert result.rules[0]["splunk"] == 'DestinationIp="45.95.147.236" OR SourceIp="45.95.147.236"'
    assert result.rules[1]["elastic"] == "dst_ip:45.95.147.236 OR src_ip:45.95.147.236"
    first = yaml.safe_load(result.sigma.split("---\n")[0])
    assert first["status"] == "experimental" and first["author"] == "ThreatLens (automated draft)"
    assert first["references"] == ["https://site.example/i/inv-1"]
    assert "&id" not in result.sigma and "*id" not in result.sigma  # no YAML aliases
    assert result.yara is None


def test_rule_ids_are_stable_for_the_same_report():
    one = rules.build([inv(IndicatorType.IP, "45.95.147.236")], None)
    two = rules.build([inv(IndicatorType.IP, "45.95.147.236")], None)
    other = rules.build([inv(IndicatorType.IP, "45.95.147.236", id_="inv-2")], None)
    ids = lambda r: [yaml.safe_load(d)["id"] for d in r.sigma.split("---\n")]
    assert ids(one) == ids(two) and ids(one) != ids(other)


def test_domain_rules_match_subdomains_and_escape_wildcards():
    result = rules.build([inv(IndicatorType.DOMAIN, "payload-drop.example", level="HIGH")], None)
    parsed = sigma_rules(result.sigma)
    assert [r.logsource.category for r in parsed] == ["dns_query", "proxy"]
    assert result.rules[0]["splunk"] == 'QueryName IN ("payload-drop.example", "*.payload-drop.example")'
    assert rules.escape("a*b?c\\d") == "a\\*b\\?c\\\\d"


def test_hash_rules_and_yara_match_the_exact_file(tmp_path):
    sha256 = hashlib.sha256(SAMPLE).hexdigest()
    md5 = hashlib.md5(SAMPLE).hexdigest()
    result = rules.build([inv(IndicatorType.HASH, sha256, subtype="sha256", id_="a"),
                          inv(IndicatorType.HASH, md5, subtype="md5", id_="b")], None)
    parsed = sigma_rules(result.sigma)
    assert [r.logsource.category for r in parsed] == ["process_creation", "image_load"]
    assert f"SHA256={sha256.upper()}" in result.sigma and f"MD5={md5.upper()}" in result.sigma

    compiled = yara.compile(source=result.yara)
    matched = {m.rule for m in compiled.match(data=SAMPLE)}
    assert matched == {f"ThreatLens_sha256_{sha256[:12]}", f"ThreatLens_md5_{md5[:12]}"}
    assert compiled.match(data=SAMPLE + b"x") == []  # one byte different, no match


def test_low_risk_private_and_known_good_get_no_rule():
    low = rules.build([inv(IndicatorType.IP, "8.8.8.8", level="LOW")], None)
    assert low.sigma is None and "low risk" in low.notes[0]
    private = rules.build([inv(IndicatorType.IP, "10.0.0.5")], None)
    assert private.sigma is None


def test_cve_links_to_community_rules_instead():
    result = rules.build([inv(IndicatorType.CVE, "CVE-2021-44228")], None)
    assert result.sigma is None and result.yara is None
    assert result.links[0]["url"].endswith("cve.2021-44228")
    assert "isn't something a log contains" in result.notes[0]


def test_reported_techniques_become_tags_linked_ones_dont():
    technique = lambda tid, strength: SimpleNamespace(external_id=tid, name=tid, strength=strength)
    attack_map = SimpleNamespace(status="ok", tactics=[
        SimpleNamespace(shortname="command-and-control", techniques=[technique("T1071", "reported")]),
        SimpleNamespace(shortname="credential-access", techniques=[technique("T1003", "linked")]),
    ])
    result = rules.build([inv(IndicatorType.IP, "45.95.147.236")], None, {"inv-1": attack_map})
    assert yaml.safe_load(result.sigma.split("---\n")[0])["tags"] == ["attack.command-and-control", "attack.t1071"]
    sigma_rules(result.sigma)


def test_bulk_groups_indicators_into_one_rule_each():
    result = rules.build([inv(IndicatorType.IP, "45.95.147.236", id_="1"), inv(IndicatorType.IP, "185.220.101.4", level="HIGH", id_="2"),
                          inv(IndicatorType.IP, "8.8.8.8", level="LOW", id_="3"), inv(IndicatorType.DOMAIN, "payload-drop.example", id_="4")],
                         None, scope="bulk:x")
    parsed = sigma_rules(result.sigma)
    assert len(parsed) == 4 and result.indicators == 3
    first = yaml.safe_load(result.sigma.split("---\n")[0])
    assert first["detection"]["selection_outbound"]["DestinationIp"] == ["45.95.147.236", "185.220.101.4"]
    assert first["title"].endswith("(2 indicators)") and first["level"] == "critical"
    assert "1 indicator rated low risk" in result.notes[0]


# ---------- Endpoints ----------

@pytest.fixture
def api(monkeypatch):
    main.limiter.reset()
    monkeypatch.setattr(main, "settings", fakes.test_settings())
    client = TestClient(main.app)
    client.__enter__()
    main.app.state.http = fakes.router()
    main.app.state.store = MemoryStore()
    yield client
    client.__exit__(None, None, None)


def test_rules_endpoint_and_downloads(api):
    report = api.post("/api/investigations", json={"query": fakes.BAD_IP}).json()
    data = api.get(f"/api/investigations/{report['id']}/rules").json()
    assert data["indicators"] == 1 and fakes.BAD_IP in data["sigma"] and data["rules"][0]["splunk"]
    download = api.get(f"/api/investigations/{report['id']}/export/sigma")
    assert download.status_code == 200 and download.headers["content-disposition"].endswith('.sigma.yml"')
    sigma_rules(download.text)
    assert api.get(f"/api/investigations/{report['id']}/export/yara").status_code == 404  # an IP has no YARA rule
    assert api.get("/api/investigations/nope/rules").status_code == 404


def test_cve_report_has_no_rule_download(api):
    report = api.post("/api/investigations", json={"query": fakes.LOG4SHELL}).json()
    response = api.get(f"/api/investigations/{report['id']}/export/sigma")
    assert response.status_code == 404 and "community" in response.json()["detail"]


def test_bulk_rules_endpoint(api):
    store = main.app.state.store
    import asyncio
    good = api.post("/api/investigations", json={"query": fakes.BAD_IP}).json()
    cve = api.post("/api/investigations", json={"query": fakes.LOG4SHELL}).json()
    batch_id = asyncio.run(store.save_batch({"rows": [{"investigation_id": good["id"]}, {"investigation_id": cve["id"]}, {}]}))
    data = api.get(f"/api/bulk/{batch_id}/rules").json()
    assert data["indicators"] == 1 and fakes.BAD_IP in data["sigma"] and data["links"]
    assert api.get(f"/api/bulk/{batch_id}/export/sigma").status_code == 200
    assert api.get("/api/bulk/nope/rules").status_code == 404
