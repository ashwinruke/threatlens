"""Watchlists: products, private keys, the daily check, alerts, notifications and verdicts."""
import asyncio
import json
import os
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

import httpx2
import pytest
from fastapi.testclient import TestClient

from app import main
from app.sources import kev
from app.store import MemoryStore
from app.watch import checker, feeds, notify
from app.watch.models import Alert, Channel, Watchlist, WatchItem
from app.watch.repository import repository_for
from tests import fakes

NOW = datetime.now(timezone.utc)
DAY = timedelta(days=1)
DISCORD = "https://discord.com/api/webhooks/123456/abcDEF-token"
NTFY = "https://ntfy.sh/threatlens-test-topic"


def nvd_iso(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%S.000")


def cve(cve_id, score, description, published, products=("f5:nginx",)):
    return {"cve": {
        "id": cve_id, "published": nvd_iso(published), "lastModified": nvd_iso(NOW), "vulnStatus": "Analyzed",
        "descriptions": [{"lang": "en", "value": description}],
        "metrics": {"cvssMetricV31": [{"type": "Primary", "source": "nvd@nist.gov",
                                       "cvssData": {"baseScore": score, "baseSeverity": "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "LOW",
                                                    "vectorString": "CVSS:3.1/AV:N"}}]},
        "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": f"cpe:2.3:a:{p}:*:*:*:*:*:*:*:*"} for p in products]}]}],
        "references": [], "weaknesses": [],
    }}


SERIOUS = cve("CVE-2026-1001", 9.8, "A heap overflow in nginx lets an attacker run code.", NOW - 2 * DAY)
MINOR = cve("CVE-2026-1002", 3.1, "A minor information leak in nginx error pages.", NOW - 2 * DAY)
OLD = cve("CVE-2019-0001", 9.8, "An old nginx issue that NVD changed recently.", NOW - 400 * DAY)
NAMED = cve("CVE-2026-1003", 9.1, "A request smuggling flaw in nginx before 1.27.4, not yet tagged by NVD.", NOW - DAY, products=())
EXPLOITED = cve("CVE-2021-23017", 7.7, "A resolver off-by-one in nginx.", NOW - 1500 * DAY)
EXPLOITED_RECENT = cve("CVE-2021-23017", 7.7, "A resolver off-by-one in nginx.", NOW - 5 * DAY)  # same CVE, as a new one
ALL_CVES = {c["cve"]["id"]: c for c in (SERIOUS, MINOR, OLD, NAMED, EXPLOITED)}

KEV = {"vulnerabilities": [
    {"cveID": "CVE-2021-23017", "vendorProject": "F5", "product": "NGINX", "vulnerabilityName": "F5 NGINX resolver",
     "dateAdded": NOW.date().isoformat(), "dueDate": (NOW + 21 * DAY).date().isoformat(),
     "shortDescription": "F5 NGINX contains an off-by-one error in its resolver.", "knownRansomwareCampaignUse": "Unknown",
     "requiredAction": "Patch."},
    {"cveID": "CVE-2020-0002", "vendorProject": "Microsoft", "product": "Exchange Server", "vulnerabilityName": "x",
     "dateAdded": NOW.date().isoformat(), "dueDate": "2026-12-01", "shortDescription": "x",
     "knownRansomwareCampaignUse": "Known", "requiredAction": "Patch."},
]}

CPE_SEARCH = {"products": [
    {"cpe": {"cpeName": f"cpe:2.3:a:f5:nginx:1.{n}.0:*:*:*:*:*:*:*", "titles": [{"title": f"F5 Nginx 1.{n}.0", "lang": "en"}]}}
    for n in range(5)] + [
    {"cpe": {"cpeName": "cpe:2.3:a:nginx:nginx_unit:1.0:*:*:*:*:*:*:*", "titles": [{"title": "Nginx Unit 1.0", "lang": "en"}]}},
    {"cpe": {"cpeName": "cpe:2.3:a:old:nginx:1:*:*:*:*:*:*:*", "titles": [], "deprecated": True}},
]}


class Internet:
    """A fake network: NVD, CISA KEV, FIRST EPSS, and the alert services. Records what was sent."""

    def __init__(self, tagged=(SERIOUS, MINOR, OLD), named=(NAMED,), failing_hosts=()):
        self.tagged, self.named, self.failing = tagged, named, set(failing_hosts)
        self.sent: list[tuple[str, httpx2.Request]] = []
        self.nvd_queries: list[dict] = []

    def handler(self, request: httpx2.Request) -> httpx2.Response:
        url = urlparse(str(request.url))
        params = {k: v[0] for k, v in parse_qs(url.query).items()}
        if url.hostname in self.failing:
            return httpx2.Response(500)
        if url.hostname in ("discord.com", "ntfy.sh", "hooks.slack.com", "api.resend.com"):
            self.sent.append((url.hostname, request))
            return httpx2.Response(204)
        if url.path.endswith("/cpes/2.0"):
            return httpx2.Response(200, json=CPE_SEARCH)
        if url.path.endswith("/cves/2.0"):
            self.nvd_queries.append(params)
            if "cveId" in params:
                found = ALL_CVES.get(params["cveId"])
                return httpx2.Response(200, json={"totalResults": int(bool(found)), "vulnerabilities": [found] if found else []})
            if "virtualMatchString" in params:
                return httpx2.Response(200, json={"vulnerabilities": list(self.tagged)})
            if "keywordSearch" in params:
                return httpx2.Response(200, json={"vulnerabilities": list(self.named)})
        if "known_exploited_vulnerabilities" in str(request.url):
            return httpx2.Response(200, json=KEV)
        if "api.first.org" in str(request.url):
            return httpx2.Response(200, json={"status": "OK", "data": []})
        return httpx2.Response(404)

    def client(self) -> httpx2.AsyncClient:
        return httpx2.AsyncClient(transport=httpx2.MockTransport(self.handler))


@pytest.fixture
def net():
    return Internet()


@pytest.fixture
def api(monkeypatch, net):
    kev.reset_catalog()
    main.limiter.reset()
    monkeypatch.setattr(checker, "NVD_PAUSE_SECONDS", 0)
    monkeypatch.setattr(main, "settings", fakes.test_settings(watch_cron_token="cron-secret",
                                                              public_site_url="https://threatlens.example"))
    client = TestClient(main.app)
    client.__enter__()
    main.app.state.http = net.client()
    main.app.state.store = MemoryStore()
    yield client
    client.__exit__(None, None, None)
    kev.reset_catalog()


def create(api, **overrides):
    body = {"name": "Web servers", "min_level": "HIGH",
            "items": [{"vendor": "f5", "product": "nginx", "title": "F5 Nginx"}],
            "channels": [{"kind": "discord", "target": DISCORD}]}
    body.update(overrides)
    response = api.post("/api/watchlists", json=body)
    assert response.status_code == 201, response.text
    data = response.json()
    return data["id"], {"X-Watchlist-Key": data["key"]}, data


def backdate(watchlist_id, days=3):
    """Pretend the watchlist was made a few days ago, so its first check covers the fake CVEs."""
    repo = repository_for(main.app.state.store)
    key_hash, w = asyncio.run(repo.get(watchlist_id))
    w.created_at = NOW - timedelta(days=days)
    asyncio.run(repo.update(w))


# ---------- Products ----------

def test_product_search_groups_versions_and_ranks(api):
    products = api.get("/api/products", params={"q": "nginx"}).json()
    assert products[0] == {"part": "a", "vendor": "f5", "product": "nginx", "kind": "application", "title": "F5 Nginx", "versions": 5}
    assert [p["product"] for p in products] == ["nginx", "nginx_unit"]  # the deprecated entry is gone


def test_product_search_is_cached(api, net):
    api.get("/api/products", params={"q": "nginx"})
    main.app.state.http = httpx2.AsyncClient(transport=httpx2.MockTransport(lambda r: httpx2.Response(500)))
    assert api.get("/api/products", params={"q": "NGINX"}).json()[0]["product"] == "nginx"


# ---------- Private keys ----------

def test_a_watchlist_needs_its_key(api):
    watchlist_id, headers, data = create(api)
    assert len(data["key"]) >= 30
    assert api.get(f"/api/watchlists/{watchlist_id}").status_code == 404
    assert api.get(f"/api/watchlists/{watchlist_id}", headers={"X-Watchlist-Key": "wrong"}).status_code == 404
    assert api.get("/api/watchlists/not-a-real-id", headers=headers).status_code == 404
    assert api.get(f"/api/watchlists/{watchlist_id}", headers=headers).json()["watchlist"]["name"] == "Web servers"


def test_webhook_addresses_are_never_shown_in_full(api):
    watchlist_id, headers, data = create(api)
    shown = data["watchlist"]["channels"][0]["target"]
    assert "abcDEF-token" not in shown and shown.startswith("discord.com/")
    assert "abcDEF-token" not in json.dumps(api.get(f"/api/watchlists/{watchlist_id}", headers=headers).json())


@pytest.mark.parametrize("kind,target", [
    ("discord", "http://discord.com/api/webhooks/1/x"),  # not https
    ("discord", "https://discord.com.evil.example/api/webhooks/1/x"),  # look-alike host
    ("discord", "https://169.254.169.254/api/webhooks/1/x"),  # internal address
    ("discord", "https://discord.com:8443/api/webhooks/1/x"),
    ("slack", "https://hooks.slack.com.evil.example/services/x"),
    ("ntfy", "https://ntfy.sh/a"),  # topic too short to be private
    ("teams", "https://example.com/workflow"),
    ("email", "not-an-email"),
])
def test_only_known_alert_services_are_accepted(kind, target):
    with pytest.raises(notify.ChannelError):
        notify.validate(kind, target)


def test_email_needs_the_server_set_up(api):
    response = api.post("/api/watchlists", json={"name": "x", "channels": [{"kind": "email", "target": "a@b.example"}]})
    assert response.status_code == 201  # creating accepts it; adding later explains the server needs it
    watchlist_id, headers = response.json()["id"], {"X-Watchlist-Key": response.json()["key"]}
    added = api.post(f"/api/watchlists/{watchlist_id}/channels", headers=headers, json={"kind": "email", "target": "a@b.example"})
    assert added.status_code == 422 and "RESEND" not in added.text


def test_creating_watchlists_is_limited(api):
    for _ in range(main.settings.watchlists_per_day_per_visitor):
        create(api)
    assert api.post("/api/watchlists", json={"name": "one too many"}).status_code == 429


# ---------- The check ----------

def test_check_finds_new_named_and_exploited_cves(api, net):
    watchlist_id, headers, _ = create(api)
    backdate(watchlist_id)
    result = api.post(f"/api/watchlists/{watchlist_id}/check", headers=headers).json()
    alerts = {a["indicator"]: a for a in result["alerts"]}

    assert set(alerts) == {"CVE-2026-1001", "CVE-2026-1003", "CVE-2021-23017"}
    assert alerts["CVE-2026-1001"]["reason"] == "new_cve" and alerts["CVE-2026-1001"]["match"] == "product"
    assert alerts["CVE-2026-1003"]["match"] == "name"  # found by name before NVD tagged the product
    exploited = alerts["CVE-2021-23017"]
    assert exploited["reason"] == "newly_exploited" and exploited["kev_added"] == NOW.date().isoformat()
    # Not alerted: the minor CVE (below HIGH), the old one NVD only edited, the other vendor's KEV entry
    assert "CVE-2026-1002" not in alerts and "CVE-2019-0001" not in alerts and "CVE-2020-0002" not in alerts
    # New CVEs score Medium in ThreatLens (no exploitation evidence yet); their CVSS severity is what alerts
    assert alerts["CVE-2026-1001"]["level"] == "MEDIUM" and alerts["CVE-2026-1001"]["cvss_severity"] == "CRITICAL"
    assert alerts["CVE-2026-1001"]["why"].startswith("NVD rates it CVSS 9.8 (Critical)")
    assert exploited["why"] == "CISA confirmed it is exploited in real attacks"
    assert result["check"]["alerts"] == 3


def test_each_alert_links_to_an_unlisted_report(api):
    watchlist_id, headers, _ = create(api)
    backdate(watchlist_id)
    alerts = api.post(f"/api/watchlists/{watchlist_id}/check", headers=headers).json()["alerts"]
    report = api.get(f"/api/investigations/{alerts[0]['investigation_id']}")
    assert report.status_code == 200 and report.json()["indicator"]["value"] == alerts[0]["indicator"]
    assert api.get("/api/investigations").json() == []  # not in the public History
    assert api.get("/api/numbers").json()["investigations"] == 0


def test_one_message_per_check_with_every_new_alert(api, net):
    watchlist_id, headers, _ = create(api, channels=[{"kind": "discord", "target": DISCORD}, {"kind": "ntfy", "target": NTFY}])
    backdate(watchlist_id)
    api.post(f"/api/watchlists/{watchlist_id}/check", headers=headers)
    hosts = [h for h, _ in net.sent]
    assert hosts == ["discord.com", "ntfy.sh"]
    discord = json.loads(net.sent[0][1].content)["content"]
    assert "3 new alerts for Web servers" in discord and "CVE-2026-1001" in discord
    assert "https://threatlens.example/i/" in discord
    # Exploited first, then by score
    assert discord.index("CVE-2021-23017") < discord.index("CVE-2026-1001") < discord.index("CVE-2026-1003")
    ntfy = net.sent[1][1]
    assert ntfy.headers["Priority"] == "high" and "CVE-2026-1003" in ntfy.content.decode()


def test_no_repeats_and_verdicts_keep_alerts_quiet(api, net, monkeypatch):
    watchlist_id, headers, _ = create(api)
    backdate(watchlist_id)
    alerts = api.post(f"/api/watchlists/{watchlist_id}/check", headers=headers).json()["alerts"]
    serious = next(a for a in alerts if a["indicator"] == "CVE-2026-1001")
    verdict = api.post(f"/api/watchlists/{watchlist_id}/alerts/{serious['id']}/verdict", headers=headers,
                       json={"status": "false_alarm", "note": "We run nginx behind a proxy that blocks this."})
    assert verdict.json()["status"] == "false_alarm" and verdict.json()["decided_at"]

    net.sent.clear()
    monkeypatch.setattr(main.settings, "watch_manual_check_minutes", 0)
    repo = repository_for(main.app.state.store)
    _, w = asyncio.run(repo.get(watchlist_id))
    w.last_checked_at = NOW - 3 * DAY  # the same CVEs are in the window again
    asyncio.run(repo.update(w))
    second = api.post(f"/api/watchlists/{watchlist_id}/check", headers=headers).json()
    assert second["check"]["alerts"] == 0 and net.sent == []
    assert next(a for a in second["alerts"] if a["indicator"] == "CVE-2026-1001")["status"] == "false_alarm"


def test_feed_cvss_is_used_when_nvd_isnt_configured(api, monkeypatch):
    monkeypatch.setattr(main.settings, "nvd_api_key", "")  # the scoring can't ask NVD, the feed still says 9.8
    watchlist_id, headers, _ = create(api)
    backdate(watchlist_id)
    alerts = {a["indicator"]: a for a in api.post(f"/api/watchlists/{watchlist_id}/check", headers=headers).json()["alerts"]}
    assert alerts["CVE-2026-1001"]["cvss"] == 9.8 and alerts["CVE-2026-1001"]["why"].startswith("NVD rates it CVSS 9.8")


def test_threshold_controls_what_alerts(api):
    watchlist_id, headers, _ = create(api, min_level="MEDIUM")
    backdate(watchlist_id)
    medium = {a["indicator"] for a in api.post(f"/api/watchlists/{watchlist_id}/check", headers=headers).json()["alerts"]}
    assert medium == {"CVE-2026-1001", "CVE-2026-1003", "CVE-2021-23017"}  # the CVSS 3.1 one stays quiet even here
    critical_id, critical_headers, _ = create(api, min_level="CRITICAL")
    backdate(critical_id)
    only = api.post(f"/api/watchlists/{critical_id}/check", headers=critical_headers).json()["alerts"]
    assert {a["indicator"] for a in only} == {"CVE-2026-1001", "CVE-2026-1003", "CVE-2021-23017"}
    assert all(a["cvss_severity"] == "CRITICAL" or a["reason"] == "newly_exploited" for a in only)


def test_an_earlier_alert_escalates_when_exploited(api, net, monkeypatch):
    net.tagged = (SERIOUS, MINOR, OLD, EXPLOITED_RECENT)
    watchlist_id, headers, _ = create(api)
    backdate(watchlist_id)
    monkeypatch.setattr(main.settings, "watch_manual_check_minutes", 0)
    kev_today = KEV["vulnerabilities"][0]["dateAdded"]
    KEV["vulnerabilities"][0]["dateAdded"] = "2020-01-01"  # not exploited yet on the first check
    try:
        first = {a["indicator"]: a for a in api.post(f"/api/watchlists/{watchlist_id}/check", headers=headers).json()["alerts"]}
        assert first["CVE-2021-23017"]["reason"] == "new_cve"
        kev.reset_catalog()
        KEV["vulnerabilities"][0]["dateAdded"] = kev_today
        net.sent.clear()
        second = {a["indicator"]: a for a in api.post(f"/api/watchlists/{watchlist_id}/check", headers=headers).json()["alerts"]}
    finally:
        KEV["vulnerabilities"][0]["dateAdded"] = kev_today
    escalated = second["CVE-2021-23017"]
    assert escalated["reason"] == "newly_exploited" and escalated["escalated"] and len(second) == len(first)
    assert "after an earlier alert" in json.loads(net.sent[0][1].content)["content"]


def test_check_now_is_rate_limited(api):
    watchlist_id, headers, _ = create(api)
    assert api.post(f"/api/watchlists/{watchlist_id}/check", headers=headers).status_code == 200
    again = api.post(f"/api/watchlists/{watchlist_id}/check", headers=headers)
    assert again.status_code == 429 and "minute" in again.json()["detail"]


def test_a_failing_channel_is_recorded_and_doesnt_stop_others(api):
    net = Internet(failing_hosts={"discord.com"})
    main.app.state.http = net.client()
    watchlist_id, headers, _ = create(api, channels=[{"kind": "discord", "target": DISCORD}, {"kind": "ntfy", "target": NTFY}])
    backdate(watchlist_id)
    data = api.post(f"/api/watchlists/{watchlist_id}/check", headers=headers).json()
    discord, ntfy = data["watchlist"]["channels"]
    assert discord["last_error"] == "Discord answered HTTP 500" and ntfy["last_error"] is None and ntfy["last_sent_at"]
    assert [h for h, _ in net.sent] == ["ntfy.sh"]


def test_test_message(api, net):
    watchlist_id, headers, data = create(api)
    channel_id = data["watchlist"]["channels"][0]["id"]
    after = api.post(f"/api/watchlists/{watchlist_id}/channels/{channel_id}/test", headers=headers).json()
    assert after["watchlist"]["channels"][0]["last_sent_at"]
    assert "ThreatLens test for Web servers" in json.loads(net.sent[0][1].content)["content"]


def test_scheduled_run_needs_the_token(api, net):
    watchlist_id, headers, _ = create(api)
    backdate(watchlist_id)
    assert api.post("/api/watch/run").status_code == 403
    assert api.post("/api/watch/run", headers={"X-Cron-Token": "nope"}).status_code == 403
    result = api.post("/api/watch/run", headers={"X-Cron-Token": "cron-secret"}).json()
    assert result["watchlists"] == 1 and result["alerts"] == 3 and result["notifications"] == 1
    main.settings.watch_cron_token = ""
    assert api.post("/api/watch/run", headers={"X-Cron-Token": ""}).status_code == 404


def test_shared_products_are_looked_up_once(api, net):
    for name in ("A", "B", "C"):
        watchlist_id, _, _ = create(api, name=name, channels=[])
        backdate(watchlist_id)
    api.post("/api/watch/run", headers={"X-Cron-Token": "cron-secret"})
    product_queries = [q for q in net.nvd_queries if "virtualMatchString" in q]
    assert [q["virtualMatchString"] for q in product_queries] == ["cpe:2.3:a:f5:nginx"]
    assert product_queries[0]["lastModStartDate"].endswith(".000+00:00")


# ---------- Verdicts on any report ----------

def test_saving_a_report_with_a_verdict(api):
    watchlist_id, headers, _ = create(api, channels=[])
    main.app.state.http = fakes.router()
    report = api.post("/api/investigations", json={"query": fakes.BAD_IP}).json()
    saved = api.post(f"/api/watchlists/{watchlist_id}/cases", headers=headers,
                     json={"investigation_id": report["id"], "status": "confirmed", "note": "Seen in our firewall logs."})
    assert saved.status_code == 200 and saved.json()["reason"] == "saved" and saved.json()["status"] == "confirmed"
    # Saving the same indicator again updates it rather than adding another
    api.post(f"/api/watchlists/{watchlist_id}/cases", headers=headers,
             json={"investigation_id": report["id"], "status": "false_alarm", "note": "It was our scanner."})
    view = api.get(f"/api/watchlists/{watchlist_id}", headers=headers).json()
    assert len(view["alerts"]) == 1 and view["alerts"][0]["status"] == "false_alarm"
    assert view["stats"]["false_alarm"] == 1 and view["stats"]["precision_pct"] == 0


def test_precision_counts_only_judged_alerts(api):
    from app.watch.api import _stats
    alerts = [Alert(indicator=f"CVE-{i}", reason="new_cve", level="HIGH", status=s)
              for i, s in enumerate(["confirmed", "confirmed", "confirmed", "false_alarm", "new", "not_affected"])]
    assert _stats(alerts)["precision_pct"] == 75


# ---------- Pieces ----------

@pytest.mark.parametrize("vendor,product,kev_vendor,kev_product,match", [
    ("f5", "nginx", "F5", "NGINX", True),
    ("apache", "log4j", "Apache", "Log4j2", True),
    ("microsoft", "exchange_server", "Microsoft", "Exchange Server", True),
    ("microsoft", "windows", "Microsoft", "Exchange Server", False),
    ("f5", "nginx", "F5", "BIG-IP", False),
])
def test_kev_product_matching(vendor, product, kev_vendor, kev_product, match):
    assert feeds.kev_matches({"vendorProject": kev_vendor, "product": kev_product}, vendor, product) is match


def test_name_search_skips_very_short_product_names(net):
    async def go():
        async with net.client() as client:
            return await feeds.new_cves("a", "golang", "go", NOW - 3 * DAY, NOW, client, "k")
    found = asyncio.run(go())
    assert all(c["match"] == "product" for c in found)
    assert not any("keywordSearch" in q for q in net.nvd_queries)


def test_teams_and_slack_messages():
    w = Watchlist(id="w1", name="Team", items=[WatchItem(vendor="f5", product="nginx", title="F5 Nginx")])
    alert = Alert(indicator="CVE-2026-1001", reason="new_cve", level="CRITICAL", score=95, item_title="F5 Nginx",
                  title="A heap overflow", investigation_id="abc")
    title, body = notify.message(w, [alert], "https://site.example")
    assert title == "ThreatLens: 1 new alert for Team"
    assert "CVE-2026-1001 — Critical 95 · F5 Nginx" in body and "https://site.example/i/abc" in body
    seen = []

    async def go(kind, target):
        transport = httpx2.MockTransport(lambda r: seen.append(json.loads(r.content)) or httpx2.Response(200))
        async with httpx2.AsyncClient(transport=transport) as client:
            await notify.send(Channel(kind=kind, target=target), title, body, client, fakes.test_settings())
    asyncio.run(go("teams", "https://prod.westus.logic.azure.com/workflows/abc/triggers/manual/paths/invoke"))
    asyncio.run(go("slack", "https://hooks.slack.com/services/T0/B0/xyz"))
    assert seen[0]["attachments"][0]["content"]["body"][0]["text"] == title
    assert seen[1]["text"].startswith("*ThreatLens: 1 new alert for Team*")


def test_redirects_are_never_followed():
    async def go():
        transport = httpx2.MockTransport(lambda r: httpx2.Response(302, headers={"location": "http://169.254.169.254/"}))
        async with httpx2.AsyncClient(transport=transport, follow_redirects=True) as client:
            await notify.send(Channel(kind="ntfy", target=NTFY), "t", "b", client, fakes.test_settings())
    with pytest.raises(notify.ChannelError, match="HTTP 302"):
        asyncio.run(go())


@pytest.mark.skipif(not os.environ.get("TEST_DATABASE_URL"), reason="set TEST_DATABASE_URL")
def test_postgres_watch_repository():
    from app.store import PostgresStore
    from app.watch.repository import PostgresWatchRepository, hash_key

    async def go():
        store = PostgresStore(os.environ["TEST_DATABASE_URL"])
        await store.init()
        repo = PostgresWatchRepository(store)
        try:
            w = await repo.create(Watchlist(name="db test", items=[WatchItem(vendor="f5", product="nginx", title="F5 Nginx")]), hash_key("k"))
            key_hash, loaded = await repo.get(w.id)
            assert key_hash == hash_key("k") and loaded.items[0].product == "nginx"
            loaded.last_checked_at = NOW
            await repo.update(loaded)
            assert (await repo.get(w.id))[1].last_checked_at == NOW
            first = await repo.add_alert(Alert(watchlist_id=w.id, indicator="CVE-1", reason="new_cve", level="HIGH"))
            assert first and await repo.add_alert(Alert(watchlist_id=w.id, indicator="CVE-1", reason="new_cve", level="HIGH")) is None
            first.status = "confirmed"
            await repo.update_alert(first)
            assert (await repo.find_alert(w.id, "CVE-1")).status == "confirmed"
            assert [a.indicator for a in await repo.alerts_for(w.id)] == ["CVE-1"]
            await repo.delete(w.id)
            assert await repo.get(w.id) is None and await repo.alerts_for(w.id) == []  # alerts go with it
            # Unlisted investigations stay out of History
            investigation = await __import__("app.investigate", fromlist=["investigate"]).investigate(
                fakes.LOG4SHELL, fakes.test_settings(), store, fakes.router(), write_ai_report=False, listed=False)
            assert investigation.id not in [s.id for s in await store.recent(50)]
            assert (await store.get(investigation.id)) is not None
        finally:
            await store.close()
    asyncio.run(go())
