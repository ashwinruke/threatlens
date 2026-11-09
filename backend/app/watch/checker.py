"""The watchlist check: find what's new for every watched product, score it, alert, notify.

Runs once a day for every watchlist (started by a scheduled GitHub Actions job, because Render's
free plan has no timers) and on demand when someone presses "Check now".

  1. Look-back window: since the watchlist's last check (a first check looks back 7 days)
  2. NVD: new CVEs for each watched product. Each product is looked up once, however many
     watchlists share it, to stay inside NVD's free rate limit.
  3. CISA KEV: entries added in the window that name a watched product. An older CVE that is
     now being exploited matters more than most new ones, so these always alert.
  4. Score each candidate with the normal ThreatLens formula (the same sources and points as
     any investigation), without saving it.
  5. Alert when ThreatLens's risk level OR NVD's CVSS severity reaches the watchlist's threshold.
     Both, because a brand-new CVE has no exploitation evidence yet, so even a CVSS 9.8 scores
     only Medium in ThreatLens; the CVSS severity is what tells you to look now. Newly exploited
     CVEs always alert. One alert per CVE per watchlist, so a CVE marked "false alarm" or
     "not affected" stays quiet; the one exception is escalation: a CVE you were told about
     that CISA later confirms exploited alerts again, unless you muted it.
  6. Save a full, unlisted investigation for each new alert (the alert links to it), with an
     AI summary while the run's AI budget lasts.
  7. Send one message per watchlist with its new alerts.
"""
import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import httpx2

from app.export import site_url
from app.investigate import investigate
from app.watch import feeds, notify
from app.watch.models import LEVEL_RANK, MUTING, Alert, Watchlist
from app.watch.repository import repository_for

log = logging.getLogger(__name__)
FIRST_LOOK_BACK = timedelta(days=7)
NVD_PAUSE_SECONDS = 0.7  # NVD allows 50 requests per 30 seconds with a key
_running = asyncio.Lock()


@dataclass
class RunSummary:
    watchlists: int = 0
    products: int = 0
    candidates: int = 0
    alerts: int = 0
    notifications: int = 0
    errors: list[str] = field(default_factory=list)

    def text(self) -> str:
        found = f"{self.alerts} new alert{'s' if self.alerts != 1 else ''}"
        problems = f", {len(self.errors)} problem{'s' if len(self.errors) != 1 else ''}" if self.errors else ""
        return f"Checked {self.products} product{'s' if self.products != 1 else ''}: {found}{problems}."


def _cvss(investigation) -> tuple[float, str] | None:
    """NVD's CVSS score and severity, from the investigation's NVD answer."""
    nvd = next((r for r in investigation.sources if r.source == "NVD" and r.facts), None)
    cvss = (nvd.facts.get("cvss") or {}) if nvd else {}
    if cvss.get("score") is None or not cvss.get("severity"):
        return None
    return float(cvss["score"]), str(cvss["severity"]).upper()


def _feed_cvss(candidate: dict) -> tuple[float, str] | None:
    """The CVSS in NVD's feed entry, for when the scoring couldn't reach NVD (no key, an outage)."""
    cvss = candidate.get("cvss") or {}
    if cvss.get("score") is None or not cvss.get("severity"):
        return None
    return float(cvss["score"]), str(cvss["severity"]).upper()


def _why(level: str, cvss: tuple[float, str] | None, reason: str, threshold: str) -> str:
    """Why this alerts, in words; empty if it doesn't."""
    if reason == "newly_exploited":
        return "CISA confirmed it is exploited in real attacks"
    bar = LEVEL_RANK[threshold]
    if LEVEL_RANK.get(level, 0) >= bar:
        return f"ThreatLens rates it {level.title()} risk"
    if cvss and LEVEL_RANK.get(cvss[1], 0) >= bar:
        return f"NVD rates it CVSS {cvss[0]:g} ({cvss[1].title()}); too new for evidence of exploitation"
    return ""


def _first_line(text: str, limit: int = 220) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= limit else text[: limit - 1].rsplit(" ", 1)[0] + "…"


async def run(store, settings, client: httpx2.AsyncClient, only: Watchlist | None = None,
              now: datetime | None = None) -> RunSummary:
    if _running.locked():
        return RunSummary(errors=["A check is already running. Try again in a minute."])
    async with _running:
        return await _run(store, settings, client, only, now or datetime.now(timezone.utc))


async def _run(store, settings, client, only, now) -> RunSummary:
    repo = repository_for(store)
    watchlists = [only] if only else [w for w in await repo.all() if w.items]
    summary = RunSummary(watchlists=len(watchlists))
    if not watchlists:
        return summary

    def window_start(w: Watchlist) -> datetime:
        return w.last_checked_at or (w.created_at - FIRST_LOOK_BACK)

    # 1-2. New CVEs per distinct product
    products: dict[tuple[str, str, str], datetime] = {}
    for w in watchlists:
        for item in w.items:
            key = (item.part, item.vendor, item.product)
            products[key] = min(products.get(key, now), window_start(w))
    summary.products = len(products)
    found: dict[tuple[str, str, str], list[dict]] = {}
    for (part, vendor, product), since in products.items():
        try:
            found[(part, vendor, product)] = await feeds.new_cves(part, vendor, product, since, now, client, settings.nvd_api_key)
        except Exception as exc:  # one product failing mustn't stop the rest
            summary.errors.append(f"NVD lookup for {vendor} {product} failed: {type(exc).__name__}")
            found[(part, vendor, product)] = []
        await asyncio.sleep(NVD_PAUSE_SECONDS)

    # 3. Newly exploited (KEV)
    earliest = min(products.values())
    try:
        exploited = await feeds.newly_exploited(earliest, client)
    except Exception as exc:
        summary.errors.append(f"CISA KEV download failed: {type(exc).__name__}")
        exploited = []

    # Which candidates belong to which watchlist, and why
    plans: dict[str, list[dict]] = {}
    for w in watchlists:
        since = window_start(w)
        mine: dict[str, dict] = {}
        for item in w.items:
            for c in found.get((item.part, item.vendor, item.product), []):
                mine.setdefault(c["cve"], {**c, "item": item.title, "reason": "new_cve"})
            for entry in exploited:
                if feeds.kev_matches(entry, item.vendor, item.product) and entry.get("dateAdded", "") >= since.date().isoformat():
                    cve = entry["cveID"].upper()
                    mine[cve] = {"cve": cve, "description": entry.get("shortDescription", ""), "published": None,
                                 "item": item.title, "reason": "newly_exploited", "match": "kev",
                                 "kev_added": entry.get("dateAdded")}
        plans[w.id] = list(mine.values())

    # 4. Score each distinct candidate once
    scored: dict[str, object] = {}
    for cve in {c["cve"] for plan in plans.values() for c in plan}:
        try:
            scored[cve] = await investigate(cve, settings, store, client, write_ai_report=False, save=False)
        except Exception as exc:
            summary.errors.append(f"Scoring {cve} failed: {type(exc).__name__}")
    summary.candidates = len(scored)

    # 5-7. Alerts, saved investigations, notifications
    saved: dict[str, str] = {}  # cve -> investigation id, shared by every watchlist alerting on it
    ai_budget = settings.watch_ai_reports_per_run
    for w in watchlists:
        new_alerts: list[Alert] = []
        for c in plans[w.id]:
            investigation = scored.get(c["cve"])
            if investigation is None:
                continue
            level = investigation.verdict.level
            cvss = _cvss(investigation) or _feed_cvss(c)
            why = _why(level, cvss, c["reason"], w.min_level)
            if not why:
                continue
            existing = await repo.find_alert(w.id, c["cve"])
            if existing:
                # Escalate an earlier alert that is now confirmed exploited (unless it was muted)
                if c["reason"] == "newly_exploited" and existing.reason == "new_cve" and existing.status not in MUTING:
                    existing.reason, existing.escalated, existing.kev_added = "newly_exploited", True, c.get("kev_added")
                    existing.level, existing.score, existing.why, existing.found_at = level, investigation.verdict.score, why, now
                    if existing.status == "resolved":
                        existing.status = "new"
                    await repo.update_alert(existing)
                    new_alerts.append(existing)
                continue
            if c["cve"] not in saved:
                try:
                    full = await investigate(
                        c["cve"], settings, store, client, write_ai_report=ai_budget > 0, research_allowed=False,
                        listed=False, ai_skipped_message="The daily watchlist check writes a limited number of AI "
                                                         "summaries per day. Run this investigation again to get one.")
                    ai_budget -= 1 if full.report and full.report.status == "ready" and not full.report.cached else 0
                    saved[c["cve"]] = full.id
                except Exception as exc:
                    summary.errors.append(f"Saving {c['cve']} failed: {type(exc).__name__}")
            alert = Alert(watchlist_id=w.id, indicator=c["cve"], reason=c["reason"], item_title=c["item"],
                          match=c["match"], level=level, score=investigation.verdict.score, why=why,
                          cvss=cvss[0] if cvss else None, cvss_severity=cvss[1] if cvss else None,
                          title=_first_line(c.get("description") or investigation.verdict.headline),
                          published=(c.get("published") or "")[:10] or None, kev_added=c.get("kev_added"),
                          investigation_id=saved.get(c["cve"]), found_at=now)
            if await repo.add_alert(alert):
                new_alerts.append(alert)
        summary.alerts += len(new_alerts)

        if new_alerts and w.channels:
            title, body = notify.message(w, sorted(new_alerts, key=lambda a: (a.reason != "newly_exploited", -(a.score or 0))), site_url(settings) or "")
            for channel in w.channels:
                try:
                    await notify.send(channel, title, body, client, settings)
                    channel.last_error, channel.last_sent_at = None, now
                    summary.notifications += 1
                except Exception as exc:
                    channel.last_error = str(exc)[:200] if isinstance(exc, notify.ChannelError) else type(exc).__name__
                    summary.errors.append(f"{w.name}: {channel.kind} notification failed")
            for alert in new_alerts:
                alert.notified = True
                await repo.update_alert(alert)

        w.last_checked_at = now
        w.last_check_summary = f"{len(new_alerts)} new alert{'s' if len(new_alerts) != 1 else ''}"
        await repo.update(w)

    log.info("watchlist check: %s", summary.text())
    return summary
