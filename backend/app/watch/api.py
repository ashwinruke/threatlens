"""Watchlist endpoints.

There are no accounts. Creating a watchlist returns a private key, shown once; every later
request for that watchlist sends it in the X-Watchlist-Key header. The website keeps it in the
browser and in the watchlist's private link (after the #, so it never reaches a server log).
"""
import hmac
import re
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Header, HTTPException, Query, Request
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from app.watch import checker, feeds, notify
from app.watch.models import Alert, AlertStatus, Channel, ChannelKind, MinLevel, WatchItem, Watchlist, public_view
from app.watch.repository import hash_key, key_matches, repository_for

router = APIRouter(tags=["watchlists"])
CPE_PART = re.compile(r"^[A-Za-z0-9._~!\\-]{1,100}$")
PRODUCT_CACHE = timedelta(days=7)


def _main():
    from app import main  # settings and the rate limiter live there (tests replace them)
    return main


class ItemIn(BaseModel):
    part: Literal["a", "o", "h"] = "a"
    vendor: str = Field(max_length=100)
    product: str = Field(max_length=100)
    title: str = Field(max_length=120)

    @field_validator("vendor", "product")
    @classmethod
    def cpe_name(cls, value: str) -> str:
        if not CPE_PART.match(value):
            raise ValueError("Pick the product from the search results")
        return value.lower()


class ChannelIn(BaseModel):
    kind: ChannelKind
    target: str = Field(max_length=500)
    label: str = Field("", max_length=60)


class WatchlistIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    min_level: MinLevel = "HIGH"
    items: list[ItemIn] = Field(default_factory=list)
    channels: list[ChannelIn] = Field(default_factory=list)


class WatchlistPatch(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=80)
    min_level: MinLevel | None = None


class VerdictIn(BaseModel):
    status: AlertStatus
    note: str = Field("", max_length=1000)


class CaseIn(VerdictIn):
    investigation_id: str = Field(max_length=64)


async def _open(request: Request, watchlist_id: str, key: str | None) -> Watchlist:
    found = await repository_for(request.app.state.store).get(watchlist_id)
    # Same answer for "doesn't exist" and "wrong key", so neither can be probed
    if not found or not key_matches(key, found[0]):
        raise HTTPException(status_code=404, detail="Watchlist not found, or the private key doesn't match.")
    return found[1]


def _channel(data: ChannelIn) -> Channel:
    try:
        target = notify.validate(data.kind, data.target)
    except notify.ChannelError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return Channel(kind=data.kind, target=target, label=data.label.strip())


def _stats(alerts: list[Alert]) -> dict:
    counts = {s: sum(a.status == s for a in alerts) for s in ("new", "confirmed", "false_alarm", "not_affected", "resolved")}
    decided = counts["confirmed"] + counts["false_alarm"]
    return {**counts, "total": len(alerts),
            # Of the alerts an analyst judged, how many were real: the alerting's precision
            "precision_pct": round(100 * counts["confirmed"] / decided) if decided else None}


async def _view(request: Request, watchlist: Watchlist) -> dict:
    alerts = await repository_for(request.app.state.store).alerts_for(watchlist.id)
    settings = _main().settings
    return {"watchlist": public_view(watchlist), "alerts": [a.model_dump(mode="json") for a in alerts],
            "stats": _stats(alerts), "email_available": bool(settings.resend_api_key),
            "manual_check_minutes": settings.watch_manual_check_minutes}


@router.get("/api/products")
async def find_products(request: Request, q: str = Query(..., min_length=2, max_length=60)):
    """Products in NVD's dictionary matching a name, to add to a watchlist."""
    main = _main()
    decision = main.limiter.check("products", main.visitor_key(request), 30, 60)
    if not decision.allowed:
        raise HTTPException(status_code=429, detail="Too many product searches. Wait a minute.")
    store = request.app.state.store
    cache_key = "cpe-search:" + q.strip().lower()
    cached = await store.get_json(cache_key, PRODUCT_CACHE)
    if cached is not None:
        return cached["products"]
    try:
        products = await feeds.search_products(q.strip(), request.app.state.http, main.settings.nvd_api_key)
    except Exception:
        raise HTTPException(status_code=502, detail="NVD's product search didn't answer. Try again in a moment.")
    await store.put_json(cache_key, {"products": products})
    return products


@router.post("/api/watchlists", status_code=201)
async def create_watchlist(body: WatchlistIn, request: Request):
    main = _main()
    settings = main.settings
    decision = main.limiter.check("watchlist", main.visitor_key(request), settings.watchlists_per_day_per_visitor, 86400)
    if not decision.allowed:
        raise HTTPException(status_code=429, detail="That's enough new watchlists for today. Try again tomorrow.")
    if len(body.items) > settings.watch_max_items or len(body.channels) > settings.watch_max_channels:
        raise HTTPException(status_code=422, detail=f"A watchlist holds up to {settings.watch_max_items} products "
                                                    f"and {settings.watch_max_channels} alert channels.")
    items, seen = [], set()
    for i in body.items:
        if (i.part, i.vendor, i.product) not in seen:
            seen.add((i.part, i.vendor, i.product))
            items.append(WatchItem(part=i.part, vendor=i.vendor, product=i.product, title=i.title.strip()))
    watchlist = Watchlist(name=body.name.strip(), min_level=body.min_level, items=items,
                          channels=[_channel(c) for c in body.channels])
    key = secrets.token_urlsafe(24)
    watchlist = await repository_for(request.app.state.store).create(watchlist, hash_key(key))
    return {"id": watchlist.id, "key": key, **(await _view(request, watchlist))}


@router.get("/api/watchlists/{watchlist_id}")
async def get_watchlist(watchlist_id: str, request: Request, x_watchlist_key: str | None = Header(None)):
    return await _view(request, await _open(request, watchlist_id, x_watchlist_key))


@router.patch("/api/watchlists/{watchlist_id}")
async def update_watchlist(watchlist_id: str, body: WatchlistPatch, request: Request, x_watchlist_key: str | None = Header(None)):
    watchlist = await _open(request, watchlist_id, x_watchlist_key)
    if body.name is not None:
        watchlist.name = body.name.strip()
    if body.min_level is not None:
        watchlist.min_level = body.min_level
    await repository_for(request.app.state.store).update(watchlist)
    return await _view(request, watchlist)


@router.delete("/api/watchlists/{watchlist_id}", status_code=204)
async def delete_watchlist(watchlist_id: str, request: Request, x_watchlist_key: str | None = Header(None)):
    await _open(request, watchlist_id, x_watchlist_key)
    await repository_for(request.app.state.store).delete(watchlist_id)


@router.post("/api/watchlists/{watchlist_id}/items")
async def add_item(watchlist_id: str, body: ItemIn, request: Request, x_watchlist_key: str | None = Header(None)):
    watchlist = await _open(request, watchlist_id, x_watchlist_key)
    if any((i.part, i.vendor, i.product) == (body.part, body.vendor, body.product) for i in watchlist.items):
        return await _view(request, watchlist)
    if len(watchlist.items) >= _main().settings.watch_max_items:
        raise HTTPException(status_code=422, detail=f"A watchlist holds up to {_main().settings.watch_max_items} products.")
    watchlist.items.append(WatchItem(part=body.part, vendor=body.vendor, product=body.product, title=body.title.strip()))
    await repository_for(request.app.state.store).update(watchlist)
    return await _view(request, watchlist)


@router.delete("/api/watchlists/{watchlist_id}/items/{item_id}")
async def remove_item(watchlist_id: str, item_id: str, request: Request, x_watchlist_key: str | None = Header(None)):
    watchlist = await _open(request, watchlist_id, x_watchlist_key)
    watchlist.items = [i for i in watchlist.items if i.id != item_id]
    await repository_for(request.app.state.store).update(watchlist)
    return await _view(request, watchlist)


@router.post("/api/watchlists/{watchlist_id}/channels")
async def add_channel(watchlist_id: str, body: ChannelIn, request: Request, x_watchlist_key: str | None = Header(None)):
    watchlist = await _open(request, watchlist_id, x_watchlist_key)
    if len(watchlist.channels) >= _main().settings.watch_max_channels:
        raise HTTPException(status_code=422, detail=f"A watchlist holds up to {_main().settings.watch_max_channels} alert channels.")
    if body.kind == "email" and not _main().settings.resend_api_key:
        raise HTTPException(status_code=422, detail="Email alerts aren't set up on this server. Use Discord, Slack, Teams or ntfy.")
    watchlist.channels.append(_channel(body))
    await repository_for(request.app.state.store).update(watchlist)
    return await _view(request, watchlist)


@router.delete("/api/watchlists/{watchlist_id}/channels/{channel_id}")
async def remove_channel(watchlist_id: str, channel_id: str, request: Request, x_watchlist_key: str | None = Header(None)):
    watchlist = await _open(request, watchlist_id, x_watchlist_key)
    watchlist.channels = [c for c in watchlist.channels if c.id != channel_id]
    await repository_for(request.app.state.store).update(watchlist)
    return await _view(request, watchlist)


@router.post("/api/watchlists/{watchlist_id}/channels/{channel_id}/test")
async def test_channel(watchlist_id: str, channel_id: str, request: Request, x_watchlist_key: str | None = Header(None)):
    main = _main()
    watchlist = await _open(request, watchlist_id, x_watchlist_key)
    decision = main.limiter.check("channel-test", watchlist_id, 5, 600)
    if not decision.allowed:
        raise HTTPException(status_code=429, detail="That's enough test messages for now. Wait a few minutes.")
    channel = next((c for c in watchlist.channels if c.id == channel_id), None)
    if not channel:
        raise HTTPException(status_code=404, detail="That alert channel isn't on this watchlist.")
    try:
        await notify.send(channel, f"ThreatLens test for {watchlist.name}",
                          "This channel will receive new alerts for this watchlist.", request.app.state.http, main.settings)
        channel.last_error, channel.last_sent_at = None, datetime.now(timezone.utc)
    except Exception as exc:
        channel.last_error = str(exc)[:200] if isinstance(exc, notify.ChannelError) else f"Couldn't reach it ({type(exc).__name__})"
    await repository_for(request.app.state.store).update(watchlist)
    return await _view(request, watchlist)


@router.post("/api/watchlists/{watchlist_id}/check")
async def check_now(watchlist_id: str, request: Request, x_watchlist_key: str | None = Header(None)):
    """Run the daily check for this watchlist right away."""
    settings = _main().settings
    watchlist = await _open(request, watchlist_id, x_watchlist_key)
    if not watchlist.items:
        raise HTTPException(status_code=422, detail="Add a product first.")
    now = datetime.now(timezone.utc)
    wait = timedelta(minutes=settings.watch_manual_check_minutes)
    if watchlist.last_manual_check_at and now - watchlist.last_manual_check_at < wait:
        minutes = int((wait - (now - watchlist.last_manual_check_at)).total_seconds() // 60) + 1
        raise HTTPException(status_code=429, detail=f"Checked a moment ago. You can check again in {minutes} minute{'s' if minutes != 1 else ''}.")
    watchlist.last_manual_check_at = now
    await repository_for(request.app.state.store).update(watchlist)
    summary = await checker.run(request.app.state.store, settings, request.app.state.http, only=watchlist, now=now)
    view = await _view(request, (await repository_for(request.app.state.store).get(watchlist_id))[1])
    return {**view, "check": {"text": summary.text(), "alerts": summary.alerts, "errors": summary.errors}}


@router.post("/api/watchlists/{watchlist_id}/alerts/{alert_id}/verdict")
async def set_verdict(watchlist_id: str, alert_id: str, body: VerdictIn, request: Request, x_watchlist_key: str | None = Header(None)):
    await _open(request, watchlist_id, x_watchlist_key)
    repo = repository_for(request.app.state.store)
    alert = await repo.get_alert(watchlist_id, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="That alert isn't on this watchlist.")
    alert.status, alert.note = body.status, body.note.strip()
    alert.decided_at = None if body.status == "new" else datetime.now(timezone.utc)
    await repo.update_alert(alert)
    return alert.model_dump(mode="json")


@router.post("/api/watchlists/{watchlist_id}/cases")
async def save_case(watchlist_id: str, body: CaseIn, request: Request, x_watchlist_key: str | None = Header(None)):
    """An analyst's verdict on any report, saved to their watchlist."""
    await _open(request, watchlist_id, x_watchlist_key)
    store = request.app.state.store
    investigation = await store.get(body.investigation_id)
    if not investigation:
        raise HTTPException(status_code=404, detail="That report doesn't exist.")
    repo = repository_for(store)
    indicator = investigation.indicator.value
    alert = await repo.find_alert(watchlist_id, indicator)
    if alert is None:
        alert = await repo.add_alert(Alert(
            watchlist_id=watchlist_id, indicator=indicator, reason="saved", match="manual",
            level=investigation.verdict.level, score=investigation.verdict.score,
            title=investigation.verdict.headline, investigation_id=investigation.id, notified=True))
    alert.status, alert.note = body.status, body.note.strip()
    alert.investigation_id = investigation.id
    alert.decided_at = None if body.status == "new" else datetime.now(timezone.utc)
    await repo.update_alert(alert)
    return alert.model_dump(mode="json")


@router.post("/api/watch/run")
async def scheduled_run(request: Request, x_cron_token: str | None = Header(None)):
    """The daily check for every watchlist, started by the scheduled GitHub Actions job."""
    token = _main().settings.watch_cron_token
    if not token:
        raise HTTPException(status_code=404, detail="The scheduled check isn't switched on (WATCH_CRON_TOKEN).")
    if not x_cron_token or not hmac.compare_digest(x_cron_token, token):
        raise HTTPException(status_code=403, detail="Wrong token.")
    summary = await checker.run(request.app.state.store, _main().settings, request.app.state.http)
    return {"text": summary.text(), "watchlists": summary.watchlists, "products": summary.products,
            "candidates": summary.candidates, "alerts": summary.alerts, "notifications": summary.notifications,
            "errors": summary.errors}
