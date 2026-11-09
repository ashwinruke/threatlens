"""Watchlists, the products on them, notification channels, and alerts."""
import uuid
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field

LEVEL_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
MinLevel = Literal["CRITICAL", "HIGH", "MEDIUM"]
ChannelKind = Literal["discord", "slack", "teams", "ntfy", "email"]
AlertStatus = Literal["new", "confirmed", "false_alarm", "not_affected", "resolved"]
# Verdicts that mean "stop telling me about this": the alert stays, so it never fires again
MUTING = {"false_alarm", "not_affected"}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _id() -> str:
    return uuid.uuid4().hex[:12]


class WatchItem(BaseModel):
    """A product to watch, as NVD names it (from its CPE dictionary: vendor and product)."""
    id: str = Field(default_factory=_id)
    part: Literal["a", "o", "h"] = "a"  # application, operating system or hardware
    vendor: str
    product: str
    title: str  # what people call it, e.g. "nginx" or "Apache Log4j"
    added_at: datetime = Field(default_factory=_now)


class Channel(BaseModel):
    id: str = Field(default_factory=_id)
    kind: ChannelKind
    target: str  # a webhook URL, an ntfy topic URL, or an email address: a secret, never shown in full
    label: str = ""
    last_error: str | None = None
    last_sent_at: datetime | None = None


class Watchlist(BaseModel):
    id: str = ""
    name: str
    min_level: MinLevel = "HIGH"
    items: list[WatchItem] = Field(default_factory=list)
    channels: list[Channel] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=_now)
    last_checked_at: datetime | None = None
    last_manual_check_at: datetime | None = None
    last_check_summary: str | None = None


class Alert(BaseModel):
    id: str = ""
    watchlist_id: str = ""
    indicator: str  # a CVE ID, or whatever indicator an analyst saved from a report
    reason: Literal["new_cve", "newly_exploited", "saved"]
    item_title: str | None = None  # the watched product it matched
    match: Literal["product", "name", "kev", "manual"] = "product"  # how sure the product match is
    level: str
    score: int | None = None
    cvss: float | None = None
    cvss_severity: str | None = None
    why: str = ""  # what crossed the threshold, in words
    escalated: bool = False  # alerted before, then confirmed exploited
    title: str = ""  # one line: what the vulnerability is
    published: str | None = None
    kev_added: str | None = None
    investigation_id: str | None = None
    found_at: datetime = Field(default_factory=_now)
    status: AlertStatus = "new"
    note: str = ""
    decided_at: datetime | None = None
    notified: bool = False


def masked(channel: Channel) -> dict:
    """A channel as the website may show it: enough to recognise, not enough to reuse."""
    target = channel.target
    if channel.kind == "email":
        name, _, domain = target.partition("@")
        shown = f"{name[:2]}…@{domain}"
    else:
        shown = target.split("//", 1)[-1].split("/", 1)[0] + "/…" + target[-4:]
    return {"id": channel.id, "kind": channel.kind, "label": channel.label, "target": shown,
            "last_error": channel.last_error, "last_sent_at": channel.last_sent_at}


def public_view(watchlist: Watchlist) -> dict:
    data = watchlist.model_dump(mode="json")
    data["channels"] = [masked(c) for c in watchlist.channels]
    return data
