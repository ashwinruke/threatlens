"""Sending alerts: Discord, Slack, Microsoft Teams, ntfy (phone push) and email.

All free, no sign-up for ThreatLens. Visitors paste a webhook URL (or an ntfy topic), and the
server posts to it (never following redirects). A server that posts to any URL a visitor gives it can be abused to reach
places it shouldn't (internal addresses, other people's services), so only the known webhook
hosts below are accepted, over HTTPS.

Email goes through Resend's free plan and needs RESEND_API_KEY on the server. Without a verified
sending domain, Resend only delivers to the email address the Resend account was made with.
"""
import re
from urllib.parse import urlparse

import httpx2

from app.watch.models import Alert, Channel, Watchlist

HOSTS = {
    "discord": (r"(?:discord|discordapp)\.com", r"/api/webhooks/\d+/[\w-]+"),
    "slack": (r"hooks\.slack\.com", r"/services/[\w/]+"),
    "teams": (r"[\w.-]+\.(?:webhook\.office\.com|logic\.azure\.com|powerplatform\.com|powerautomate\.com)", r"/.+"),
    "ntfy": (r"ntfy\.sh", r"/[\w-]{6,64}"),
}
EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[a-z]{2,}$", re.IGNORECASE)
RESEND_URL = "https://api.resend.com/emails"
LEVEL_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
REASON = {"new_cve": "New CVE", "newly_exploited": "Now exploited in the wild (CISA KEV)", "saved": "Saved by an analyst"}


class ChannelError(ValueError):
    pass


def validate(kind: str, target: str) -> str:
    """Returns the cleaned target, or raises ChannelError with a message a person can act on."""
    target = target.strip()
    if kind == "email":
        if not EMAIL.match(target):
            raise ChannelError("That doesn't look like an email address.")
        return target
    url = urlparse(target)
    host_pattern, path_pattern = HOSTS[kind]
    if url.scheme != "https" or not re.fullmatch(host_pattern, url.hostname or "", re.IGNORECASE) \
            or not re.fullmatch(path_pattern, url.path or "") or url.username or url.port not in (None, 443):
        examples = {"discord": "https://discord.com/api/webhooks/…", "slack": "https://hooks.slack.com/services/…",
                    "teams": "a Teams workflow URL (…webhook.office.com/… or …logic.azure.com/…)",
                    "ntfy": "https://ntfy.sh/your-secret-topic"}
        raise ChannelError(f"That isn't a {kind.title()} address ThreatLens accepts. It should look like {examples[kind]}.")
    return target


def _line(alert: Alert, site_url: str) -> str:
    score = f" {alert.score}" if alert.score is not None else ""
    product = f" · {alert.item_title}" if alert.item_title else ""
    link = f"{site_url}/i/{alert.investigation_id}" if site_url and alert.investigation_id else ""
    title = (alert.title[:150] + "…") if len(alert.title) > 150 else alert.title
    reason = "Now exploited in the wild (CISA KEV), after an earlier alert" if alert.escalated else REASON[alert.reason]
    cvss = f" · CVSS {alert.cvss:g}" if alert.cvss is not None else ""
    return (f"{LEVEL_EMOJI.get(alert.level, '•')} {alert.indicator} — {alert.level.title()}{score}{cvss}{product}\n"
            f"   {reason}. {title}" + (f"\n   {link}" if link else ""))


def message(watchlist: Watchlist, alerts: list[Alert], site_url: str) -> tuple[str, str]:
    """(title, body) in plain text that reads well in every channel."""
    count = len(alerts)
    title = f"ThreatLens: {count} new alert{'s' if count != 1 else ''} for {watchlist.name}"
    lines = [_line(a, site_url) for a in alerts[:10]]
    if count > 10:
        lines.append(f"…and {count - 10} more.")
    if site_url:
        lines.append(f"\nOpen the watchlist to triage: {site_url}/watchlists/{watchlist.id}")
    return title, "\n".join(lines)


async def send(channel: Channel, title: str, body: str, client: httpx2.AsyncClient, settings) -> None:
    """Raises on failure; the caller records the error on the channel."""
    kind = channel.kind
    if kind == "discord":
        payload = {"content": f"**{title}**\n{body}"[:1990], "allowed_mentions": {"parse": []}}
        response = await client.post(channel.target, json=payload, timeout=15, follow_redirects=False)
    elif kind == "slack":
        response = await client.post(channel.target, json={"text": f"*{title}*\n{body}"}, timeout=15, follow_redirects=False)
    elif kind == "teams":
        card = {"type": "AdaptiveCard", "version": "1.4", "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "body": [{"type": "TextBlock", "text": title, "weight": "Bolder", "wrap": True}]
                + [{"type": "TextBlock", "text": part, "wrap": True} for part in body.split("\n") if part.strip()]}
        payload = {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}]}
        response = await client.post(channel.target, json=payload, timeout=15, follow_redirects=False)
    elif kind == "ntfy":
        headers = {"Title": title.encode("ascii", "ignore").decode(), "Priority": "high", "Tags": "warning"}
        response = await client.post(channel.target, content=body.encode(), headers=headers, timeout=15, follow_redirects=False)
    elif kind == "email":
        if not settings.resend_api_key:
            raise ChannelError("Email isn't set up on this server (it needs RESEND_API_KEY).")
        response = await client.post(RESEND_URL, headers={"Authorization": f"Bearer {settings.resend_api_key}"}, timeout=15,
                                     json={"from": settings.alert_email_from, "to": [channel.target],
                                           "subject": title, "text": body}, follow_redirects=False)
    else:
        raise ChannelError(f"Unknown channel {kind}")
    if response.status_code >= 300:
        raise ChannelError(f"{kind.title()} answered HTTP {response.status_code}")
