"""Usage limits, so a public demo can't drain the free tiers.

Two kinds of limit:
- Per visitor: a few investigations per hour from one address, so nobody can
  hold the queue or burn the API quotas of every source.
- Per day, for everyone: a ceiling on investigations and AI reports.

The per-visitor counters live in memory. The daily ones are counted in the
database, so they survive a server restart (Render restarts a free service often).
"""
import time
from collections import defaultdict, deque
from dataclasses import dataclass

from fastapi import Request


@dataclass
class Decision:
    allowed: bool
    retry_after_seconds: int = 0
    message: str = ""


class VisitorLimiter:
    """Counts recent requests per visitor, per action."""

    def __init__(self) -> None:
        self._seen: dict[tuple[str, str], deque[float]] = defaultdict(deque)

    def check(self, action: str, visitor: str, allowed: int, window_seconds: int) -> Decision:
        now = time.monotonic()
        history = self._seen[(action, visitor)]
        while history and now - history[0] > window_seconds:
            history.popleft()
        if len(history) >= allowed:
            wait = int(window_seconds - (now - history[0])) + 1
            minutes = max(1, round(wait / 60))
            return Decision(
                allowed=False,
                retry_after_seconds=wait,
                message=(f"You've used the {allowed} investigations allowed per hour on this public demo. "
                         f"Try again in about {minutes} minute{'s' if minutes != 1 else ''}, "
                         "or open one of the example investigations below."),
            )
        history.append(now)
        return Decision(allowed=True)

    def reset(self) -> None:
        self._seen.clear()


def visitor_key(request: Request) -> str:
    """Identify the visitor by IP address.

    Render sits behind a proxy, so the real address is the first entry of
    X-Forwarded-For. A determined person can fake this header; that's fine here,
    because these limits protect free quotas, not secrets.
    """
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"
