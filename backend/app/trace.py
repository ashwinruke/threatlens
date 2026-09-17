"""Records every step of an investigation.

This is the raw material for ThreatLens's "why did it decide that?" view.
Each step saves what happened, why, and how long it took.
"""
import time
from contextlib import contextmanager
from typing import Any

from app.models import TraceStep


class Trace:
    def __init__(self) -> None:
        self.steps: list[TraceStep] = []

    def add(self, kind: str, title: str, reason: str | None = None,
            detail: dict[str, Any] | None = None, status: str = "ok",
            duration_ms: int | None = None) -> TraceStep:
        step = TraceStep(step=len(self.steps) + 1, kind=kind, title=title, reason=reason,
                         detail=detail or {}, status=status, duration_ms=duration_ms)
        self.steps.append(step)
        return step

    @contextmanager
    def timed(self, kind: str, title: str, reason: str | None = None):
        """Use as: with trace.timed("score", "Calculated risk") as step: ..."""
        started = time.perf_counter()
        step = self.add(kind, title, reason)
        try:
            yield step
        except Exception:
            step.status = "error"
            raise
        finally:
            step.duration_ms = round((time.perf_counter() - started) * 1000)
