"""Records every step of an investigation.

This is the raw material for ThreatLens's "why did it decide that?" view.
Each step saves what happened, why, and how long it took.

A listener can be attached to hear about each step the moment it's finished; that's
how the live view streams steps to the browser while the investigation is still running.
"""
import logging
import time
from contextlib import contextmanager
from typing import Any, Callable

from app.models import TraceStep

logger = logging.getLogger("threatlens")


class Trace:
    def __init__(self, listener: Callable[[TraceStep], None] | None = None) -> None:
        self.steps: list[TraceStep] = []
        self.listener = listener

    def _announce(self, step: TraceStep) -> None:
        if self.listener:
            try:
                self.listener(step)
            except Exception:  # a broken listener (e.g. a closed browser tab) never breaks an investigation
                logger.warning("Trace listener failed", exc_info=True)

    def add(self, kind: str, title: str, reason: str | None = None,
            detail: dict[str, Any] | None = None, status: str = "ok",
            duration_ms: int | None = None, announce: bool = True) -> TraceStep:
        step = TraceStep(step=len(self.steps) + 1, kind=kind, title=title, reason=reason,
                         detail=detail or {}, status=status, duration_ms=duration_ms)
        self.steps.append(step)
        if announce:
            self._announce(step)
        return step

    @contextmanager
    def timed(self, kind: str, title: str, reason: str | None = None):
        """Use as: with trace.timed("score", "Calculated risk") as step: ...

        The step is announced when it finishes, with its final title, reason, and duration.
        """
        started = time.perf_counter()
        step = self.add(kind, title, reason, announce=False)
        try:
            yield step
        except Exception:
            step.status = "error"
            raise
        finally:
            step.duration_ms = round((time.perf_counter() - started) * 1000)
            self._announce(step)
