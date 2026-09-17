"""Run a real investigation from the terminal and print it in a readable way.

Run from the backend folder:
    python -m scripts.try_investigation CVE-2021-44228
    python -m scripts.try_investigation 8.8.8.8

Uses your real API keys from .env. Doesn't need the database (uses memory),
so it also doesn't fill your database with test runs.
"""
import asyncio
import sys

import httpx2

from app.config import get_settings
from app.detection import DetectionError
from app.investigate import investigate
from app.store import MemoryStore

LEVEL_MARK = {"CRITICAL": "!!!", "HIGH": "!! ", "MEDIUM": "!  ", "LOW": "   ", "UNKNOWN": "?  "}


async def main(query: str) -> None:
    settings = get_settings()
    async with httpx2.AsyncClient(headers={"User-Agent": "ThreatLens/dev"}, follow_redirects=True) as client:
        try:
            result = await investigate(query, settings, MemoryStore(), client)
        except DetectionError as exc:
            print(f"Input problem: {exc}")
            return

    v = result.verdict
    print(f"\n{LEVEL_MARK.get(v.level, '')} {v.level}  score {v.score}/100  ({v.confidence} confidence)")
    print(f"    {v.headline}\n")

    print("SCORE BREAKDOWN")
    for s in result.signals:
        print(f"  {s.points:+4d}  {s.label}  [{s.source}]")
        print(f"        {s.evidence}")
    for rule in v.rules_applied:
        print(f"  rule: {rule}")

    print("\nSOURCES")
    for src in result.sources:
        extra = " (cached)" if src.cached else f" ({src.duration_ms} ms)" if src.duration_ms is not None else ""
        print(f"  {src.status.value:<13} {src.source}{extra}")
        if src.message and src.status.value != "ok":
            print(f"                {src.message}")

    print("\nTRACE")
    for step in result.trace:
        print(f"  {step.step:>2}. [{step.kind}] {step.title}")
    print(f"\nFinished in {result.duration_ms} ms.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print('Usage: python -m scripts.try_investigation "<CVE, IP, domain, or hash>"')
        sys.exit(1)
    asyncio.run(main(" ".join(sys.argv[1:])))
