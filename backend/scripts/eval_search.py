"""Measure how well knowledge search finds the right entry.

Run from the backend folder (needs ATT&CK imported):   python -m scripts.eval_search

For each test query it checks whether the expected entry is the top result (hit@1)
or in the top three (hit@3), and prints the score per category.
"""
import asyncio
from collections import defaultdict

from app.config import get_settings
from app.knowledge.search import search
from app.store import PostgresStore
from tests.search_cases import CASES


async def main() -> None:
    store = PostgresStore(get_settings().database_url)
    await store.init()
    totals: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0])
    print(f"{'query':<44} {'expected':<12} {'got':<10} result")
    for query, expected, category in CASES:
        results = await search(store, query, limit=3)
        ids = [r.external_id for r in results]
        top = results[0] if results else None
        accepted = expected if isinstance(expected, tuple) else (expected,)
        hit1 = bool(ids) and ids[0] in accepted
        hit3 = any(i in accepted for i in ids)
        expected = "/".join(accepted)
        totals[category][0] += 1
        totals[category][1] += hit1
        totals[category][2] += hit3
        mark = "top" if hit1 else "top 3" if hit3 else "MISS"
        got = f"{top.external_id}" if top else "-"
        print(f"{query:<44} {expected:<12} {got:<10} {mark:<6} {top.matched_on if top else ''}")
    print(f"\n{'category':<10} {'hit@1':>8} {'hit@3':>8}")
    for category, (n, h1, h3) in totals.items():
        print(f"{category:<10} {h1:>4}/{n:<3} {h3:>4}/{n:<3}")
    await store.close()


if __name__ == "__main__":
    asyncio.run(main())
