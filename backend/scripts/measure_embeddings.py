"""Should ThreatLens add search-by-meaning? Measure before deciding.

This compares three ways of searching the ATT&CK knowledge base, on the same test
queries used by scripts/eval_search.py:
  - text:      the current search (names, aliases, spelling, description words)
  - meaning:   a small embedding model that compares meanings instead of words
  - combined:  both rankings merged (reciprocal rank fusion)

It also measures what the model costs: memory, load time, and time per query.
Render's free plan has 512 MB of memory for the whole server, so memory decides
whether this can run there at all.

One-time setup (these packages are NOT added to requirements.txt unless we decide to):
    pip install fastembed psutil

Run from the backend folder (needs ATT&CK imported):
    python -m scripts.measure_embeddings
    python -m scripts.measure_embeddings --model sentence-transformers/all-MiniLM-L6-v2
"""
import argparse
import asyncio
import gc
import time
from collections import defaultdict

from app.config import get_settings
from app.knowledge.search import search as text_search
from app.store import PostgresStore
from tests.search_cases import CASES

RRF_K = 60  # standard constant for reciprocal rank fusion
TOP = 25


def entity_text(row: dict) -> str:
    """What the model reads for each entry: name, aliases, kind, and the start of the description."""
    aliases = f" Also known as: {', '.join(row['aliases'])}." if row["aliases"] else ""
    return f"{row['name']} ({row['kind']}).{aliases} {row['description'][:600]}"


def rrf(*rankings: list[str]) -> list[str]:
    """Merge rankings: an entry near the top of either list rises to the top."""
    scores: dict[str, float] = defaultdict(float)
    for ranking in rankings:
        for position, item in enumerate(ranking):
            scores[item] += 1 / (RRF_K + position + 1)
    return sorted(scores, key=lambda item: -scores[item])


def load_model(name: str):
    from fastembed import TextEmbedding  # imported here so a missing package gives a clear message
    return TextEmbedding(model_name=name)


def memory_mb() -> float:
    import psutil
    return psutil.Process().memory_info().rss / 1024 / 1024


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default="BAAI/bge-small-en-v1.5")
    args = parser.parse_args()

    try:
        import fastembed  # noqa: F401
        import numpy as np
        import psutil  # noqa: F401
    except ImportError:
        print("First run:  pip install fastembed psutil")
        return

    store = PostgresStore(get_settings().database_url)
    await store.init()
    with store.connection() as conn:
        rows = conn.execute("SELECT external_id, name, kind, aliases, description FROM entities "
                            "WHERE external_id IS NOT NULL ORDER BY external_id").fetchall()
    ids = [r["external_id"] for r in rows]
    print(f"{len(rows)} ATT&CK entries loaded from the database.\n")

    gc.collect()
    before = memory_mb()
    started = time.perf_counter()
    model = load_model(args.model)
    load_seconds = time.perf_counter() - started
    after_load = memory_mb()

    started = time.perf_counter()
    vectors = np.array(list(model.embed([entity_text(r) for r in rows])))
    vectors /= np.linalg.norm(vectors, axis=1, keepdims=True)
    embed_all_seconds = time.perf_counter() - started
    peak = memory_mb()

    embed_query = getattr(model, "query_embed", model.embed)
    query_times = []
    totals = {name: defaultdict(lambda: [0, 0, 0]) for name in ("text", "meaning", "combined")}
    misses = []
    for query, expected, category in CASES:
        accepted = expected if isinstance(expected, tuple) else (expected,)
        started = time.perf_counter()
        q = np.array(list(embed_query([query]))[0])
        query_times.append(time.perf_counter() - started)
        q /= np.linalg.norm(q)
        meaning = [ids[i] for i in np.argsort(-(vectors @ q))[:TOP]]
        text_results = await text_search(store, query, limit=TOP)
        text = [r.external_id for r in text_results]
        # An exact ID, name, or alias match (score 190+) is certain: keep it first
        if text_results and text_results[0].score >= 190:
            combined = text[:1] + [i for i in rrf(text, meaning) if i != text[0]]
        else:
            combined = rrf(text, meaning)
        for name, ranking in (("text", text), ("meaning", meaning), ("combined", combined)):
            t = totals[name][category]
            t[0] += 1
            t[1] += bool(ranking) and ranking[0] in accepted
            t[2] += any(i in accepted for i in ranking[:3])
        if combined[:1] and combined[0] not in accepted:
            misses.append((query, "/".join(accepted), combined[0]))

    print(f"Model: {args.model}")
    print(f"  Memory before loading:        {before:6.0f} MB")
    print(f"  After loading the model:      {after_load:6.0f} MB  (+{after_load - before:.0f} MB)")
    print(f"  After embedding all entries:  {peak:6.0f} MB  (+{peak - before:.0f} MB total)")
    print(f"  Load time:                    {load_seconds:6.1f} s")
    print(f"  Embedding all {len(rows)} entries:  {embed_all_seconds:6.1f} s")
    print(f"  Per query:                    {1000 * sum(query_times) / len(query_times):6.0f} ms\n")

    print("Right answer first / in the top 3:")
    print(f"  {'category':<10}" + "".join(f"{name:>14}" for name in totals))
    for category in ("exact", "typo", "topic", "meaning"):
        cells = []
        for name in totals:
            n, h1, h3 = totals[name][category]
            cells.append(f"{h1:>2}/{n} {h3:>2}/{n}")
        print(f"  {category:<10}" + "".join(f"{c:>14}" for c in cells))

    if misses:
        print("\nCombined search still misses:")
        for query, expected, got in misses:
            print(f"  {query!r}: expected {expected}, got {got}")

    extra = peak - before
    print("\nWhat this means for Render's free plan (512 MB for the whole server):")
    print(f"  The model adds about {extra:.0f} MB. Check your ThreatLens service's current memory in")
    print("  Render's Metrics tab: if current usage plus this stays well under 512 MB, it can fit.")
    await store.close()


if __name__ == "__main__":
    asyncio.run(main())
