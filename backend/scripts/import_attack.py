"""Load MITRE ATT&CK into the ThreatLens knowledge graph.

Run from the backend folder:
    python -m scripts.import_attack                 # downloads the latest version from MITRE
    python -m scripts.import_attack --file path.json  # uses a file you already downloaded

Safe to run again: it updates everything to the latest version and removes entries MITRE
has retired. The whole import happens in one transaction, so a failure changes nothing.
Needs DATABASE_URL.
"""
import argparse
import asyncio
import json
import sys
import time

import httpx2

from app.config import get_settings
from app.knowledge.attack import DOWNLOAD_URL, SOURCE, parse_bundle
from app.knowledge.repository import KnowledgeRepository
from app.store import PostgresStore


def load_bundle(file: str | None) -> dict:
    if file:
        print(f"Reading {file}...")
        with open(file, encoding="utf-8") as handle:
            return json.load(handle)
    print("Downloading MITRE ATT&CK (about 50 MB)...")
    response = httpx2.get(DOWNLOAD_URL, timeout=180, follow_redirects=True)
    response.raise_for_status()
    return response.json()


async def main() -> None:
    parser = argparse.ArgumentParser(description="Import MITRE ATT&CK into ThreatLens")
    parser.add_argument("--file", help="a local enterprise-attack.json instead of downloading")
    args = parser.parse_args()

    settings = get_settings()
    if not settings.database_url:
        print("DATABASE_URL is not set in backend/.env.")
        sys.exit(1)

    bundle = load_bundle(args.file)
    version, entities, relationships, redirects = parse_bundle(bundle)
    print(f"Parsed ATT&CK {version}: {len(entities)} entries, {len(relationships)} relationships, "
          f"{len(redirects)} retired IDs.")

    store = PostgresStore(settings.database_url)
    await store.init()  # also creates the knowledge tables if they don't exist yet
    started = time.perf_counter()
    print("Writing to the database (this can take a minute over the internet)...")
    result = await asyncio.to_thread(KnowledgeRepository(store).import_source,
                                     SOURCE, version, entities, relationships, redirects)
    print(f"Done in {time.perf_counter() - started:.0f} seconds. "
          f"Removed {result['removed_entities']} entries MITRE no longer lists.")

    stats = await KnowledgeRepository(store).stats(SOURCE)
    print(f"\nATT&CK {stats.version} is loaded:")
    for kind, count in sorted(stats.entities.items()):
        print(f"  {kind:<11} {count}")
    print(f"  {'links':<11} {stats.relationships}")
    await store.close()


if __name__ == "__main__":
    asyncio.run(main())
