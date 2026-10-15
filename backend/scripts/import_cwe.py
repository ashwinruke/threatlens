"""Load MITRE's CWE catalog (Common Weakness Enumeration) into the ThreatLens knowledge graph.

Run from the backend folder:
    python -m scripts.import_cwe                       # downloads the latest catalog from MITRE
    python -m scripts.import_cwe --file cwec_latest.xml.zip   # or a file you downloaded (zip or xml)

Safe to run again: it updates everything to the latest version and removes weaknesses MITRE
has deprecated. The whole import happens in one transaction, so a failure changes nothing.
Needs DATABASE_URL. Independent of the ATT&CK import: either can run first.
"""
import argparse
import asyncio
import sys
import time

import httpx2

from app.config import get_settings
from app.knowledge.cwe import DOWNLOAD_URL, SOURCE, parse_catalog, read_file
from app.knowledge.repository import KnowledgeRepository
from app.store import PostgresStore


def load(file: str | None) -> bytes:
    if file:
        print(f"Reading {file}...")
        with open(file, "rb") as handle:
            return read_file(handle.read())
    print("Downloading the CWE catalog from MITRE (about 2 MB)...")
    response = httpx2.get(DOWNLOAD_URL, timeout=120, follow_redirects=True,
                          headers={"User-Agent": "ThreatLens/cwe-import"})
    response.raise_for_status()
    return read_file(response.content)


async def main() -> None:
    parser = argparse.ArgumentParser(description="Import MITRE CWE into ThreatLens")
    parser.add_argument("--file", help="a local cwec_latest.xml.zip or .xml instead of downloading")
    args = parser.parse_args()

    settings = get_settings()
    if not settings.database_url:
        print("DATABASE_URL is not set in backend/.env.")
        sys.exit(1)

    version, entities, relationships = parse_catalog(load(args.file))
    print(f"Parsed CWE {version}: {len(entities)} weaknesses, {len(relationships)} links between them.")

    # A quick sanity check against well-known entries, so a format change is noticed immediately
    by_id = {e.external_id: e for e in entities}
    for known in ("CWE-79", "CWE-89", "CWE-502"):
        entry = by_id.get(known)
        print(f"  {known}: {entry.name if entry else 'MISSING (check the file format)'}")

    store = PostgresStore(settings.database_url)
    await store.init()
    started = time.perf_counter()
    print("Writing to the database...")
    result = await asyncio.to_thread(KnowledgeRepository(store).import_source,
                                     SOURCE, version, entities, relationships, [])
    print(f"Done in {time.perf_counter() - started:.0f} seconds. "
          f"Removed {result['removed_entities']} weaknesses MITRE no longer lists.")
    stats = await KnowledgeRepository(store).stats(SOURCE)
    print(f"\nCWE {stats.version} is loaded: {stats.entities.get('weakness', 0)} weaknesses, "
          f"{stats.relationships} links.")
    await store.close()


if __name__ == "__main__":
    asyncio.run(main())
