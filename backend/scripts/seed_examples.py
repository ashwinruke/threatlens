"""Fill the home page's example investigations.

Run from the backend folder:   python -m scripts.seed_examples

It runs a few investigations and pins them, so a first-time visitor sees real
results instantly instead of waiting for a sleeping server.

Two examples are fixed (Log4Shell, Google's public DNS). Two are picked live from
abuse.ch, so they're always real, current threats:
  - a malware sample hash from MalwareBazaar
  - a botnet address from ThreatFox
Hashes stay malicious forever, so that example never goes stale. Re-run this script
whenever you want to refresh the live ones (about once a month is plenty).

Needs DATABASE_URL, because examples are stored in the database.
"""
import asyncio
import sys

import httpx2

from app.config import get_settings
from app.investigate import investigate
from app.store import PostgresStore

FIXED = [
    ("log4shell", "Log4Shell", "The 2021 flaw that hit almost every Java application. Still exploited today.",
     "CVE-2021-44228"),
    ("medium-cve", "A medium-risk CVE", "Serious on paper, but not exploited in the wild. Shows how the score separates the two.",
     "CVE-2024-48990"),
    ("known-good", "Google's public DNS", "A harmless address analysts see constantly. Shows how false alarms are avoided.",
     "8.8.8.8"),
]

PAUSE_SECONDS = 20  # VirusTotal's free tier allows only a few requests per minute


async def recent_malware_hash(client: httpx2.AsyncClient, auth_key: str) -> str | None:
    response = await client.post("https://mb-api.abuse.ch/api/v1/",
                                 data={"query": "get_recent", "selector": "100"},
                                 headers={"Auth-Key": auth_key})
    response.raise_for_status()
    body = response.json()
    for sample in body.get("data") or []:
        if sample.get("sha256_hash"):
            return sample["sha256_hash"]
    return None


async def recent_botnet_ip(client: httpx2.AsyncClient, auth_key: str) -> str | None:
    response = await client.post("https://threatfox-api.abuse.ch/api/v1/",
                                 json={"query": "get_iocs", "days": 2},
                                 headers={"Auth-Key": auth_key})
    response.raise_for_status()
    body = response.json()
    for row in body.get("data") or []:
        if row.get("ioc_type") == "ip:port" and row.get("ioc"):
            return str(row["ioc"]).rsplit(":", 1)[0]
    return None


async def main() -> None:
    settings = get_settings()
    if not settings.database_url:
        print("DATABASE_URL is not set. Examples are stored in the database, so set it first.")
        sys.exit(1)

    store = PostgresStore(settings.database_url)
    await store.init()

    async with httpx2.AsyncClient(timeout=httpx2.Timeout(settings.source_timeout_seconds),
                                  headers={"User-Agent": "ThreatLens/seed"}, follow_redirects=True) as client:
        jobs = list(FIXED)
        if settings.abusech_auth_key:
            try:
                sample = await recent_malware_hash(client, settings.abusech_auth_key)
                if sample:
                    jobs.append(("malware-hash", "A live malware sample",
                                 "A hash taken from MalwareBazaar. Real malware, confirmed by its sample database.", sample))
            except Exception as exc:
                print(f"Couldn't fetch a malware hash ({type(exc).__name__}); skipping that example.")
            try:
                ip = await recent_botnet_ip(client, settings.abusech_auth_key)
                if ip:
                    jobs.append(("botnet-ip", "A live botnet address",
                                 "An address reported to ThreatFox in the last two days.", ip))
            except Exception as exc:
                print(f"Couldn't fetch a botnet address ({type(exc).__name__}); skipping that example.")
        else:
            print("ABUSECH_AUTH_KEY is not set, so only the fixed examples will be pinned.")

        for position, (slot, label, note, query) in enumerate(jobs):
            print(f"\nInvestigating {query} ({label})...")
            result = await investigate(query, settings, store, client)
            print(f"  {result.verdict.level} {result.verdict.score}/100  "
                  f"AI summary: {result.report.status if result.report else 'none'}  ({result.duration_ms} ms)")
            await store.pin_example(slot, label, note, position, result.id)
            if position < len(jobs) - 1:
                await asyncio.sleep(PAUSE_SECONDS)

    pinned = await store.examples()
    print("\nPinned examples now on the home page:")
    for example in pinned:
        print(f"  {example.level:<8} {example.indicator_value:<66} {example.label}")
    await store.close()


if __name__ == "__main__":
    asyncio.run(main())
