"""Freeze the evaluation cases: run the real pipeline on recorded source answers.

    python -m scripts.build_eval_cases                         # indicator cases only
    python -m scripts.build_eval_cases --database "$DATABASE_URL"  # also threat and weakness profiles

For every case in evals/recordings.py this runs detection, the source parsers and the scoring
formula exactly as production does, but the "internet" is a fake that answers with the recorded
responses. The evidence packet the AI would receive is saved to evals/cases.json, together with
what a correct report must and must not say. Run it again only when the recordings or the
evidence format change; the frozen file is what keeps results comparable over time.

--database needs ATT&CK and CWE imported. Your Neon database works: it is only read, and
nothing is saved to the history. --load-sample loads the small test sample into that database first; use it
only on a throwaway test database.
"""
import argparse
import asyncio
import copy
import ipaddress
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx2

from app import known_good
from app.ai.prompt import build_evidence
from app.config import Settings
from app.investigate import investigate
from app.sources import kev
from app.store import MemoryStore
from evals.recordings import CASES, PROFILE_CASES

OUT = Path(__file__).resolve().parent.parent / "evals" / "cases.json"

NO_RECORD = {
    "nvd": (200, {"totalResults": 0, "vulnerabilities": []}),
    "kev": (200, {"vulnerabilities": []}),
    "epss": (200, {"status": "OK", "data": []}),
    "abuseipdb": (200, {"data": {"abuseConfidenceScore": 0, "totalReports": 0, "numDistinctUsers": 0,
                                 "lastReportedAt": None, "isWhitelisted": False, "isTor": False}}),
    "virustotal": (404, {"error": {"code": "NotFoundError", "message": "not found"}}),
    "otx": (200, {"pulse_info": {"count": 0, "pulses": []}}),
    "threatfox": (200, {"query_status": "no_result", "data": "Your search did not yield any results"}),
    "urlhaus": (200, {"query_status": "no_results"}),
    "malwarebazaar": (200, {"query_status": "hash_not_found"}),
}
HOSTS = [("services.nvd.nist.gov", "nvd"), ("known_exploited_vulnerabilities", "kev"), ("api.first.org", "epss"),
         ("abuseipdb.com", "abuseipdb"), ("virustotal.com", "virustotal"), ("otx.alienvault.com", "otx"),
         ("threatfox-api.abuse.ch", "threatfox"), ("urlhaus-api.abuse.ch", "urlhaus"), ("mb-api.abuse.ch", "malwarebazaar")]


def recorded_internet(responses: dict, now: datetime) -> httpx2.AsyncClient:
    """A fake network that answers each source with its recording (or "no record")."""
    recent = (now - timedelta(days=2)).isoformat()

    def handler(request: httpx2.Request) -> httpx2.Response:
        url = str(request.url)
        for host, key in HOSTS:
            if host in url:
                status, body = (200, responses[key]) if key in responses else NO_RECORD[key]
                text = json.dumps(body).replace("RECENT", recent)
                return httpx2.Response(status, content=text, headers={"content-type": "application/json"})
        return httpx2.Response(404)

    return httpx2.AsyncClient(transport=httpx2.MockTransport(handler))


def offline_settings(database_url: str = "") -> Settings:
    return Settings(_env_file=None, nvd_api_key="k", abuseipdb_api_key="k", otx_api_key="k", virustotal_api_key="k",
                    abusech_auth_key="k", database_url=database_url, research_enabled=False, source_timeout_seconds=5)


def freeze(case: dict, investigation) -> dict:
    packet, citations = build_evidence(investigation)
    verdict = investigation.verdict
    return {
        "id": case["id"], "title": case["title"], "category": case["category"], "query": case["query"],
        "verdict": {"level": verdict.level, "score": verdict.score},
        "packet": packet, "citations": [c.model_dump() for c in citations], "expect": case["expect"],
    }


_real_check_ip = known_good.check_ip
_DOCUMENTATION_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def _check_ip_treating_documentation_as_public(value: str):
    """The made-up malicious IPs come from documentation ranges, which ThreatLens rightly refuses to
    send to outside services. For the recordings, treat them like any public address."""
    if any(ipaddress.ip_address(value) in net for net in _DOCUMENTATION_NETS):
        return known_good.KnownGoodResult(is_known_good=False, skip_external_lookup=False, reason="")
    return _real_check_ip(value)


async def build(database_url: str | None, load_sample: bool) -> list[dict]:
    now = datetime.now(timezone.utc)
    known_good.check_ip = _check_ip_treating_documentation_as_public
    frozen = []
    for case in CASES:
        kev.reset_catalog()  # the KEV catalog is cached between lookups; each case has its own
        async with recorded_internet(case["responses"], now) as client:
            investigation = await investigate(case["query"], offline_settings(), MemoryStore(), client,
                                              write_ai_report=False)
        frozen.append(freeze(case, investigation))
        print(f"  {case['id']:<22} {investigation.verdict.level:<9} {investigation.verdict.score!s:>4}  "
              f"{len(frozen[-1]['citations']) - 1} sources")

    if database_url:
        from app.store import PostgresStore

        store = PostgresStore(database_url)
        await store.init()

        async def dont_save(investigation):  # building cases must not add to the site's history
            return investigation.id
        store.save = dont_save
        if load_sample:
            _load_sample(store)
        try:
            for case in PROFILE_CASES:
                async with recorded_internet({}, now) as client:
                    investigation = await investigate(case["query"], offline_settings(database_url), store, client,
                                                      write_ai_report=False)
                if investigation.verdict.level != "PROFILE":
                    print(f"  {case['id']:<22} skipped: no profile found ({investigation.verdict.headline})")
                    continue
                frozen.append(freeze(case, investigation))
                print(f"  {case['id']:<22} PROFILE")
        finally:
            await store.close()
    else:
        print("  (threat and weakness profiles skipped: add --database to include them)")
    return frozen


def _load_sample(store) -> None:
    from app.knowledge import cwe
    from app.knowledge.attack import SOURCE, parse_bundle
    from app.knowledge.repository import KnowledgeRepository
    from tests.attack_sample import BUNDLE
    from tests.cwe_sample import zipped

    repo = KnowledgeRepository(store)
    repo.import_source(SOURCE, *parse_bundle(copy.deepcopy(BUNDLE)))
    version, entities, relationships = cwe.parse_catalog(cwe.read_file(zipped()))
    repo.import_source(cwe.SOURCE, version, entities, relationships, [])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--database", help="PostgreSQL URL with ATT&CK and CWE imported, for the profile cases")
    parser.add_argument("--load-sample", action="store_true", help="load the small test sample first (test databases only)")
    parser.add_argument("--out", type=Path, default=OUT)
    args = parser.parse_args()
    print("Building evaluation cases from the recordings:")
    cases = asyncio.run(build(args.database, args.load_sample))
    args.out.write_text(json.dumps({"built_at": datetime.now(timezone.utc).date().isoformat(), "cases": cases},
                                   indent=1, ensure_ascii=False, default=str) + "\n", encoding="utf-8")
    print(f"Saved {len(cases)} cases to {args.out}")


if __name__ == "__main__":
    main()
