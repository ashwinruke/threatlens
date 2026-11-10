"""The public API (v1): for security tools that send indicators to ThreatLens automatically.

    curl -X POST https://threatlens-api-fyjy.onrender.com/v1/lookup \\
         -H "Authorization: Bearer tl_..." -H "Content-Type: application/json" \\
         -d '{"indicator": "CVE-2021-44228"}'

Keys are free and made on the website's API page. Only a hash of each key is stored. Every key
has a daily allowance (one unit per indicator looked up) and a per-minute limit, and the API
shares ThreatLens's daily ceilings with the website, so automated use can't use up the free
tiers the website runs on.

The JSON is versioned: fields may be added within v1, but never renamed or removed.
Lookups made through the API are saved unlisted: their report links work, but they never
appear in the website's public History.
"""
import asyncio
import hashlib
import json
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from app.detection import DetectionError
from app.investigate import investigate
from app.models import Investigation

router = APIRouter(prefix="/v1", tags=["Public API v1"])
keys_router = APIRouter(tags=["API keys"])
bearer = HTTPBearer(auto_error=False, description="Your ThreatLens API key, starting with tl_")
KEY_PREFIX = "tl_"
DOCS = "https://threatlens-xi.vercel.app/developers"


def _main():
    from app import main  # settings, limits and the export helpers live there (tests replace them)
    return main


def hash_key(key: str) -> str:
    return hashlib.sha256(f"threatlens-api:{key}".encode()).hexdigest()


# ---------------------------------------------------------------- key storage

@dataclass
class ApiKey:
    id: str
    name: str
    prefix: str  # the first characters, so a person can tell keys apart
    created_at: datetime
    last_used_at: datetime | None = None
    revoked: bool = False


class MemoryKeys:
    def __init__(self) -> None:
        self.keys: dict[str, ApiKey] = {}  # key hash -> key

    async def create(self, key_hash: str, name: str, prefix: str) -> ApiKey:
        key = ApiKey(id=str(uuid.uuid4()), name=name, prefix=prefix, created_at=datetime.now(timezone.utc))
        self.keys[key_hash] = key
        return key

    async def find(self, key_hash: str) -> ApiKey | None:
        return self.keys.get(key_hash)

    async def touch(self, key: ApiKey) -> None:
        key.last_used_at = datetime.now(timezone.utc)

    async def revoke(self, key: ApiKey) -> None:
        key.revoked = True


class PostgresKeys:
    def __init__(self, store) -> None:
        self.store = store

    def _key(self, row) -> ApiKey:
        return ApiKey(id=str(row["id"]), name=row["name"], prefix=row["prefix"], created_at=row["created_at"],
                      last_used_at=row["last_used_at"], revoked=row["revoked_at"] is not None)

    async def create(self, key_hash: str, name: str, prefix: str) -> ApiKey:
        def run():
            with self.store.connection() as conn:
                return conn.execute("INSERT INTO api_keys (key_hash, name, prefix) VALUES (%s, %s, %s) RETURNING *",
                                    (key_hash, name, prefix)).fetchone()
        return self._key(await asyncio.to_thread(run))

    async def find(self, key_hash: str) -> ApiKey | None:
        def run():
            with self.store.connection() as conn:
                return conn.execute("SELECT * FROM api_keys WHERE key_hash = %s", (key_hash,)).fetchone()
        row = await asyncio.to_thread(run)
        return self._key(row) if row else None

    async def touch(self, key: ApiKey) -> None:
        now = datetime.now(timezone.utc)
        if key.last_used_at and now - key.last_used_at < timedelta(minutes=5):
            return  # one write every few minutes is plenty

        def run():
            with self.store.connection() as conn:
                conn.execute("UPDATE api_keys SET last_used_at = now() WHERE id = %s", (key.id,))
        await asyncio.to_thread(run)

    async def revoke(self, key: ApiKey) -> None:
        def run():
            with self.store.connection() as conn:
                conn.execute("UPDATE api_keys SET revoked_at = now() WHERE id = %s", (key.id,))
        await asyncio.to_thread(run)


def keys_for(store):
    keys = getattr(store, "_api_keys", None)
    if keys is None:
        keys = PostgresKeys(store) if hasattr(store, "connection") else MemoryKeys()
        store._api_keys = keys
    return keys


# ---------------------------------------------------------------- creating a key (website)

class KeyRequest(BaseModel):
    name: str = Field(min_length=1, max_length=60, description="What the key is for, e.g. 'SOC alert enrichment'")


@keys_router.post("/api/keys", status_code=201)
async def create_key(body: KeyRequest, request: Request):
    """Make a free API key. It's shown once; only a hash is kept."""
    main = _main()
    decision = main.limiter.check("api-key", main.visitor_key(request), main.settings.api_keys_per_day_per_visitor, 86400)
    if not decision.allowed:
        raise HTTPException(status_code=429, detail="That's enough new API keys for today. Try again tomorrow.")
    secret = KEY_PREFIX + secrets.token_urlsafe(32)
    key = await keys_for(request.app.state.store).create(hash_key(secret), body.name.strip(), secret[:10])
    return {"key": secret, "name": key.name, "prefix": key.prefix, "daily_limit": main.settings.api_daily_units,
            "per_minute_limit": main.settings.api_requests_per_minute}


# ---------------------------------------------------------------- authentication and limits

def _unauthorized(message: str) -> HTTPException:
    return HTTPException(status_code=401, detail=f"{message} Make a free key at {DOCS}.",
                         headers={"WWW-Authenticate": "Bearer"})


async def api_key(request: Request, credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
                  x_api_key: str | None = Header(None, include_in_schema=False)) -> ApiKey:
    """Every /v1 call: a valid key, under its per-minute limit."""
    secret = credentials.credentials if credentials else x_api_key
    if not secret:
        raise _unauthorized("Send your API key as 'Authorization: Bearer tl_...'.")
    if not secret.startswith(KEY_PREFIX) or len(secret) > 100:
        raise _unauthorized("That isn't a ThreatLens API key.")
    keys = keys_for(request.app.state.store)
    key = await keys.find(hash_key(secret))
    if not key or key.revoked:
        raise _unauthorized("That API key doesn't exist or was revoked.")
    main = _main()
    decision = main.limiter.check("api-minute", key.id, main.settings.api_requests_per_minute, 60)
    if not decision.allowed:
        raise HTTPException(status_code=429, detail="Too many requests this minute.",
                            headers={"Retry-After": str(decision.retry_after_seconds)})
    await keys.touch(key)
    return key


def _tomorrow() -> datetime:
    today = datetime.now(timezone.utc).date()
    return datetime(today.year, today.month, today.day, tzinfo=timezone.utc) + timedelta(days=1)


async def _spend(request: Request, key: ApiKey, units: int, response: Response | None = None) -> int:
    """Take units from the key's daily allowance and the site-wide daily ceiling. Returns what's left."""
    main = _main()
    store = request.app.state.store
    used = await store.count_today(f"api:{key.id}", add=0)
    limit = main.settings.api_daily_units
    if used + units > limit:
        raise HTTPException(status_code=429, detail=f"This key's daily allowance ({limit} indicators) is used up. "
                            "It resets at midnight UTC.", headers={"Retry-After": str(int((_tomorrow() - datetime.now(timezone.utc)).total_seconds()))})
    if await store.count_today("investigations", add=0) + units > main.settings.daily_investigation_cap:
        raise HTTPException(status_code=503, detail="ThreatLens has reached its daily limit for all users. Try again tomorrow.",
                            headers={"Retry-After": "3600"})
    await store.count_today(f"api:{key.id}", add=units)
    await store.count_today("investigations", add=units)
    left = limit - used - units
    if response is not None:
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(left)
    return left


# ---------------------------------------------------------------- the v1 shape

def compact(inv: Investigation) -> dict:
    """An investigation in the API's stable shape."""
    from app.export import site_url

    base = site_url(_main().settings)
    report = inv.report
    return {
        "id": inv.id,
        "indicator": {"type": inv.indicator.type.value, "value": inv.indicator.value, "subtype": inv.indicator.subtype},
        "verdict": {"level": inv.verdict.level, "score": inv.verdict.score, "confidence": inv.verdict.confidence,
                    "headline": inv.verdict.headline},
        "signals": [{"label": s.label, "points": s.points, "source": s.source, "evidence": s.evidence} for s in inv.signals],
        "sources": [{"name": r.source, "status": r.status.value if hasattr(r.status, "value") else r.status,
                     "link": r.link, "message": r.message} for r in inv.sources],
        "ai_summary": {"status": report.status, "summary": report.summary,
                       "findings": [f.text for f in report.findings], "actions": [a.text for a in report.actions]}
                      if report and report.status == "ready" else None,
        "threat": {"name": inv.threat.profile.entity.name, "id": inv.threat.profile.entity.external_id,
                   "kind": inv.threat.profile.entity.kind,
                   "techniques": [t.external_id for t in inv.threat.profile.techniques][:50]}
                  if inv.threat and inv.threat.profile else None,
        "report_url": f"{base}/i/{inv.id}" if base and inv.id else None,
        "links": {"self": f"/v1/investigations/{inv.id}", "rules": f"/v1/investigations/{inv.id}/rules",
                  "stix": f"/v1/investigations/{inv.id}/stix"} if inv.id else None,
        "created_at": inv.created_at.isoformat(),
    }


class LookupRequest(BaseModel):
    indicator: str = Field(min_length=1, max_length=500, description="A CVE, IP, domain, URL, email, file hash or threat name",
                           examples=["CVE-2021-44228"])
    ai_summary: bool = Field(False, description="Also write the cited AI summary (slower; subject to the daily AI limit)")


class BatchRequest(BaseModel):
    indicators: list[str] = Field(min_length=1, max_length=20, description="Up to 20 indicators")


async def _lookup(request: Request, query: str, ai_summary: bool) -> Investigation:
    main = _main()
    store = request.app.state.store
    ai_allowed = ai_summary and await store.count_today("ai_reports", add=0) < main.settings.daily_ai_report_cap
    result = await investigate(
        query, main.settings, store, request.app.state.http, write_ai_report=ai_allowed, research_allowed=False,
        listed=False, ai_skipped_message=None if ai_allowed or not ai_summary else main.AI_LIMIT_MESSAGE)
    if result.report and result.report.status == "ready" and not result.report.cached:
        await store.count_today("ai_reports")
    return result


# ---------------------------------------------------------------- endpoints

@router.get("/usage", summary="This key's allowance today")
async def usage(request: Request, key: ApiKey = Depends(api_key)):
    main = _main()
    used = await request.app.state.store.count_today(f"api:{key.id}", add=0)
    limit = main.settings.api_daily_units
    return {"key": {"name": key.name, "prefix": key.prefix, "created_at": key.created_at.isoformat()},
            "daily_limit": limit, "used_today": used, "remaining_today": max(0, limit - used),
            "resets_at": _tomorrow().isoformat(), "per_minute_limit": main.settings.api_requests_per_minute}


@router.post("/lookup", summary="Investigate one indicator")
async def lookup(body: LookupRequest, request: Request, response: Response, key: ApiKey = Depends(api_key)):
    """Checks the intelligence sources, scores the risk, and returns the verdict with its evidence.
    Uses 1 unit of the key's daily allowance. Answers in a few seconds (up to a minute if the free server is waking)."""
    await _spend(request, key, 1, response)
    try:
        return compact(await _lookup(request, body.indicator, body.ai_summary))
    except DetectionError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/lookup/batch", summary="Investigate up to 20 indicators")
async def lookup_batch(body: BatchRequest, request: Request, response: Response, key: ApiKey = Depends(api_key)):
    """One result per indicator, in the order sent. Uses 1 unit per indicator. No AI summaries."""
    await _spend(request, key, len(body.indicators), response)
    gate = asyncio.Semaphore(3)  # the sources' free tiers don't like bursts

    async def one(query: str) -> dict:
        async with gate:
            try:
                return {"input": query, "ok": True, "result": compact(await _lookup(request, query, False))}
            except DetectionError as exc:
                return {"input": query, "ok": False, "error": str(exc)}
            except Exception as exc:
                return {"input": query, "ok": False, "error": f"Investigation failed ({type(exc).__name__})."}

    results = await asyncio.gather(*(one(q) for q in body.indicators))
    return {"count": len(results), "results": list(results)}


async def _found(request: Request, investigation_id: str) -> Investigation:
    found = await request.app.state.store.get(investigation_id)
    if not found:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return found


@router.get("/investigations/{investigation_id}", summary="A saved investigation")
async def get_investigation(investigation_id: str, request: Request, key: ApiKey = Depends(api_key)):
    return compact(await _found(request, investigation_id))


@router.get("/investigations/{investigation_id}/rules", summary="Draft Sigma and YARA rules")
async def get_rules(investigation_id: str, request: Request, key: ApiKey = Depends(api_key)):
    """Sigma rules (with Splunk and Elastic searches) and YARA rules for the indicator, or links to
    community rules for a CVE or a threat profile."""
    found = await _found(request, investigation_id)
    return (await _main().detection_rules([found], request.app.state.store)).as_dict()


@router.get("/investigations/{investigation_id}/stix", summary="STIX 2.1 bundle")
async def get_stix(investigation_id: str, request: Request, key: ApiKey = Depends(api_key)):
    from app.export import investigation_stix

    found = await _found(request, investigation_id)
    bundle = await investigation_stix(found, request.app.state.store, _main().settings)
    return Response(content=json.dumps(bundle), media_type="application/stix+json;version=2.1")


@router.delete("/key", status_code=204, summary="Revoke this key")
async def revoke(request: Request, key: ApiKey = Depends(api_key)):
    """Switches the key off for good, for example if it leaked."""
    await keys_for(request.app.state.store).revoke(key)
