"""ThreatLens API entry point.

Run locally with:  uvicorn app.main:app --reload
"""
import asyncio
import json
import logging
import re
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import httpx2
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response, StreamingResponse

from app.config import get_settings
from app.db import check_database
from app.detection import DetectionError, detect
from app.attack_map import AttackMap, build_attack_map, navigator_layer
from app.bulk import Batch, BulkRequest, Plan, plan, run_bulk
from app.export import batch_csv, batch_stix, investigation_csv, investigation_stix
from app.graph import InvestigationGraph, build_graph
from app.investigate import investigate
from app.knowledge.api import router as knowledge_router
from app.limits import VisitorLimiter, visitor_key
from app.models import Example, Indicator, InvestigateRequest, Investigation, InvestigationSummary
from app.store import MemoryStore, PostgresStore

logger = logging.getLogger("threatlens")
settings = get_settings()
KEEPALIVE_SECONDS = 15
limiter = VisitorLimiter()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # One shared HTTP client: reuses connections, which makes source lookups faster
    app.state.http = httpx2.AsyncClient(
        timeout=httpx2.Timeout(settings.source_timeout_seconds),
        headers={"User-Agent": f"ThreatLens/{settings.app_version}"},
        follow_redirects=True,
    )
    app.state.store = MemoryStore()
    app.state.tasks = set()  # streamed investigations still running
    if settings.database_url:
        store = PostgresStore(settings.database_url)
        try:
            await store.init()
            app.state.store = store
            logger.warning("Using PostgreSQL store.")
        except Exception as exc:
            logger.warning("Database setup failed (%s). Using in-memory store instead.", type(exc).__name__)
            await store.close()
    else:
        logger.warning("DATABASE_URL not set. Using in-memory store; investigations won't be kept.")
    yield
    await app.state.store.close()
    await app.state.http.aclose()


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="ThreatLens — See the threat before it sees you.",
    lifespan=lifespan,
)

app.include_router(knowledge_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {"name": settings.app_name, "version": settings.app_version, "docs": "/docs"}


@app.get("/health")
def health():
    """Fast check that the server is running. Render uses this path too."""
    return {
        "status": "ok",
        "version": settings.app_version,
        "environment": settings.app_env,
        "time": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/health/db")
def health_db():
    """Check the database connection. Returns 503 if the database is down."""
    result = check_database()
    return JSONResponse(status_code=200 if result["status"] == "ok" else 503, content=result)


@app.post("/api/detect", response_model=Indicator)
def detect_input(body: InvestigateRequest, request: Request):
    """Only identify the input type, without contacting any source. Useful for instant form feedback."""
    decision = limiter.check("detect", visitor_key(request), settings.detects_per_minute_per_visitor, 60)
    if not decision.allowed:
        raise HTTPException(status_code=429, detail="Too many requests. Slow down for a moment.",
                            headers={"Retry-After": str(decision.retry_after_seconds)})
    try:
        return detect(body.query)
    except DetectionError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


AI_LIMIT_MESSAGE = ("The daily AI summary limit for this free demo has been reached. "
                    "The score, evidence, and decision trail below are unaffected.")


async def _admit(request: Request) -> tuple[object, bool, bool]:
    """Apply the usage limits. Returns (store, AI allowed, research allowed) or raises 429."""
    store = request.app.state.store
    decision = limiter.check("investigate", visitor_key(request),
                             settings.investigations_per_hour_per_visitor, 3600)
    if not decision.allowed:
        raise HTTPException(status_code=429, detail=decision.message,
                            headers={"Retry-After": str(decision.retry_after_seconds)})

    # Daily ceilings for everyone, so the free tiers survive a busy day
    used_today = await store.count_today("investigations")
    if used_today > settings.daily_investigation_cap:
        raise HTTPException(
            status_code=429,
            detail=("ThreatLens has reached its daily investigation limit for this free demo. "
                    "The example investigations below still work, and new searches open again tomorrow."),
        )
    ai_allowed = await store.count_today("ai_reports", add=0) < settings.daily_ai_report_cap
    research_allowed = await store.count_today("research_runs", add=0) < settings.daily_research_cap
    return store, ai_allowed, research_allowed


async def _count_usage(store, result: Investigation) -> None:
    if result.report and result.report.status == "ready" and not result.report.cached:
        await store.count_today("ai_reports")
    if result.research and result.research.ai_calls and not result.research.cached:
        await store.count_today("research_runs")


@app.post("/api/investigations", response_model=Investigation)
async def create_investigation(body: InvestigateRequest, request: Request):
    """Run a full investigation and return the result. Usually takes a few seconds."""
    store, ai_allowed, research_allowed = await _admit(request)
    try:
        result = await investigate(body.query, settings, store, request.app.state.http,
                                   ai_cache_only=not ai_allowed, research_allowed=research_allowed,
                                   ai_skipped_message=AI_LIMIT_MESSAGE)
    except DetectionError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    await _count_usage(store, result)
    return result


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data, default=str)}\n\n"


@app.post("/api/investigations/stream")
async def stream_investigation(body: InvestigateRequest, request: Request):
    """The same investigation, sent step by step as it happens (Server-Sent Events).

    Events, in order:
    - `step`: one decision-trail step, the moment it's recorded
    - `status`: a short message during a slow wait, e.g. "Waiting for 5 sources to answer…"
    - `done`: the finished investigation, exactly as `POST /api/investigations` returns it
    - `error`: something went wrong; `detail` says what

    Problems with the input or the usage limits are answered with a normal 422 or 429 before
    any streaming starts. If the browser disconnects, the investigation still finishes and is saved.
    """
    try:
        detect(body.query)
    except DetectionError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    store, ai_allowed, research_allowed = await _admit(request)
    queue: asyncio.Queue = asyncio.Queue()

    async def run() -> None:
        try:
            result = await investigate(body.query, settings, store, request.app.state.http,
                                       ai_cache_only=not ai_allowed, research_allowed=research_allowed,
                                       ai_skipped_message=AI_LIMIT_MESSAGE,
                                       on_event=lambda kind, data: queue.put_nowait((kind, data)))
            await _count_usage(store, result)
            queue.put_nowait(("done", result.model_dump(mode="json")))
        except Exception:
            logger.exception("Streamed investigation failed")
            queue.put_nowait(("error", {"detail": "The investigation failed unexpectedly. Please try again."}))

    # Runs on its own, so closing the tab doesn't cancel it; kept referenced until it ends
    task = asyncio.create_task(run())
    request.app.state.tasks.add(task)
    task.add_done_callback(request.app.state.tasks.discard)

    async def events():
        while True:
            try:
                kind, data = await asyncio.wait_for(queue.get(), timeout=KEEPALIVE_SECONDS)
            except asyncio.TimeoutError:
                yield ": still working\n\n"  # a comment line keeps proxies from closing a quiet connection
                continue
            yield _sse(kind, data)
            if kind in ("done", "error"):
                return

    return StreamingResponse(events(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ---------------------------------------------------------------- bulk lookup

@app.post("/api/bulk/parse", response_model=Plan)
def parse_bulk(body: BulkRequest, request: Request):
    """What a bulk lookup would investigate, without contacting any source. For the live preview."""
    decision = limiter.check("detect", visitor_key(request), settings.detects_per_minute_per_visitor, 60)
    if not decision.allowed:
        raise HTTPException(status_code=429, detail="Too many requests. Slow down for a moment.",
                            headers={"Retry-After": str(decision.retry_after_seconds)})
    return plan(body.text, settings.bulk_max_items)


@app.post("/api/bulk/stream")
async def stream_bulk(body: BulkRequest, request: Request):
    """Investigate everything in the pasted text, sending each result the moment it's ready.

    Events: `plan` (what will be investigated), `row` (one finished item, in the order they finish),
    `done` (the saved batch, with its id for a shareable link), `error`. Like single investigations,
    it keeps going if the browser disconnects, and the batch is saved at the end.
    """
    planned = plan(body.text, settings.bulk_max_items)
    if not planned.items:
        raise HTTPException(status_code=422, detail="No indicators found. Paste CVEs, IPs, domains, URLs, hashes "
                                                    "or threat names, one per line or inside any text.")
    store = request.app.state.store
    decision = limiter.check("bulk", visitor_key(request), settings.bulk_batches_per_hour_per_visitor, 3600)
    if not decision.allowed:
        minutes = max(1, round(decision.retry_after_seconds / 60))
        raise HTTPException(status_code=429, headers={"Retry-After": str(decision.retry_after_seconds)},
                            detail=(f"You've used the {settings.bulk_batches_per_hour_per_visitor} bulk lookups allowed "
                                    f"per hour on this public demo. Try again in about {minutes} minute"
                                    f"{'s' if minutes != 1 else ''}."))
    used_today = await store.count_today("investigations", add=0)
    if used_today + len(planned.items) > settings.daily_investigation_cap:
        raise HTTPException(status_code=429, detail=(
            "This bulk lookup would go over the daily investigation limit for this free demo. "
            "Try fewer indicators, or come back tomorrow."))
    await store.count_today("investigations", add=len(planned.items))
    queue: asyncio.Queue = asyncio.Queue()
    queue.put_nowait(("plan", planned.model_dump(mode="json")))

    async def run() -> None:
        try:
            batch = await run_bulk(planned, settings, store, request.app.state.http,
                                   on_row=lambda row: queue.put_nowait(("row", row.model_dump(mode="json"))))
            queue.put_nowait(("done", batch.model_dump(mode="json")))
        except Exception:
            logger.exception("Bulk lookup failed")
            queue.put_nowait(("error", {"detail": "The bulk lookup failed unexpectedly. Please try again."}))

    task = asyncio.create_task(run())
    request.app.state.tasks.add(task)
    task.add_done_callback(request.app.state.tasks.discard)

    async def events():
        while True:
            try:
                kind, data = await asyncio.wait_for(queue.get(), timeout=KEEPALIVE_SECONDS)
            except asyncio.TimeoutError:
                yield ": still working\n\n"
                continue
            yield _sse(kind, data)
            if kind in ("done", "error"):
                return

    return StreamingResponse(events(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/bulk/{batch_id}", response_model=Batch)
async def get_bulk(batch_id: str, request: Request):
    found = await request.app.state.store.get_batch(batch_id)
    if not found:
        raise HTTPException(status_code=404, detail="Bulk lookup not found.")
    return found


# ---------------------------------------------------------------- exports

STIX_MEDIA_TYPE = "application/stix+json;version=2.1"


def _filename(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", text)[:60].strip("_") or "export"


def _download(content: str | dict, filename: str, media_type: str) -> Response:
    body = json.dumps(content, indent=2, ensure_ascii=False) if isinstance(content, dict) else content
    return Response(body, media_type=media_type,
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@app.get("/api/investigations/{investigation_id}/export/{fmt}")
async def export_investigation(investigation_id: str, fmt: str, request: Request):
    """Download a report as STIX 2.1 (fmt=stix) or CSV (fmt=csv)."""
    if fmt not in ("stix", "csv"):
        raise HTTPException(status_code=404, detail="Exports are available as stix or csv.")
    store = request.app.state.store
    found = await store.get(investigation_id)
    if not found:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    name = f"threatlens-{_filename(found.indicator.value)}"
    if fmt == "stix":
        return _download(await investigation_stix(found, store, settings), f"{name}.stix.json", STIX_MEDIA_TYPE)
    return _download(await investigation_csv(found, store, settings), f"{name}.csv", "text/csv; charset=utf-8")


@app.get("/api/bulk/{batch_id}/export/{fmt}")
async def export_bulk(batch_id: str, fmt: str, request: Request):
    """Download a whole bulk lookup as STIX 2.1 (one bundle) or CSV (one row per indicator)."""
    if fmt not in ("stix", "csv"):
        raise HTTPException(status_code=404, detail="Exports are available as stix or csv.")
    store = request.app.state.store
    batch = await store.get_batch(batch_id)
    if not batch:
        raise HTTPException(status_code=404, detail="Bulk lookup not found.")
    name = f"threatlens-bulk-{batch_id[:8]}"
    if fmt == "csv":
        return _download(batch_csv(batch, settings), f"{name}.csv", "text/csv; charset=utf-8")
    investigations = []
    for row in batch["rows"]:
        if row.get("investigation_id"):
            found = await store.get(row["investigation_id"])
            if found:
                investigations.append(found)
    return _download(await batch_stix(batch, investigations, store, settings), f"{name}.stix.json", STIX_MEDIA_TYPE)


@app.get("/api/examples", response_model=list[Example])
async def list_examples(request: Request):
    """Ready-made investigations pinned to the home page. Filled in by scripts/seed_examples.py."""
    return await request.app.state.store.examples()


@app.get("/api/investigations", response_model=list[InvestigationSummary])
async def list_investigations(request: Request, limit: int = Query(20, ge=1, le=100)):
    return await request.app.state.store.recent(limit)


@app.get("/api/investigations/{investigation_id}", response_model=Investigation)
async def get_investigation(investigation_id: str, request: Request):
    found = await request.app.state.store.get(investigation_id)
    if not found:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return found


@app.get("/api/investigations/{investigation_id}/graph", response_model=InvestigationGraph)
async def get_investigation_graph(investigation_id: str, request: Request):
    """The decision map (why this verdict) and the connections graph for a saved investigation."""
    store = request.app.state.store
    found = await store.get(investigation_id)
    if not found:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return await build_graph(found, store)


@app.get("/api/investigations/{investigation_id}/attack", response_model=AttackMap)
async def get_attack_map(investigation_id: str, request: Request):
    """The ATT&CK techniques this investigation touches, by stage of attack."""
    store = request.app.state.store
    found = await store.get(investigation_id)
    if not found:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return await build_attack_map(found, store)


@app.get("/api/investigations/{investigation_id}/attack/layer")
async def get_navigator_layer(investigation_id: str, request: Request):
    """The same map as an ATT&CK Navigator layer file, to open in MITRE's Navigator."""
    store = request.app.state.store
    found = await store.get(investigation_id)
    if not found:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    attack_map = await build_attack_map(found, store)
    if attack_map.status != "ok":
        raise HTTPException(status_code=404, detail="There are no ATT&CK techniques to export for this investigation.")
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", found.indicator.value)[:60] or "investigation"
    return JSONResponse(navigator_layer(attack_map, found.indicator.value),
                        headers={"Content-Disposition": f'attachment; filename="threatlens-{safe}-attack-layer.json"'})
