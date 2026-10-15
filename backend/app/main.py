"""ThreatLens API entry point.

Run locally with:  uvicorn app.main:app --reload
"""
import asyncio
import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import httpx2
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse

from app.config import get_settings
from app.db import check_database
from app.detection import DetectionError, detect
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
