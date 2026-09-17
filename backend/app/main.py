import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import httpx2
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import get_settings
from app.db import check_database
from app.detection import DetectionError, detect
from app.investigate import investigate
from app.models import Indicator, InvestigateRequest, Investigation, InvestigationSummary
from app.store import MemoryStore, PostgresStore

logger = logging.getLogger("threatlens")
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # One shared HTTP client: reuses connections, which makes source lookups faster
    app.state.http = httpx2.AsyncClient(
        timeout=httpx2.Timeout(settings.source_timeout_seconds),
        headers={"User-Agent": f"ThreatLens/{settings.app_version}"},
        follow_redirects=True,
    )
    app.state.store = MemoryStore()
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

# CORS decides which websites are allowed to call this API from a browser.
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
def detect_input(body: InvestigateRequest):
    """Only identify the input type, without contacting any source. Useful for instant form feedback."""
    try:
        return detect(body.query)
    except DetectionError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@app.post("/api/investigations", response_model=Investigation)
async def create_investigation(body: InvestigateRequest, request: Request):
    """Run a full investigation. Usually takes a few seconds."""
    try:
        return await investigate(body.query, settings, request.app.state.store, request.app.state.http)
    except DetectionError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@app.get("/api/investigations", response_model=list[InvestigationSummary])
async def list_investigations(request: Request, limit: int = Query(20, ge=1, le=100)):
    return await request.app.state.store.recent(limit)


@app.get("/api/investigations/{investigation_id}", response_model=Investigation)
async def get_investigation(investigation_id: str, request: Request):
    found = await request.app.state.store.get(investigation_id)
    if not found:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return found
