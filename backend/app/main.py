from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import get_settings
from app.db import check_database

settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="ThreatLens — See the threat before it sees you.",
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
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "docs": "/docs",
    }


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
    code = 200 if result["status"] == "ok" else 503
    return JSONResponse(status_code=code, content=result)
