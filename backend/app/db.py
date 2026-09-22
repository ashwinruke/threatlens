"""Database helpers.

Day 1 only needs a health check. Real tables arrive on Day 2.
"""
import time

import psycopg

from app.config import get_settings


def check_database() -> dict:
    """Connect to Postgres, run a tiny query, and check for pgvector.

    Returns a plain dictionary so the API can show it directly.
    Never returns the connection string or any password.
    """
    settings = get_settings()
    if not settings.database_url:
        return {"status": "not_configured", "detail": "DATABASE_URL is not set."}

    started = time.perf_counter()
    try:
        # connect_timeout is generous because a sleeping Neon database needs a moment to wake
        with psycopg.connect(settings.database_url, connect_timeout=15) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT version();")
                version = cur.fetchone()[0].split(",")[0]
                cur.execute("SELECT extversion FROM pg_extension WHERE extname = 'vector';")
                row = cur.fetchone()
        latency_ms = round((time.perf_counter() - started) * 1000)
        return {
            "status": "ok",
            "postgres": version,
            "pgvector": row[0] if row else None,
            "latency_ms": latency_ms,
        }
    except Exception as exc:  # show the type of error, not secrets
        return {"status": "error", "detail": type(exc).__name__}
