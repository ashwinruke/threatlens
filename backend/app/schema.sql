-- ThreatLens database tables.
-- Safe to run many times: it only creates what doesn't exist yet.

CREATE EXTENSION IF NOT EXISTS vector;

-- One row per investigation. The full result (signals, sources, trace) is stored as JSON
-- for now, because its shape will keep changing during the MVP. Phase 2 adds proper
-- tables for entities and relationships.
CREATE TABLE IF NOT EXISTS investigations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    query           TEXT NOT NULL,
    indicator_type  TEXT NOT NULL,
    indicator_value TEXT NOT NULL,
    score           INTEGER NOT NULL,
    level           TEXT NOT NULL,
    confidence      TEXT NOT NULL,
    result          JSONB NOT NULL,
    duration_ms     INTEGER NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS investigations_created_idx ON investigations (created_at DESC);
CREATE INDEX IF NOT EXISTS investigations_indicator_idx ON investigations (indicator_type, indicator_value);

-- Cached answers from each source, so repeated lookups don't burn free API limits.
CREATE TABLE IF NOT EXISTS source_cache (
    source          TEXT NOT NULL,
    indicator_type  TEXT NOT NULL,
    indicator_value TEXT NOT NULL,
    result          JSONB NOT NULL,
    fetched_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (source, indicator_type, indicator_value)
);
