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

-- AI reports, reused when the exact same evidence is explained again (saves free AI quota).
CREATE TABLE IF NOT EXISTS ai_report_cache (
    evidence_hash   TEXT PRIMARY KEY,
    report          JSONB NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Daily counters (investigations run, AI reports written), so limits survive a restart.
CREATE TABLE IF NOT EXISTS daily_counters (
    day             DATE NOT NULL,
    name            TEXT NOT NULL,
    count           INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (day, name)
);

-- Investigations pinned to the home page as ready-made examples.
CREATE TABLE IF NOT EXISTS pinned_examples (
    slot             TEXT PRIMARY KEY,
    label            TEXT NOT NULL,
    note             TEXT NOT NULL,
    position         INTEGER NOT NULL DEFAULT 0,
    investigation_id UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Threat knowledge graph (Phase 2). Filled by scripts/import_attack.py.
-- ---------------------------------------------------------------------------

-- Any "thing" in the graph: techniques, tactics, groups, malware, tools, campaigns, mitigations.
CREATE TABLE IF NOT EXISTS entities (
    id              TEXT PRIMARY KEY,
    kind            TEXT NOT NULL,
    external_id     TEXT,
    name            TEXT NOT NULL,
    aliases         TEXT[] NOT NULL DEFAULT '{}',
    description     TEXT NOT NULL DEFAULT '',
    url             TEXT,
    source          TEXT NOT NULL,
    details         JSONB NOT NULL DEFAULT '{}',
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS entities_external_id_idx ON entities (upper(external_id));
CREATE INDEX IF NOT EXISTS entities_kind_idx ON entities (kind);

-- How entities connect: "APT29 uses Mimikatz", "M1043 mitigates T1003.001".
CREATE TABLE IF NOT EXISTS relationships (
    id              TEXT PRIMARY KEY,
    source_id       TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    target_id       TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    type            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    source          TEXT NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS relationships_source_idx ON relationships (source_id);
CREATE INDEX IF NOT EXISTS relationships_target_idx ON relationships (target_id);

-- IDs MITRE retired, pointing at the entry that replaced them.
CREATE TABLE IF NOT EXISTS entity_redirects (
    old_external_id TEXT PRIMARY KEY,
    entity_id       TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    source          TEXT NOT NULL
);

-- Which version of each knowledge source is loaded.
CREATE TABLE IF NOT EXISTS knowledge_imports (
    source          TEXT PRIMARY KEY,
    version         TEXT,
    imported_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    counts          JSONB NOT NULL DEFAULT '{}'
);
