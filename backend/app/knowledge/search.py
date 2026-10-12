"""Finds knowledge entries by ID, name, alias, similar spelling, or description words.

Three signals, because each catches what the others miss:
  1. Exact match on an ID, name, or alias   ("G1017", "APT29", "Cozy Bear"), also ignoring spaces and
     punctuation, because feeds write names like "AgentTesla" or "win.cobalt_strike"
  2. Similar spelling (PostgreSQL trigrams)  ("mimikats", "cobalt", "volt typhon")
  3. Full-text search of the descriptions    ("lsass dumping", "scheduled task persistence")

The database finds the candidates; the final ranking is done here in plain Python,
so every score can be explained and tested.
"""
import asyncio
import re

from app.knowledge.models import SearchResult

KINDS = {"technique", "tactic", "group", "malware", "tool", "campaign", "mitigation"}
MAX_LIMIT = 25

CANDIDATES_SQL = """
WITH q AS (
    SELECT %(q)s::text AS raw,
           lower(%(q)s::text) AS low,
           nullif(websearch_to_tsquery('english', %(q)s)::text, '')::tsquery AS all_words,
           nullif(replace(websearch_to_tsquery('english', %(q)s)::text, ' & ', ' | '), '')::tsquery AS any_word
),
scored AS (
    SELECT e.external_id, e.name, e.kind, e.url, e.description,
           upper(coalesce(e.external_id, '')) = upper(q.raw) AS exact_id,
           lower(e.name) = q.low AS exact_name,
           regexp_replace(lower(e.name), '[^a-z0-9]', '', 'g') = %(compact)s AS compact_name,
           EXISTS (SELECT 1 FROM unnest(e.aliases) a
                   WHERE regexp_replace(lower(a), '[^a-z0-9]', '', 'g') = %(compact)s) AS compact_alias,
           (SELECT a FROM unnest(e.aliases) a WHERE lower(a) = q.low LIMIT 1) AS exact_alias,
           greatest(similarity(lower(e.name), q.low), word_similarity(q.low, lower(e.name))) AS name_similarity,
           (SELECT a FROM unnest(e.aliases) a
             ORDER BY greatest(similarity(lower(a), q.low), word_similarity(q.low, lower(a))) DESC LIMIT 1) AS best_alias,
           coalesce((SELECT max(greatest(similarity(lower(a), q.low), word_similarity(q.low, lower(a))))
                       FROM unnest(e.aliases) a), 0) AS alias_similarity,
           coalesce(q.all_words IS NOT NULL AND e.search @@ q.all_words, false) AS has_all_words,
           coalesce(ts_rank_cd(e.search, q.any_word, 32), 0) AS text_rank
    FROM entities e, q
    WHERE (%(kinds)s::text[] IS NULL OR e.kind = ANY(%(kinds)s::text[]))
)
SELECT * FROM scored
WHERE exact_id OR exact_name OR exact_alias IS NOT NULL OR compact_name OR compact_alias
   OR name_similarity > 0.45 OR alias_similarity > 0.45 OR text_rank > 0
ORDER BY exact_id DESC, (exact_name OR exact_alias IS NOT NULL OR compact_name OR compact_alias) DESC,
         greatest(name_similarity, alias_similarity) DESC, text_rank DESC
LIMIT 200
"""


def normalize_query(text: str) -> str:
    return " ".join(text.split())[:200]


# Malpedia-style family names start with a platform, e.g. "win.cobalt_strike", "elf.mirai"
PLATFORM_PREFIX = re.compile(r"^(?:win|elf|osx|apk|jar|js|ps1|py|vbs|php|asp)\.", re.IGNORECASE)


def compact(text: str) -> str | None:
    """Lowercase letters and digits only: "Agent Tesla", "AgentTesla" and "win.agent_tesla" all become "agenttesla".

    Too short to be meaningful? Returns None, so "--" doesn't match every entry without letters.
    """
    letters = re.sub(r"[^a-z0-9]", "", PLATFORM_PREFIX.sub("", text.strip()).lower())
    return letters if len(letters) >= 3 else None


def score(row: dict) -> tuple[float, str]:
    """Final score (higher is better) and a plain explanation of why it matched.

    Exact matches sit in their own tiers (200+), which a partial match (at most 105)
    can never reach. Within a tier, description relevance breaks ties, for example
    between two techniques both named "Spearphishing Attachment".
    """
    text = row["text_rank"] * (1.0 if row["has_all_words"] else 0.5)
    if row["exact_id"]:
        return 300.0, "ID"
    if row["exact_name"]:
        return round(200 + text * 10, 2), "name"
    if row["exact_alias"]:
        return round(190 + text * 10, 2), f"alias: {row['exact_alias']}"
    if row.get("compact_name"):
        return round(195 + text * 10, 2), "name, ignoring spaces"
    if row.get("compact_alias"):
        return round(190 + text * 5, 2), "alias, ignoring spaces"

    spelling = max(row["name_similarity"], row["alias_similarity"] * 0.95)
    total = spelling * 60 + text * 40 + (5 if row["has_all_words"] else 0)

    if spelling >= 0.45 and spelling * 60 >= text * 40:
        if row["name_similarity"] >= row["alias_similarity"] * 0.95:
            reason = "similar name"
        else:
            reason = f"similar alias: {row['best_alias']}"
    else:
        reason = "description" if row["has_all_words"] else "some description words"
    return round(total, 2), reason


def first_sentence(text: str, limit: int = 220) -> str:
    text = " ".join(text.split())
    match = re.search(r"(?<=[.!?])\s", text)
    sentence = text[:match.start()] if match else text
    return sentence if len(sentence) <= limit else sentence[:limit - 1].rsplit(" ", 1)[0] + "…"


async def search(store, query: str, kinds: list[str] | None = None, limit: int = 10) -> list[SearchResult]:
    query = normalize_query(query)
    if not query:
        return []
    kinds = [k for k in (kinds or []) if k in KINDS] or None
    limit = max(1, min(limit, MAX_LIMIT))

    def run():
        with store.connection() as conn:
            return conn.execute(CANDIDATES_SQL, {"q": query, "kinds": kinds, "compact": compact(query)}).fetchall()

    rows = await asyncio.to_thread(run)
    results = []
    for row in rows:
        points, reason = score(row)
        results.append(SearchResult(external_id=row["external_id"], name=row["name"], kind=row["kind"],
                                    url=row["url"], snippet=first_sentence(row["description"]),
                                    matched_on=reason, score=points))
    results.sort(key=lambda r: (-r.score, r.external_id or ""))
    return results[:limit]
