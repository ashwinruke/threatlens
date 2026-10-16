"""Reads and writes the threat knowledge graph in PostgreSQL."""
import asyncio

from psycopg.types.json import Jsonb

from app.knowledge.models import (Entity, EntitySummary, EntityView, KnowledgeStats, MitigationCoverage, Redirect,
                                  RelatedGroup, Relationship, TacticCount, TechniqueRef, ThreatProfile)

MAX_MITIGATIONS = 8
# ATT&CK entries that are categories rather than specific defenses, so they aren't ranked:
# M1055 "Do Not Mitigate" (explicitly not a defense) and M1056 "Pre-compromise" (a broad bucket
# for attacker-side reconnaissance that names no concrete control).
NOT_SPECIFIC_DEFENSES = ["M1055", "M1056"]

# How each connection is described from the point of view of the entity being viewed.
# (direction, relationship type, kind of the other entity) -> label
LABELS = [
    (("out", "subtechnique-of", "technique"), "Parent technique"),
    (("in", "subtechnique-of", "technique"), "Sub-techniques"),
    (("out", "attributed-to", "group"), "Attributed to"),
    (("in", "attributed-to", "campaign"), "Campaigns attributed to this group"),
    (("out", "uses", "malware"), "Malware used"),
    (("out", "uses", "tool"), "Tools used"),
    (("out", "uses", "technique"), "Techniques used"),
    (("in", "uses", "group"), "Used by groups"),
    (("in", "uses", "campaign"), "Used in campaigns"),
    (("in", "uses", "malware"), "Used by malware"),
    (("in", "uses", "tool"), "Used by tools"),
    (("in", "mitigates", "mitigation"), "Mitigations"),
    (("out", "mitigates", "technique"), "Techniques this mitigates"),
    (("in", "in-tactic", "technique"), "Techniques in this tactic"),
    # CWE weaknesses
    (("out", "childof", "weakness"), "Broader weakness"),
    (("in", "childof", "weakness"), "More specific weaknesses"),
    (("out", "can-precede", "weakness"), "Can lead to"),
    (("in", "can-precede", "weakness"), "Can result from"),
]
LABEL_ORDER = {key: (position, label) for position, (key, label) in enumerate(LABELS)}


class KnowledgeRepository:
    def __init__(self, store) -> None:
        self.store = store  # a PostgresStore; the knowledge graph needs a real database

    # ---------------------------------------------------------------- import

    def import_source(self, source: str, version: str | None, entities: list[Entity],
                      relationships: list[Relationship], redirects: list[Redirect]) -> dict:
        """Replace everything from one source in a single transaction.

        Anything from this source that's no longer in the file (for example, entries MITRE
        retired since the last import) is deleted first, then the rest is upserted. Deleting
        first matters when MITRE moves an ID such as C0035 to a new internal record: the old
        record must be gone before the new one can take its ID. If anything fails, nothing changes.
        """
        counts: dict[str, int] = {}
        for entity in entities:
            counts[entity.kind] = counts.get(entity.kind, 0) + 1

        with self.store.connection() as conn, conn.transaction(), conn.cursor() as cur:
            cur.execute("DELETE FROM entities WHERE source = %s AND NOT (id = ANY(%s))",
                        (source, [e.id for e in entities]))
            removed_entities = cur.rowcount

            cur.executemany(
                "INSERT INTO entities (id, kind, external_id, name, aliases, description, url, source, details, updated_at) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, now()) "
                "ON CONFLICT (id) DO UPDATE SET kind = EXCLUDED.kind, external_id = EXCLUDED.external_id, "
                "name = EXCLUDED.name, aliases = EXCLUDED.aliases, description = EXCLUDED.description, "
                "url = EXCLUDED.url, details = EXCLUDED.details, updated_at = now()",
                [(e.id, e.kind, e.external_id, e.name, e.aliases, e.description, e.url, e.source, Jsonb(e.details))
                 for e in entities],
            )

            cur.executemany(
                "INSERT INTO relationships (id, source_id, target_id, type, description, source, updated_at) "
                "VALUES (%s, %s, %s, %s, %s, %s, now()) "
                "ON CONFLICT (id) DO UPDATE SET source_id = EXCLUDED.source_id, target_id = EXCLUDED.target_id, "
                "type = EXCLUDED.type, description = EXCLUDED.description, updated_at = now()",
                [(r.id, r.source_id, r.target_id, r.type, r.description, r.source) for r in relationships],
            )
            cur.execute("DELETE FROM relationships WHERE source = %s AND NOT (id = ANY(%s))",
                        (source, [r.id for r in relationships]))

            cur.execute("DELETE FROM entity_redirects WHERE source = %s", (source,))
            cur.executemany(
                "INSERT INTO entity_redirects (old_external_id, entity_id, source) VALUES (%s, %s, %s) "
                "ON CONFLICT (old_external_id) DO UPDATE SET entity_id = EXCLUDED.entity_id",
                [(r.old_external_id, r.entity_id, r.source) for r in redirects],
            )

            cur.execute(
                "INSERT INTO knowledge_imports (source, version, imported_at, counts) VALUES (%s, %s, now(), %s) "
                "ON CONFLICT (source) DO UPDATE SET version = EXCLUDED.version, imported_at = now(), "
                "counts = EXCLUDED.counts",
                (source, version, Jsonb({**counts, "relationships": len(relationships), "redirects": len(redirects)})),
            )
        return {"entities": len(entities), "relationships": len(relationships), "redirects": len(redirects),
                "removed_entities": removed_entities}

    # ---------------------------------------------------------------- reading

    async def stats(self, source: str) -> KnowledgeStats | None:
        def run():
            with self.store.connection() as conn:
                imported = conn.execute("SELECT version, imported_at FROM knowledge_imports WHERE source = %s",
                                        (source,)).fetchone()
                if not imported:
                    return None
                kinds = conn.execute("SELECT kind, count(*) AS n FROM entities WHERE source = %s GROUP BY kind",
                                     (source,)).fetchall()
                rels = conn.execute("SELECT count(*) AS n FROM relationships WHERE source = %s", (source,)).fetchone()
                return imported, kinds, rels
        result = await asyncio.to_thread(run)
        if not result:
            return None
        imported, kinds, rels = result
        return KnowledgeStats(source=source, version=imported["version"], imported_at=imported["imported_at"],
                              entities={k["kind"]: k["n"] for k in kinds}, relationships=rels["n"])

    async def view(self, external_id: str) -> EntityView | None:
        """An entity and everything connected to it. Retired IDs redirect to their replacement."""
        def run():
            with self.store.connection() as conn:
                row = conn.execute("SELECT * FROM entities WHERE upper(external_id) = upper(%s)",
                                   (external_id,)).fetchone()
                redirected_from = None
                if not row:
                    row = conn.execute(
                        "SELECT e.* FROM entity_redirects r JOIN entities e ON e.id = r.entity_id "
                        "WHERE upper(r.old_external_id) = upper(%s)", (external_id,)).fetchone()
                    if row:
                        redirected_from = external_id.upper()
                if not row:
                    return None
                links = conn.execute(
                    "SELECT 'out' AS direction, r.type, e.external_id, e.name, e.kind, e.url "
                    "FROM relationships r JOIN entities e ON e.id = r.target_id WHERE r.source_id = %s "
                    "UNION ALL "
                    "SELECT 'in' AS direction, r.type, e.external_id, e.name, e.kind, e.url "
                    "FROM relationships r JOIN entities e ON e.id = r.source_id WHERE r.target_id = %s",
                    (row["id"], row["id"]),
                ).fetchall()
                if row["kind"] == "tactic":
                    # ATT&CK records a technique's tactics inside the technique, not as relationships
                    links = links + conn.execute(
                        "SELECT 'in' AS direction, 'in-tactic' AS type, external_id, name, kind, url "
                        "FROM entities WHERE kind = 'technique' AND details -> 'tactics' @> %s",
                        (Jsonb([{"id": row["external_id"]}]),),
                    ).fetchall()
                return row, links, redirected_from
        result = await asyncio.to_thread(run)
        if not result:
            return None
        row, links, redirected_from = result
        return EntityView(entity=_entity(row), related=_group(links), redirected_from=redirected_from)


    async def summaries(self, external_ids: list[str]) -> dict[str, EntitySummary]:
        """Name, kind and link for a list of IDs, keyed by upper-case ID. Unknown IDs are left out."""
        if not external_ids:
            return {}

        def run():
            with self.store.connection() as conn:
                return conn.execute(
                    "SELECT external_id, name, kind, url FROM entities WHERE upper(external_id) = ANY(%s)",
                    ([i.upper() for i in external_ids],)).fetchall()
        return {row["external_id"].upper(): EntitySummary(**row) for row in await asyncio.to_thread(run)}

    async def names(self, external_ids: list[str]) -> dict[str, str]:
        """Names for a list of IDs, e.g. {"CWE-502": "Deserialization of Untrusted Data"}. Unknown IDs are left out."""
        if not external_ids:
            return {}

        def run():
            with self.store.connection() as conn:
                return conn.execute("SELECT external_id, name FROM entities WHERE upper(external_id) = ANY(%s)",
                                    ([i.upper() for i in external_ids],)).fetchall()
        return {row["external_id"].upper(): row["name"] for row in await asyncio.to_thread(run)}

    async def profile(self, external_id: str) -> ThreatProfile | None:
        """Everything a defender needs about one threat, built on top of view().

        For a group, malware, tool or campaign this adds:
        - its techniques with their tactics, and how many fall under each tactic
        - mitigations ranked by how many of its techniques they help against
        Only techniques ATT&CK links to this entry directly are counted (not those of the
        malware it uses), which matches how MITRE's own pages present it.
        """
        view = await self.view(external_id)
        if not view:
            return None
        entity_id = view.entity.id

        def run():
            with self.store.connection() as conn:
                techniques = conn.execute(
                    "SELECT DISTINCT e.external_id, e.name, e.url, e.details -> 'tactics' AS tactics "
                    "FROM relationships r JOIN entities e ON e.id = r.target_id "
                    "WHERE r.source_id = %s AND r.type = 'uses' AND e.kind = 'technique' ORDER BY e.external_id",
                    (entity_id,),
                ).fetchall()
                mitigations = conn.execute(
                    "SELECT m.external_id, m.name, m.url, count(DISTINCT used.target_id) AS covers "
                    "FROM relationships used "
                    "JOIN relationships mit ON mit.target_id = used.target_id AND mit.type = 'mitigates' "
                    "JOIN entities m ON m.id = mit.source_id "
                    "WHERE used.source_id = %s AND used.type = 'uses' AND NOT (m.external_id = ANY(%s)) "
                    "GROUP BY m.external_id, m.name, m.url ORDER BY covers DESC, m.external_id LIMIT %s",
                    (entity_id, NOT_SPECIFIC_DEFENSES, MAX_MITIGATIONS),
                ).fetchall()
                return techniques, mitigations

        techniques, mitigations = await asyncio.to_thread(run)
        refs = [TechniqueRef(external_id=t["external_id"], name=t["name"], url=t["url"],
                             tactics=[x["name"] for x in (t["tactics"] or [])]) for t in techniques]
        counts: dict[str, int] = {}
        for ref in refs:
            for tactic in ref.tactics:
                counts[tactic] = counts.get(tactic, 0) + 1
        return ThreatProfile(
            entity=view.entity, related=view.related, techniques=refs,
            tactics=[TacticCount(name=n, count=c) for n, c in sorted(counts.items(), key=lambda x: (-x[1], x[0]))],
            mitigations=[MitigationCoverage(**m) for m in mitigations],
        )


def _entity(row: dict) -> Entity:
    return Entity(id=row["id"], kind=row["kind"], external_id=row["external_id"], name=row["name"],
                  aliases=list(row["aliases"] or []), description=row["description"], url=row["url"],
                  source=row["source"], details=row["details"] or {})


def _group(links: list[dict]) -> list[RelatedGroup]:
    groups: dict[tuple, list[EntitySummary]] = {}
    for link in links:
        key = (link["direction"], link["type"], link["kind"])
        if key not in LABEL_ORDER:
            continue
        groups.setdefault(key, []).append(
            EntitySummary(external_id=link["external_id"], name=link["name"], kind=link["kind"], url=link["url"]))
    result = []
    for key in sorted(groups, key=lambda k: LABEL_ORDER[k][0]):
        items = sorted({(i.external_id or "", i.name): i for i in groups[key]}.values(),
                       key=lambda i: (i.external_id or "", i.name))
        result.append(RelatedGroup(label=LABEL_ORDER[key][1], relationship=key[1], items=items))
    return result
