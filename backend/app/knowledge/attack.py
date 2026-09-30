"""Reads MITRE ATT&CK's official STIX file and turns it into entities and relationships.

What's kept: techniques (with sub-techniques), tactics, threat groups, malware, tools,
campaigns, and mitigations, plus the relationships between them.

What's skipped:
- entries MITRE has retired ("revoked") or deprecated; retired IDs become redirects instead
- detection strategies and analytics, which ThreatLens doesn't use yet
"""
import re

from app.knowledge.models import ATTACK_KINDS, Entity, Redirect, Relationship

SOURCE = "mitre-attack"
DOWNLOAD_URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
                "enterprise-attack/enterprise-attack.json")
KEPT_RELATIONSHIPS = {"uses", "mitigates", "subtechnique-of", "attributed-to"}
MAX_REFERENCES = 25

CITATION = re.compile(r"\s*\(Citation:[^)]*\)")
MARKDOWN_LINK = re.compile(r"\[([^\]]+)\]\((https?://[^)]+)\)")


def clean_text(text: str | None) -> str:
    """Make ATT&CK's description text readable.

    - "[Mimikatz](https://attack.mitre.org/software/S0002)" becomes "Mimikatz"
    - "(Citation: Some Report 2024)" markers are removed
    - <code>...</code> becomes `...`, so commands stay recognizable

    Other angle brackets are left alone on purpose: commands contain placeholders
    like "net user <username>", and removing them would change their meaning.
    """
    if not text:
        return ""
    text = MARKDOWN_LINK.sub(r"\1", text)
    text = CITATION.sub("", text)
    text = re.sub(r"</?code>", "`", text)
    text = re.sub(r"</?b>", "", text)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _is_live(obj: dict) -> bool:
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def _attack_ref(obj: dict) -> dict:
    return next((r for r in obj.get("external_references", []) if r.get("source_name") == SOURCE), {})


def _aliases(obj: dict) -> list[str]:
    names = obj.get("aliases") or obj.get("x_mitre_aliases") or []
    return [a for a in dict.fromkeys(names) if a and a != obj.get("name")]


def _references(obj: dict) -> list[dict]:
    refs = []
    for r in obj.get("external_references", []):
        if r.get("source_name") == SOURCE or not r.get("url"):
            continue
        refs.append({"title": r.get("source_name"), "url": r["url"]})
    return refs[:MAX_REFERENCES]


def parse_bundle(bundle: dict) -> tuple[str | None, list[Entity], list[Relationship], list[Redirect]]:
    """Returns (ATT&CK version, entities, relationships, redirects)."""
    objects = bundle.get("objects", [])
    by_id = {o["id"]: o for o in objects if "id" in o}

    version = next((o.get("x_mitre_version") for o in objects if o.get("type") == "x-mitre-collection"), None)
    tactics = {o.get("x_mitre_shortname"): {"id": _attack_ref(o).get("external_id"), "name": o["name"]}
               for o in objects if o.get("type") == "x-mitre-tactic" and _is_live(o)}

    entities: list[Entity] = []
    for obj in objects:
        kind = ATTACK_KINDS.get(obj.get("type"))
        if not kind or not _is_live(obj):
            continue
        ref = _attack_ref(obj)
        details: dict = {"references": _references(obj), "version": obj.get("x_mitre_version"),
                         "modified": obj.get("modified")}
        if kind == "technique":
            details["is_subtechnique"] = bool(obj.get("x_mitre_is_subtechnique"))
            details["platforms"] = obj.get("x_mitre_platforms", [])
            details["tactics"] = [tactics[p["phase_name"]] for p in obj.get("kill_chain_phases", [])
                                  if p.get("kill_chain_name") == SOURCE and p.get("phase_name") in tactics]
        elif kind in ("malware", "tool"):
            details["platforms"] = obj.get("x_mitre_platforms", [])
        elif kind == "campaign":
            details["first_seen"] = obj.get("first_seen")
            details["last_seen"] = obj.get("last_seen")
        elif kind == "tactic":
            details["shortname"] = obj.get("x_mitre_shortname")
        entities.append(Entity(
            id=obj["id"], kind=kind, external_id=ref.get("external_id"), name=obj["name"],
            aliases=_aliases(obj), description=clean_text(obj.get("description")),
            url=ref.get("url"), source=SOURCE, details=details,
        ))

    kept = {e.id for e in entities}
    relationships = [
        Relationship(id=o["id"], source_id=o["source_ref"], target_id=o["target_ref"],
                     type=o["relationship_type"], description=clean_text(o.get("description")), source=SOURCE)
        for o in objects
        if o.get("type") == "relationship" and _is_live(o)
        and o.get("relationship_type") in KEPT_RELATIONSHIPS
        and o.get("source_ref") in kept and o.get("target_ref") in kept
    ]

    # A retired ID (e.g. an old group merged into another) should still lead somewhere useful
    replaced_by = {o["source_ref"]: o["target_ref"] for o in objects
                   if o.get("type") == "relationship" and o.get("relationship_type") == "revoked-by"}
    redirects = []
    for o in objects:
        if o.get("type") != "relationship" or o.get("relationship_type") != "revoked-by":
            continue
        old = by_id.get(o["source_ref"])
        old_id = _attack_ref(old).get("external_id") if old else None
        target = _follow_revocations(o["target_ref"], replaced_by, kept)
        if old_id and target:
            redirects.append(Redirect(old_external_id=old_id, entity_id=target, source=SOURCE))
    return version, entities, relationships, _unique_redirects(redirects)


def _follow_revocations(entity_id: str, replaced_by: dict[str, str], kept: set[str]) -> str | None:
    """Follow a chain of replacements (A replaced by B, B replaced by C) to a live entry."""
    seen = set()
    while entity_id not in kept:
        if entity_id in seen or entity_id not in replaced_by:
            return None
        seen.add(entity_id)
        entity_id = replaced_by[entity_id]
    return entity_id


def _unique_redirects(redirects: list[Redirect]) -> list[Redirect]:
    return list({r.old_external_id: r for r in redirects}.values())
