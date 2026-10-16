"""The ATT&CK map: which attack techniques an investigation touches, stage by stage.

Analysts read MITRE ATT&CK as a sequence of stages (tactics): get in (Initial Access), run
code (Execution), stay in (Persistence), and so on, up to Impact. Under each stage sit the
techniques: the specific ways attackers do it.

Every technique on the map says why it's there, and how strong that link is:
  - reported:  a source named this technique for this indicator (AlienVault OTX community
               reports list techniques), or ATT&CK records the investigated threat using it
  - linked:    a threat linked to this investigation (a malware family a source reported, a
               group the research agent found) is known to use it. The indicator itself
               wasn't seen doing it, so it's context: "what to expect", not "what happened"

Built from the saved investigation by plain rules, never by AI. It also gives:
  - the defenses (ATT&CK mitigations) that cover the most mapped techniques
  - an ATT&CK Navigator layer file, so analysts can open the map in MITRE's own tool
"""
import asyncio
import re

from pydantic import BaseModel, Field

from app.graph import connections
from app.knowledge.repository import NOT_SPECIFIC_DEFENSES, KnowledgeRepository
from app.models import Investigation, IndicatorType, SourceStatus

# ATT&CK's Enterprise tactics, in the order of an attack. Names and short names come from the
# loaded ATT&CK data, because they change: v19 renamed Defense Evasion (TA0005) to Stealth and
# added Defense Impairment (TA0112). A tactic not listed here is added after Impact.
TACTIC_ORDER = ["TA0043", "TA0042", "TA0001", "TA0002", "TA0003", "TA0004", "TA0005", "TA0112",
                "TA0006", "TA0007", "TA0008", "TA0009", "TA0011", "TA0010", "TA0040"]
# A plain description of each stage, for people new to ATT&CK
STAGE_TEXT = {
    "TA0043": "Gathering information to plan the attack",
    "TA0042": "Setting up infrastructure, accounts and tools",
    "TA0001": "Getting into the network",
    "TA0002": "Running malicious code",
    "TA0003": "Keeping access after restarts or password changes",
    "TA0004": "Gaining higher permissions",
    "TA0005": "Staying hidden from defenders",
    "TA0112": "Switching off or weakening security tools",
    "TA0006": "Stealing passwords and keys",
    "TA0007": "Learning about the environment",
    "TA0008": "Moving to other systems",
    "TA0009": "Gathering the data they want",
    "TA0011": "Communicating with compromised systems",
    "TA0010": "Stealing the data",
    "TA0040": "Disrupting, destroying or encrypting",
}
THREAT_KINDS = {"group", "malware", "tool", "campaign"}
MAX_LINKED = 6  # linked threats whose techniques are included, closest first
MAX_DEFENSES = 8
TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


class Evidence(BaseModel):
    strength: str  # reported or linked
    text: str  # plain sentence: why this technique is on the map
    source: str  # where that came from: "AlienVault OTX", "MITRE ATT&CK", "Research R2"...


class MappedTechnique(BaseModel):
    external_id: str
    name: str
    url: str | None = None
    strength: str  # the strongest evidence: reported beats linked
    evidence: list[Evidence] = Field(default_factory=list)
    linked_threats: list[str] = Field(default_factory=list)  # names of linked threats known to use it


class TacticRow(BaseModel):
    id: str
    name: str
    shortname: str
    about: str  # what this stage means, in plain words
    techniques: list[MappedTechnique] = Field(default_factory=list)


class Defense(BaseModel):
    external_id: str | None
    name: str
    url: str | None
    covers: int  # how many of the mapped techniques it helps against


class LinkedThreat(BaseModel):
    external_id: str
    name: str
    kind: str
    found_by: list[str]  # which sources or research steps linked it
    techniques: int  # how many of its techniques are on the map


class AttackMap(BaseModel):
    investigation_id: str | None
    status: str  # ok, empty, unavailable
    tactics: list[TacticRow] = Field(default_factory=list)
    technique_count: int = 0
    reported_count: int = 0
    linked: list[LinkedThreat] = Field(default_factory=list)
    defenses: list[Defense] = Field(default_factory=list)
    attack_version: str | None = None
    notes: list[str] = Field(default_factory=list)


class _Collector:
    def __init__(self) -> None:
        self.techniques: dict[str, dict] = {}  # external id -> {"evidence": [...], "linked": [...]}

    def add(self, external_id: str, evidence: Evidence, linked_name: str | None = None) -> None:
        entry = self.techniques.setdefault(external_id.upper(), {"evidence": [], "linked": []})
        if not any(e.text == evidence.text for e in entry["evidence"]):
            entry["evidence"].append(evidence)
        if linked_name and linked_name not in entry["linked"]:
            entry["linked"].append(linked_name)


def _reported_ids(investigation: Investigation) -> list[str]:
    """Technique IDs the sources named for this indicator (today: AlienVault OTX)."""
    found = []
    for result in investigation.sources:
        if result.status != SourceStatus.OK:
            continue
        for technique in result.facts.get("attack_techniques") or []:
            match = TECHNIQUE_RE.search(str(technique))
            if match and match.group(0) not in found:
                found.append(match.group(0))
    return found


def _db(store, query: str, params: tuple) -> list[dict]:
    with store.connection() as conn:
        return conn.execute(query, params).fetchall()


async def _tactics(store) -> list[dict]:
    """ATT&CK's tactics, in attack order."""
    rows = await asyncio.to_thread(
        _db, store, "SELECT external_id, name, details ->> 'shortname' AS shortname FROM entities "
                    "WHERE kind = 'tactic' AND source = 'mitre-attack'", ())
    order = {tid: i for i, tid in enumerate(TACTIC_ORDER)}
    return sorted(rows, key=lambda r: (order.get(r["external_id"], len(order)), r["external_id"]))


async def _techniques_by_id(store, ids: list[str]) -> dict[str, dict]:
    if not ids:
        return {}
    rows = await asyncio.to_thread(
        _db, store, "SELECT external_id, name, url, details -> 'tactics' AS tactics FROM entities "
                    "WHERE kind = 'technique' AND upper(external_id) = ANY(%s)", ([i.upper() for i in ids],))
    return {row["external_id"].upper(): row for row in rows}


async def _techniques_used_by(store, ids: list[str]) -> list[dict]:
    """Techniques that ATT&CK records these groups, malware, tools or campaigns using."""
    if not ids:
        return []
    return await asyncio.to_thread(
        _db, store,
        "SELECT upper(s.external_id) AS by_id, t.external_id, t.name, t.url, t.details -> 'tactics' AS tactics "
        "FROM relationships r JOIN entities s ON s.id = r.source_id JOIN entities t ON t.id = r.target_id "
        "WHERE r.type = 'uses' AND t.kind = 'technique' AND upper(s.external_id) = ANY(%s)",
        ([i.upper() for i in ids],))


async def _defenses(store, technique_ids: list[str]) -> list[Defense]:
    if not technique_ids:
        return []
    rows = await asyncio.to_thread(
        _db, store,
        "SELECT m.external_id, m.name, m.url, count(DISTINCT t.id) AS covers "
        "FROM relationships r JOIN entities m ON m.id = r.source_id JOIN entities t ON t.id = r.target_id "
        "WHERE r.type = 'mitigates' AND m.kind = 'mitigation' AND upper(t.external_id) = ANY(%s) "
        "AND NOT (m.external_id = ANY(%s)) "
        "GROUP BY m.external_id, m.name, m.url ORDER BY covers DESC, m.external_id LIMIT %s",
        ([i.upper() for i in technique_ids], NOT_SPECIFIC_DEFENSES, MAX_DEFENSES))
    return [Defense(**row) for row in rows]


async def build_attack_map(investigation: Investigation, store) -> AttackMap:
    result = AttackMap(investigation_id=investigation.id, status="ok")
    if not hasattr(store, "connection"):
        result.status = "unavailable"
        result.notes.append("The ATT&CK map needs the knowledge base, which isn't connected.")
        return result

    collector = _Collector()
    details: dict[str, dict] = {}  # technique id -> row with name, url, tactics
    profile = investigation.threat.profile if investigation.threat and investigation.threat.profile else None
    subject_id = profile.entity.external_id.upper() if profile and profile.entity.external_id else None

    # 1. What the investigated item itself is recorded or reported doing
    if profile:
        entity = profile.entity
        if entity.kind in THREAT_KINDS:
            for row in await _techniques_used_by(store, [entity.external_id]):
                details[row["external_id"].upper()] = row
                collector.add(row["external_id"], Evidence(
                    strength="reported", source="MITRE ATT&CK",
                    text=f"ATT&CK records {entity.name} using this technique."))
        elif entity.kind == "technique":
            rows = await _techniques_by_id(store, [entity.external_id])
            details.update(rows)
            if rows:
                collector.add(entity.external_id, Evidence(
                    strength="reported", source="MITRE ATT&CK", text="This is the technique you looked up."))
        elif entity.kind == "weakness":
            result.notes.append("CWE weaknesses are kinds of software mistakes, and MITRE doesn't map them to "
                                "ATT&CK techniques. Investigate a CVE with this weakness to see how it's exploited.")
    elif investigation.indicator.type != IndicatorType.THREAT:
        reported = _reported_ids(investigation)
        rows = await _techniques_by_id(store, reported)
        details.update(rows)
        for technique in reported:
            if technique.upper() in rows:
                collector.add(technique, Evidence(
                    strength="reported", source="AlienVault OTX",
                    text="Named in AlienVault OTX community reports about this indicator."))
        missing = [t for t in reported if t.upper() not in rows]
        if missing:
            result.notes.append(f"{', '.join(missing)} {'is' if len(missing) == 1 else 'are'} not in the loaded "
                                "ATT&CK version (possibly retired), so not shown.")

    # 2. Techniques of threats linked to this investigation, closest first
    graph = await connections(investigation, store)
    threats = [n for n in graph.nodes if n.kind in THREAT_KINDS and n.id.startswith("id:")
               and n.id[3:] != subject_id]
    threats.sort(key=lambda n: (n.depth, -len(n.seen_in), n.label))
    if len(threats) > MAX_LINKED:
        result.notes.append(f"Techniques of the {MAX_LINKED} closest linked threats are included; "
                            f"{len(threats) - MAX_LINKED} more are in the Connections graph.")
        threats = threats[:MAX_LINKED]
    by_threat: dict[str, list[dict]] = {}
    for row in await _techniques_used_by(store, [n.id[3:] for n in threats]):
        by_threat.setdefault(row["by_id"], []).append(row)
    for node in threats:
        rows = by_threat.get(node.id[3:].upper(), [])
        where = ", ".join(node.seen_in) or "the investigation"
        name = node.label
        result.linked.append(LinkedThreat(external_id=node.id[3:], name=name, kind=node.kind,
                                          found_by=node.seen_in, techniques=len(rows)))
        for row in rows:
            details.setdefault(row["external_id"].upper(), row)
            collector.add(row["external_id"], Evidence(
                strength="linked", source=where,
                text=f"Used by {name}, linked to this investigation through {where}."), linked_name=name)

    # 3. Lay them out by stage
    rows_by_tactic = {}
    for tactic in await _tactics(store):
        rows_by_tactic[tactic["external_id"]] = TacticRow(
            id=tactic["external_id"], name=tactic["name"], shortname=tactic["shortname"] or "",
            about=STAGE_TEXT.get(tactic["external_id"], ""))
    other = TacticRow(id="other", name="Other", shortname="", about="Techniques without a listed stage")
    for technique_id, entry in collector.techniques.items():
        row = details.get(technique_id)
        if not row:
            continue
        strength = "reported" if any(e.strength == "reported" for e in entry["evidence"]) else "linked"
        mapped = MappedTechnique(external_id=row["external_id"], name=row["name"], url=row["url"], strength=strength,
                                 evidence=sorted(entry["evidence"], key=lambda e: e.strength != "reported"),
                                 linked_threats=entry["linked"])
        tactics = [t.get("id") for t in (row["tactics"] or [])]
        placed = False
        for tactic in tactics:
            if tactic in rows_by_tactic:
                rows_by_tactic[tactic].techniques.append(mapped)
                placed = True
        if not placed:
            other.techniques.append(mapped)

    result.tactics = list(rows_by_tactic.values()) + ([other] if other.techniques else [])
    for tactic in result.tactics:
        tactic.techniques.sort(key=lambda t: (t.strength != "reported", -len(t.linked_threats), t.external_id))
    mapped_ids = [i for i in collector.techniques if i in details]
    result.technique_count = len(mapped_ids)
    result.reported_count = sum(1 for i in mapped_ids
                                if any(e.strength == "reported" for e in collector.techniques[i]["evidence"]))
    result.defenses = await _defenses(store, mapped_ids)
    stats = await KnowledgeRepository(store).stats("mitre-attack")
    result.attack_version = stats.version if stats else None
    if not mapped_ids:
        result.status = "empty"
        if not result.notes:
            result.notes.append("No source reported attack techniques for this, and no threat linked to it "
                                "has techniques recorded in ATT&CK.")
    elif result.reported_count == 0:
        result.notes.append("Every technique here comes from linked threats: it shows what those threats are known "
                            "to do, not something this indicator was seen doing.")
    return result


def navigator_layer(attack_map: AttackMap, title: str) -> dict:
    """An ATT&CK Navigator layer (format 4.5): open https://mitre-attack.github.io/attack-navigator/,
    choose "Open Existing Layer", and upload this file.

    Score: 3 for a reported technique, plus 1 for each linked threat known to use it.
    """
    techniques, top = [], 1
    for tactic in attack_map.tactics:
        if not tactic.shortname:
            continue
        for technique in tactic.techniques:
            score = (3 if technique.strength == "reported" else 0) + len(technique.linked_threats)
            top = max(top, score)
            techniques.append({
                "techniqueID": technique.external_id, "tactic": tactic.shortname, "score": score, "color": "",
                "comment": "\n".join(f"{e.text} ({e.source})" for e in technique.evidence),
                "enabled": True, "showSubtechniques": "." in technique.external_id,
            })
    major = (attack_map.attack_version or "").split(".")[0] or None
    layer = {
        "name": f"ThreatLens: {title}"[:120],
        "versions": {"navigator": "5.1.0", "layer": "4.5", **({"attack": major} if major else {})},
        "domain": "enterprise-attack",
        "description": "Techniques ThreatLens mapped for this investigation. Score: 3 if a source reported the "
                       "technique or ATT&CK records the threat using it, plus 1 per linked threat known to use it.",
        "techniques": techniques,
        "gradient": {"colors": ["#fde9c4", "#f0b34a", "#e36b5d"], "minValue": 0, "maxValue": top},
        "legendItems": [{"label": "Reported", "color": "#e36b5d"}, {"label": "Linked threats only", "color": "#fde9c4"}],
        "metadata": [{"name": "Made with", "value": "ThreatLens"}],
        "sortTechniques": 3, "hideDisabled": False, "selectSubtechniquesWithParent": False,
    }
    return layer
