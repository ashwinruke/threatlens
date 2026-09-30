"""Shapes for the threat knowledge graph.

An Entity is any "thing" in the graph: a technique, a threat group, a piece of malware...
A Relationship connects two entities: "APT29 uses Mimikatz", "Mimikatz uses T1003.001".
Later steps add ThreatLens's own entities (CVEs, IPs, hashes) to the same graph.
"""
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

# How ATT&CK's object types map to ThreatLens's plain names
ATTACK_KINDS = {
    "attack-pattern": "technique",
    "x-mitre-tactic": "tactic",
    "intrusion-set": "group",
    "malware": "malware",
    "tool": "tool",
    "campaign": "campaign",
    "course-of-action": "mitigation",
}


class Entity(BaseModel):
    id: str  # stable id; for ATT&CK objects, MITRE's own STIX id
    kind: str  # technique, tactic, group, malware, tool, campaign, mitigation
    external_id: str | None = None  # T1059.001, G1017, S0154...
    name: str
    aliases: list[str] = Field(default_factory=list)
    description: str = ""
    url: str | None = None
    source: str  # "mitre-attack"
    details: dict[str, Any] = Field(default_factory=dict)


class Relationship(BaseModel):
    id: str
    source_id: str
    target_id: str
    type: str  # uses, mitigates, subtechnique-of, attributed-to
    description: str = ""
    source: str


class Redirect(BaseModel):
    """An ID MITRE retired, pointing at the entry that replaced it."""

    old_external_id: str
    entity_id: str
    source: str


class EntitySummary(BaseModel):
    external_id: str | None
    name: str
    kind: str
    url: str | None


class RelatedGroup(BaseModel):
    label: str  # "Techniques used", "Used by groups", ...
    relationship: str
    items: list[EntitySummary]


class EntityView(BaseModel):
    """One entity with everything connected to it, ready for the API."""

    entity: Entity
    related: list[RelatedGroup]
    redirected_from: str | None = None


class KnowledgeStats(BaseModel):
    source: str
    version: str | None
    imported_at: datetime | None
    entities: dict[str, int]
    relationships: int
