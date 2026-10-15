"""Reads MITRE's CWE catalog (Common Weakness Enumeration) into the knowledge graph.

CWE names the kinds of mistakes that cause vulnerabilities: "CWE-79 Cross-site Scripting",
"CWE-89 SQL Injection", "CWE-502 Deserialization of Untrusted Data". NVD tags most CVEs
with one or more of them, so CWE explains *what kind of flaw* a CVE is.

What's kept: weaknesses (not categories or views), each with its alternate names,
description, how likely it is to be exploited, its consequences, how to prevent it,
and the platforms it affects. Relationships kept: "child of" (more specific than) and
"can precede" (can lead to), from CWE's main hierarchy (the Research Concepts view, 1000).

What's skipped: deprecated and obsolete weaknesses, and links to other views, which
would repeat the same parent-child relationships in different arrangements.

The file format follows MITRE's published schema (https://cwe.mitre.org/data/xsd/).
The parser ignores XML namespaces, so a new schema version with the same element names
still reads correctly.
"""
import io
import zipfile
import xml.etree.ElementTree as ET

from app.knowledge.models import Entity, Relationship

SOURCE = "mitre-cwe"
DOWNLOAD_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
MAIN_VIEW = "1000"  # Research Concepts: CWE's complete hierarchy
KEPT_NATURES = {"ChildOf": "childof", "CanPrecede": "can-precede"}
SKIPPED_STATUSES = {"Deprecated", "Obsolete"}
MAX_MITIGATIONS = 6
MAX_TEXT = 600


def _tag(element: ET.Element) -> str:
    """Element name without its namespace: '{http://cwe.mitre.org/cwe-7}Weakness' -> 'Weakness'."""
    return element.tag.rsplit("}", 1)[-1]


def _child(element: ET.Element, name: str) -> ET.Element | None:
    return next((c for c in element if _tag(c) == name), None)


def _children(element: ET.Element | None, name: str) -> list[ET.Element]:
    return [c for c in element if _tag(c) == name] if element is not None else []


def _text(element: ET.Element | None, limit: int | None = None) -> str:
    """All text inside an element, including inside XHTML paragraphs and lists, as one clean string."""
    if element is None:
        return ""
    text = " ".join(" ".join(element.itertext()).split())
    if limit and len(text) > limit:
        text = text[:limit - 1].rsplit(" ", 1)[0] + "…"
    return text


def cwe_id(number: str | int) -> str:
    return f"CWE-{int(number)}"


def entity_id(number: str | int) -> str:
    return f"cwe--{int(number)}"


def read_file(data: bytes) -> bytes:
    """MITRE publishes the catalog as a zip with one XML file inside. Accept either form."""
    if data[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            name = next(n for n in archive.namelist() if n.lower().endswith(".xml"))
            return archive.read(name)
    return data


def _weakness(element: ET.Element) -> Entity:
    number = element.get("ID")
    aliases = [_text(_child(term, "Term")) for term in _children(_child(element, "Alternate_Terms"), "Alternate_Term")]

    consequences = []
    for consequence in _children(_child(element, "Common_Consequences"), "Consequence"):
        consequences.append({
            "scope": [_text(s) for s in _children(consequence, "Scope")],
            "impact": [_text(i) for i in _children(consequence, "Impact")],
        })

    mitigations = []
    for mitigation in _children(_child(element, "Potential_Mitigations"), "Mitigation")[:MAX_MITIGATIONS]:
        description = _text(_child(mitigation, "Description"), limit=MAX_TEXT)
        if description:
            mitigations.append({
                "phase": [_text(p) for p in _children(mitigation, "Phase")],
                "description": description,
                "effectiveness": _text(_child(mitigation, "Effectiveness")) or None,
            })

    platforms = []
    applicable = _child(element, "Applicable_Platforms")
    for platform in (list(applicable) if applicable is not None else []):
        label = platform.get("Name") or platform.get("Class")
        if label and label not in platforms and not label.startswith("Not "):
            platforms.append(label)

    description = _text(_child(element, "Description"))
    extended = _text(_child(element, "Extended_Description"), limit=MAX_TEXT * 2)
    return Entity(
        id=entity_id(number), kind="weakness", external_id=cwe_id(number), name=element.get("Name", "").strip(),
        aliases=[a for a in dict.fromkeys(aliases) if a],
        description=f"{description}\n\n{extended}".strip() if extended else description,
        url=f"https://cwe.mitre.org/data/definitions/{int(number)}.html", source=SOURCE,
        details={
            "abstraction": element.get("Abstraction"),  # Pillar, Class, Base, Variant, Compound
            "status": element.get("Status"),
            "likelihood_of_exploit": _text(_child(element, "Likelihood_Of_Exploit")) or None,
            "consequences": consequences,
            "mitigations": mitigations,
            "platforms": platforms[:12],
            "capec": [f"CAPEC-{p.get('CAPEC_ID')}"
                      for p in _children(_child(element, "Related_Attack_Patterns"), "Related_Attack_Pattern")],
        },
    )


def parse_catalog(xml: bytes) -> tuple[str | None, list[Entity], list[Relationship]]:
    """Returns (CWE version, weakness entities, relationships between them)."""
    root = ET.fromstring(xml)
    if _tag(root) != "Weakness_Catalog":
        raise ValueError("This doesn't look like MITRE's CWE catalog (no Weakness_Catalog element).")
    version = root.get("Version")

    elements = [w for w in _children(_child(root, "Weaknesses"), "Weakness")
                if w.get("ID") and w.get("Status") not in SKIPPED_STATUSES]
    entities = [_weakness(w) for w in elements]
    kept = {e.id for e in entities}

    relationships: dict[str, Relationship] = {}
    for element in elements:
        source_id = entity_id(element.get("ID"))
        for related in _children(_child(element, "Related_Weaknesses"), "Related_Weakness"):
            kind = KEPT_NATURES.get(related.get("Nature"))
            if not kind or related.get("View_ID") != MAIN_VIEW or not related.get("CWE_ID"):
                continue
            target_id = entity_id(related.get("CWE_ID"))
            if target_id not in kept or target_id == source_id:
                continue
            rel_id = f"cwe-rel--{source_id}--{kind}--{target_id}"
            relationships[rel_id] = Relationship(id=rel_id, source_id=source_id, target_id=target_id,
                                                 type=kind, source=SOURCE)
    return version, entities, list(relationships.values())

