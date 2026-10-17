"""Exports: a report or a whole bulk lookup as STIX 2.1 or CSV.

STIX 2.1 is the standard format security tools use to share threat intelligence (OpenCTI, MISP,
Microsoft Sentinel, many SIEMs and threat intelligence platforms read it). A STIX file is a
"bundle" of objects and the relationships between them:

    indicator  45.95.147.236  --indicates-->  malware  Mirai
    intrusion-set  Volt Typhoon  --uses-->  attack-pattern  T1003.001 LSASS Memory
    intrusion-set  Magic Hound  --targets-->  vulnerability  CVE-2021-44228

plus a "report" that lists everything ThreatLens found, with its verdict and summary.

What goes in, by plain rules:
  - the investigated item: an indicator with a STIX pattern (IP, domain, file hash), a vulnerability
    (CVE), or the ATT&CK entry itself (threat profile)
  - threats linked to it (from the Connections graph: exact ATT&CK matches only)
  - ATT&CK techniques *reported* for it (the solid ones on the ATT&CK map). Techniques that only
    linked threats are known for are left out: they describe those threats, not this indicator.

IDs are deterministic (UUIDv5), so exporting the same thing twice gives the same IDs and a
platform that imports both can merge them. Everything is marked TLP:WHITE: it comes from
public sources and may be shared freely.

CSV is for spreadsheets. Cells that start with = + - @ are prefixed with ' so a spreadsheet never
runs them as formulas (CSV injection), since some values come from outside sources.
"""
import csv
import io
import json
import uuid
from datetime import datetime, timezone

from app.attack_map import build_attack_map
from app.config import Settings
from app.graph import connections
from app.models import IndicatorType, Investigation, SourceStatus

# A fixed namespace for ThreatLens's object IDs, so the same thing always gets the same ID
NAMESPACE = uuid.UUID("5f1f8a52-3c4e-4c1a-9f0e-7d2b8a6e4c31")
# STIX's own namespace for observable IDs (STIX 2.1 spec, section 2.9)
SCO_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
TLP_WHITE = {
    "type": "marking-definition", "spec_version": "2.1",
    "id": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "created": "2017-01-20T00:00:00.000Z", "definition_type": "tlp", "name": "TLP:WHITE",
    "definition": {"tlp": "white"},
}
REFERENCE_CREATED = "2017-05-31T21:30:00.000Z"  # for MITRE reference objects, which don't change per investigation
IDENTITY = {
    "type": "identity", "spec_version": "2.1", "id": f"identity--{uuid.uuid5(NAMESPACE, 'identity|ThreatLens')}",
    "created": "2026-01-01T00:00:00.000Z", "modified": "2026-01-01T00:00:00.000Z",
    "name": "ThreatLens", "identity_class": "system",
    "description": "ThreatLens, an explainable threat intelligence agent. Scores come from a published formula, not AI.",
}
STIX_KIND = {"group": "intrusion-set", "malware": "malware", "tool": "tool", "campaign": "campaign",
             "technique": "attack-pattern"}
HASH_NAMES = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256"}
CONFIDENCE = {"high": 85, "medium": 60, "low": 30}  # STIX confidence is 0-100
INDICATOR_TYPES = {"CRITICAL": "malicious-activity", "HIGH": "malicious-activity", "MEDIUM": "anomalous-activity",
                   "LOW": "benign", "UNKNOWN": "unknown"}
MAX_DESCRIPTION = 1500


def stix_id(kind: str, key: str) -> str:
    return f"{kind}--{uuid.uuid5(NAMESPACE, f'{kind}|{key}')}"


def timestamp(value: datetime) -> str:
    value = value.astimezone(timezone.utc)
    return value.strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond // 1000:03d}Z"


def site_url(settings: Settings) -> str | None:
    """Where the website lives, for "open this report" links inside exports."""
    if settings.public_site_url:
        return settings.public_site_url.rstrip("/")
    for origin in settings.cors_origin_list:
        if origin.startswith("https://"):
            return origin
    return None


def _quote(value: str) -> str:
    """A string inside a STIX pattern: backslashes and quotes escaped."""
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _short(text: str | None, limit: int = MAX_DESCRIPTION) -> str:
    text = " ".join(str(text or "").split())
    return text if len(text) <= limit else text[:limit - 1].rsplit(" ", 1)[0] + "…"


class _Bundle:
    def __init__(self) -> None:
        self.objects: dict[str, dict] = {}

    def add(self, obj: dict) -> str:
        if obj["id"] not in self.objects:
            self.objects[obj["id"]] = obj
        return obj["id"]

    def sdo(self, kind: str, key: str, created: str, **props) -> str:
        obj = {"type": kind, "spec_version": "2.1", "id": stix_id(kind, key), "created": created, "modified": created,
               "created_by_ref": IDENTITY["id"], "object_marking_refs": [TLP_WHITE["id"]]}
        obj.update({k: v for k, v in props.items() if v not in (None, "", [], {})})
        return self.add(obj)

    def relate(self, source: str, kind: str, target: str, created: str, description: str = "") -> str:
        return self.sdo("relationship", f"{source}|{kind}|{target}", created, relationship_type=kind,
                        source_ref=source, target_ref=target, description=description)

    def bundle(self) -> dict:
        objects = [TLP_WHITE, IDENTITY, *self.objects.values()]
        return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


def _observable(indicator) -> tuple[str, dict] | None:
    """The STIX pattern and the matching observable (SCO) for an IP, domain or hash."""
    value = indicator.value
    if indicator.type == IndicatorType.IP:
        kind = "ipv6-addr" if indicator.subtype == "ipv6" else "ipv4-addr"
        props = {"value": value}
        pattern = f"[{kind}:value = '{_quote(value)}']"
    elif indicator.type == IndicatorType.DOMAIN:
        kind, props = "domain-name", {"value": value}
        pattern = f"[domain-name:value = '{_quote(value)}']"
    elif indicator.type == IndicatorType.HASH:
        algorithm = HASH_NAMES[indicator.subtype]
        kind, props = "file", {"hashes": {algorithm: value}}
        pattern = f"[file:hashes.'{algorithm}' = '{_quote(value)}']"
    else:
        return None
    # STIX 2.1 observables get IDs from their own content (UUIDv5 over the canonical JSON)
    canonical = json.dumps(props, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    sco = {"type": kind, "spec_version": "2.1", "id": f"{kind}--{uuid.uuid5(SCO_NAMESPACE, canonical)}", **props}
    return pattern, sco


def _attack_object(bundle: _Bundle, kind: str, external_id: str, name: str, url: str | None,
                   description: str = "", aliases: list[str] | None = None) -> str | None:
    stix_kind = STIX_KIND.get(kind)
    if not stix_kind:
        return None
    props = {"name": name, "description": _short(description),
             "external_references": [{"source_name": "mitre-attack", "external_id": external_id,
                                      **({"url": url} if url else {})}]}
    if aliases and stix_kind in ("intrusion-set", "campaign", "malware", "tool"):
        props["aliases"] = [a for a in aliases if a != name][:20]
    if stix_kind == "malware":
        props["is_family"] = True
    return bundle.sdo(stix_kind, external_id.upper(), REFERENCE_CREATED, **props)


def _split_label(label: str) -> tuple[str, str | None]:
    """'Volt Typhoon (G1017)' -> ('Volt Typhoon', 'G1017'); 'Campaign C0017' -> ('Campaign C0017', None)."""
    if label.endswith(")") and " (" in label:
        name, _, rest = label.rpartition(" (")
        return name, rest[:-1]
    return label, None


async def _add_investigation(bundle: _Bundle, investigation: Investigation, store, settings: Settings) -> str:
    """Adds one investigation's objects to the bundle. Returns the id of its main object."""
    created = timestamp(investigation.created_at)
    verdict = investigation.verdict
    indicator = investigation.indicator
    site = site_url(settings)
    report_ref = ([{"source_name": "ThreatLens", "url": f"{site}/i/{investigation.id}",
                    "description": "The full ThreatLens report, with every source and decision step"}]
                  if site and investigation.id else [])
    profile = investigation.threat.profile if investigation.threat and investigation.threat.profile else None
    scored = verdict.level not in ("PROFILE",)
    extra = {"x_threatlens_level": verdict.level, **({"x_threatlens_score": verdict.score} if scored else {})}
    main = None

    if profile:
        entity = profile.entity
        if entity.kind == "weakness":
            main = None  # CWE has no STIX object type; the report carries it as a reference
        else:
            main = _attack_object(bundle, entity.kind, entity.external_id, entity.name, entity.url,
                                  entity.description, entity.aliases)
    elif indicator.type == IndicatorType.CVE:
        nvd = next((s.facts for s in investigation.sources if s.source == "NVD" and s.status == SourceStatus.OK), {})
        refs = [{"source_name": "cve", "external_id": indicator.value}]
        for weakness in nvd.get("weaknesses") or []:
            cwe = str(weakness).split(" ", 1)[0]
            refs.append({"source_name": "cwe", "external_id": cwe,
                         "url": f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html"})
        published = nvd.get("published")
        vuln_created = REFERENCE_CREATED
        if published:
            try:
                vuln_created = timestamp(datetime.fromisoformat(published).replace(tzinfo=timezone.utc))
            except ValueError:
                pass
        main = bundle.sdo("vulnerability", indicator.value, vuln_created, name=indicator.value,
                          description=_short(nvd.get("description")), external_references=refs)
    else:
        found = _observable(indicator)
        if found:
            pattern, sco = found
            main = bundle.sdo(
                "indicator", investigation.id or indicator.value, created,
                name=indicator.value, description=verdict.headline, pattern=pattern, pattern_type="stix",
                pattern_version="2.1", valid_from=created, indicator_types=[INDICATOR_TYPES.get(verdict.level, "unknown")],
                confidence=CONFIDENCE.get(verdict.confidence, 30), labels=[verdict.level.lower()],
                external_references=report_ref, **extra)
            bundle.add(sco)
            bundle.relate(main, "based-on", sco["id"], created)

    # Linked threats from the Connections graph (exact ATT&CK matches only)
    graph = await connections(investigation, store)
    for node in graph.nodes:
        # Techniques come in through the ATT&CK map below, which says how strong each one is
        if node.id == "subject" or node.kind not in STIX_KIND or node.kind == "technique":
            continue
        if node.id.startswith("id:"):
            name, external_id = _split_label(node.label)
            linked = _attack_object(bundle, node.kind, external_id or node.id[3:], name, node.link)
        elif node.kind in ("malware", "group"):
            # A family or group name from a feed that isn't in ATT&CK: still worth sharing, by name
            props = {"name": node.label, "description": f"Reported by {', '.join(node.seen_in)}." if node.seen_in else ""}
            if node.kind == "malware":
                props["is_family"] = True
            linked = bundle.sdo(STIX_KIND[node.kind], f"name|{node.label.lower()}", REFERENCE_CREATED, **props)
        else:
            continue
        if not linked or not main or linked == main:
            continue
        how = f"Linked by ThreatLens through {', '.join(node.seen_in)}." if node.seen_in else ""
        if indicator.type == IndicatorType.CVE and not profile:
            if node.kind in ("group", "campaign", "malware", "tool"):
                bundle.relate(linked, "targets", main, REFERENCE_CREATED, how)
        elif profile:
            kind = "uses" if node.kind in ("malware", "tool") and profile.entity.kind in ("group", "campaign") else "related-to"
            bundle.relate(main, kind, linked, REFERENCE_CREATED, how)
        elif node.kind in ("group", "malware", "campaign", "tool"):
            bundle.relate(main, "indicates", linked, created, how)

    # Techniques reported for this item (the solid ones on the ATT&CK map)
    attack = await build_attack_map(investigation, store)
    for tactic in attack.tactics:
        for technique in tactic.techniques:
            if technique.strength != "reported":
                continue
            pattern_id = _attack_object(bundle, "technique", technique.external_id, technique.name, technique.url)
            if not main or pattern_id == main:
                continue
            why = technique.evidence[0].text if technique.evidence else ""
            if profile and profile.entity.kind in ("group", "malware", "tool", "campaign"):
                bundle.relate(main, "uses", pattern_id, REFERENCE_CREATED, why)
            elif not profile and indicator.type != IndicatorType.CVE:
                bundle.relate(main, "indicates", pattern_id, created, why)

    return main


def _report_text(investigation: Investigation) -> str:
    verdict = investigation.verdict
    parts = [verdict.headline]
    if verdict.level != "PROFILE":
        parts.append(f"ThreatLens score {verdict.score}/100 ({verdict.level}, {verdict.confidence} confidence), "
                     "from a published formula: " + "; ".join(f"{s.label} ({s.points:+d}, {s.source})"
                                                           for s in investigation.signals) + ".")
    report = investigation.report
    if report and report.status == "ready" and report.summary:
        parts.append(f"AI summary (explains the score, never sets it): {report.summary}")
    return "\n\n".join(parts)


def _report_type(indicator_type: IndicatorType, entity) -> str:
    """STIX's suggested report types: what the report is mainly about."""
    if indicator_type == IndicatorType.CVE:
        return "vulnerability"
    if indicator_type != IndicatorType.THREAT:
        return "indicator"
    kind = entity.kind if entity else None
    return {"group": "threat-actor", "campaign": "campaign", "technique": "attack-pattern",
            "malware": "malware", "tool": "tool"}.get(kind, "threat-report")


async def investigation_stix(investigation: Investigation, store, settings: Settings) -> dict:
    bundle = _Bundle()
    await _add_investigation(bundle, investigation, store, settings)
    refs = list(bundle.objects)
    entity = investigation.threat.profile.entity if investigation.threat and investigation.threat.profile else None
    created = timestamp(investigation.created_at)
    site = site_url(settings)
    refs_out = [{"source_name": "ThreatLens", "url": f"{site}/i/{investigation.id}"}] if site and investigation.id else []
    if entity and entity.kind == "weakness":
        refs_out.append({"source_name": "cwe", "external_id": entity.external_id, "url": entity.url})
    bundle.sdo("report", f"report|{investigation.id or investigation.indicator.value}", created,
               name=f"ThreatLens: {investigation.indicator.value}", description=_report_text(investigation),
               published=created, report_types=[_report_type(investigation.indicator.type, entity)],
               object_refs=refs or [IDENTITY["id"]], external_references=refs_out)
    return bundle.bundle()


async def batch_stix(batch: dict, investigations: list[Investigation], store, settings: Settings) -> dict:
    bundle = _Bundle()
    for investigation in investigations:
        await _add_investigation(bundle, investigation, store, settings)
    refs = list(bundle.objects) or [IDENTITY["id"]]
    created = batch["created_at"] if isinstance(batch["created_at"], str) else timestamp(batch["created_at"])
    created = timestamp(datetime.fromisoformat(str(created).replace("Z", "+00:00")))
    lines = [f"{r.get('value') or r['query']}: {r.get('level') or 'failed'}"
             + (f" {r['score']}/100" if r.get("score") is not None and r.get("level") not in ("PROFILE", "UNKNOWN") else "")
             + (f". {r['headline']}" if r.get("headline") else "") for r in batch["rows"]]
    site = site_url(settings)
    bundle.sdo("report", f"batch|{batch.get('id')}", created,
               name=f"ThreatLens bulk lookup ({len(batch['rows'])} indicators)",
               description=_short("\n".join(lines), 5000), published=created, report_types=["indicator"],
               object_refs=refs,
               external_references=[{"source_name": "ThreatLens", "url": f"{site}/b/{batch['id']}"}] if site and batch.get("id") else [])
    return bundle.bundle()


# ---------------------------------------------------------------- CSV

def _cell(value):
    """Spreadsheets run cells starting with = + - @ as formulas; text from outside sources must never do that."""
    if isinstance(value, (int, float)) or value is None:
        return "" if value is None else value
    text = " ".join(str(value).split())
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def _csv(header: list[str], rows: list[list]) -> str:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\r\n")
    writer.writerow(header)
    for row in rows:
        writer.writerow([_cell(v) for v in row])
    return "﻿" + out.getvalue()  # the BOM makes Excel read the file as UTF-8


async def investigation_csv(investigation: Investigation, store, settings: Settings) -> str:
    """One row per piece of evidence: the verdict, each signal, each source, each AI statement, each
    connection, and each ATT&CK technique."""
    verdict = investigation.verdict
    site = site_url(settings)
    rows = [["verdict", investigation.indicator.value, verdict.level, None if verdict.level == "PROFILE" else verdict.score,
             "ThreatLens", verdict.headline, f"{site}/i/{investigation.id}" if site else ""]]
    for s in investigation.signals:
        rows.append(["signal", s.label, "", s.points, s.source, s.evidence, ""])
    for s in investigation.sources:
        rows.append(["source", s.source, s.status.value, None, s.source, s.message or "", s.link or ""])
    report = investigation.report
    if report and report.status == "ready":
        names = {c.id: c.source for c in report.citations}
        for field, label in (("findings", "ai finding"), ("affected", "ai affected"), ("actions", "ai action")):
            for item in getattr(report, field):
                extra = f" ({item.priority})" if field == "actions" else ""
                rows.append([label, item.text, extra.strip(" ()"), None,
                             "; ".join(f"{c} {names.get(c, '')}".strip() for c in item.sources), "", ""])
    graph = await connections(investigation, store)
    for node in graph.nodes:
        if node.id != "subject":
            rows.append(["connection", node.label, node.kind, None, ", ".join(node.seen_in), node.detail or "",
                         node.link or ""])
    attack = await build_attack_map(investigation, store)
    for tactic in attack.tactics:
        for technique in tactic.techniques:
            rows.append(["attack technique", f"{technique.external_id} {technique.name}", technique.strength, None,
                         tactic.name, technique.evidence[0].text if technique.evidence else "", technique.url or ""])
    return _csv(["section", "item", "value", "points", "source", "detail", "link"], rows)


def batch_csv(batch: dict, settings: Settings) -> str:
    """One row per indicator in a bulk lookup."""
    site = site_url(settings)
    rows = []
    for r in batch["rows"]:
        rows.append([
            r.get("value") or r["query"], r["query"], r["type"], r.get("subtype") or "", r.get("level") or "",
            r.get("score") if r.get("level") not in ("PROFILE", None) else None, r.get("confidence") or "",
            r.get("headline") or "", " | ".join(r.get("top_signals") or []),
            r.get("sources_ok"), r.get("sources_total"), r.get("error") or "",
            f"{site}/i/{r['investigation_id']}" if site and r.get("investigation_id") else r.get("investigation_id") or "",
        ])
    return _csv(["indicator", "you_entered", "type", "subtype", "level", "score", "confidence", "headline",
                 "top_signals", "sources_answered", "sources_asked", "error", "report"], rows)
