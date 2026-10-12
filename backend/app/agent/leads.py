"""Leads: concrete things in the evidence that are worth following up.

Found by plain rules, not AI, so the agent starts from facts the sources actually reported:
malware family names, threat groups, ATT&CK techniques, and CVEs. Without leads, the agent
doesn't run at all, which saves free AI quota on results with nothing to explore.
"""
import asyncio
import re

from app.models import Investigation, IndicatorType, SourceStatus

MAX_LEADS = 10
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
# VirusTotal and others sometimes report placeholders rather than real family names
NOT_FAMILIES = {"", "generic", "unknown", "malware", "trojan", "other", "none", "n/a", "unnamed malware"}


def _facts(investigation: Investigation, source: str) -> dict:
    for result in investigation.sources:
        if result.source == source and result.status == SourceStatus.OK:
            return result.facts
    return {}


def _add(leads: list[str], seen: set[str], value, what: str, where: str) -> None:
    text = " ".join(str(value or "").split())
    if not text or text.lower() in NOT_FAMILIES or text.lower() in seen or len(text) > 80:
        return
    seen.add(text.lower())
    leads.append(f"{text} ({what}, from {where})")


def from_evidence(investigation: Investigation) -> list[str]:
    """Leads in the source facts of a CVE, IP, domain, or hash investigation."""
    leads: list[str] = []
    seen: set[str] = {investigation.indicator.value.lower()}

    if investigation.indicator.type == IndicatorType.CVE:
        leads.append(f"{investigation.indicator.value} (the CVE itself: which groups or campaigns exploited it?)")
        kev = _facts(investigation, "CISA KEV")
        if kev.get("product"):
            _add(leads, seen, f"{kev.get('vendor', '')} {kev['product']}", "affected product", "CISA KEV")

    bazaar = _facts(investigation, "MalwareBazaar")
    _add(leads, seen, bazaar.get("malware_family"), "malware family", "MalwareBazaar")
    for family in _facts(investigation, "ThreatFox").get("malware_families", []):
        _add(leads, seen, family, "malware family", "ThreatFox")
    vt = _facts(investigation, "VirusTotal")
    for family in vt.get("family_names", []) or []:
        _add(leads, seen, family, "malware family", "VirusTotal")
    otx = _facts(investigation, "AlienVault OTX")
    for family in otx.get("malware_families", []):
        _add(leads, seen, family, "malware family", "AlienVault OTX")
    for adversary in otx.get("adversaries", []):
        _add(leads, seen, adversary, "threat actor", "AlienVault OTX")
    for technique in otx.get("attack_techniques", []):
        match = TECHNIQUE_RE.search(str(technique))
        if match:
            _add(leads, seen, match.group(0), "ATT&CK technique", "AlienVault OTX")
    return leads[:MAX_LEADS]


async def from_profile(investigation: Investigation, store) -> list[str]:
    """Leads for a threat profile: CVEs its ATT&CK record says it exploited, and its software."""
    profile = investigation.threat.profile
    leads: list[str] = []
    seen: set[str] = {profile.entity.name.lower()}
    for cve in await cves_mentioned(store, profile.entity.id, profile.entity.description):
        _add(leads, seen, cve, "CVE named in its ATT&CK record", "MITRE ATT&CK")
    for group in profile.related:
        if group.label in ("Malware used", "Campaigns attributed to this group", "Attributed to"):
            for item in group.items[:3]:
                _add(leads, seen, f"{item.external_id} {item.name}", group.label.lower(), "MITRE ATT&CK")
    return leads[:MAX_LEADS]


async def cves_mentioned(store, entity_id: str, description: str) -> list[str]:
    """CVE IDs in an entity's ATT&CK description and in its relationship descriptions."""
    found = {c.upper() for c in CVE_RE.findall(description or "")}
    if hasattr(store, "connection"):
        def run():
            with store.connection() as conn:
                return conn.execute(
                    "SELECT description FROM relationships WHERE source_id = %s AND description ~* 'CVE-[0-9]{4}-[0-9]+'",
                    (entity_id,),
                ).fetchall()
        for row in await asyncio.to_thread(run):
            found.update(c.upper() for c in CVE_RE.findall(row["description"]))
    return sorted(found)
