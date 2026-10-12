"""Investigating a threat by name: "Volt Typhoon", "LockBit", "Cozy Bear", "G1017".

1. Search the ATT&CK knowledge base (Step 2's search)
2. Decide whether one entry clearly matches, several could, or none does
3. Build a profile of the match: software, techniques by tactic, campaigns, best defenses
4. Package it so the AI report writer can cite it, like any other source

A threat name gets a profile, not a risk score. How dangerous Volt Typhoon is depends on
whether it targets you, which ThreatLens can't know, so inventing a number would be dishonest.
"""
from app.knowledge.models import SearchResult, ThreatLookup, ThreatProfile
from app.knowledge.repository import KnowledgeRepository
from app.knowledge.search import search
from app.models import Indicator, SourceResult, SourceStatus, Verdict

THREAT_KINDS = ["group", "malware", "tool", "campaign", "technique"]
EXACT_SCORE = 190  # exact ID, name, or alias (see knowledge/search.py)
CLOSE_SCORE = 45  # a spelling match at least this good can be accepted...
CLEAR_LEAD = 10  # ...if it's clearly ahead of the next one
MAX_CANDIDATES = 5
MIN_CANDIDATE_SCORE = 30  # below this, or matched only by scattered description words, it's noise
MAX_TECHNIQUES_FOR_AI = 40

KIND_PHRASES = {"group": "a threat group", "malware": "malware", "tool": "a tool attackers use",
                "campaign": "a campaign", "technique": "an attack technique"}


def useful(results: list[SearchResult]) -> list[SearchResult]:
    """Drop weak matches, so "zzqq unknown gang" finds nothing instead of anything with "unknown" in it."""
    return [r for r in results if r.score >= EXACT_SCORE
            or (r.matched_on != "some description words" and r.score >= MIN_CANDIDATE_SCORE)]


def choose(results: list[SearchResult]) -> tuple[str, SearchResult | None]:
    """matched / ambiguous / not_found, and the chosen result if there is one.

    An exact match always wins. A spelling match wins only if it's good and clearly ahead,
    so "cobalt" (Cobalt Strike or Cobalt Group?) asks instead of guessing. Matches based only
    on description words are never picked automatically: a name search deserves a name match.
    """
    if not results:
        return "not_found", None
    top = results[0]
    if top.score >= EXACT_SCORE:
        return "matched", top
    second = results[1].score if len(results) > 1 else 0
    if top.matched_on.startswith("similar") and top.score >= CLOSE_SCORE and top.score - second >= CLEAR_LEAD:
        return "matched", top
    return "ambiguous", None


async def look_up(indicator: Indicator, store) -> ThreatLookup:
    if not hasattr(store, "connection"):
        return ThreatLookup(query=indicator.value, status="unavailable")
    results = useful(await search(store, indicator.value, THREAT_KINDS, limit=MAX_CANDIDATES + 3))
    status, chosen = choose(results)
    if not chosen:
        return ThreatLookup(query=indicator.value, status=status, candidates=results[:MAX_CANDIDATES])
    profile = await KnowledgeRepository(store).profile(chosen.external_id)
    others = [r for r in results if r.external_id != chosen.external_id][:MAX_CANDIDATES - 1]
    return ThreatLookup(query=indicator.value, status="matched", matched_on=chosen.matched_on,
                        candidates=others, profile=profile)


def _plural(n: int, word: str, plural: str | None = None) -> str:
    return f"{n} {word if n == 1 else plural or word + 's'}"


def _join(parts: list[str]) -> str:
    return parts[0] if len(parts) == 1 else ", ".join(parts[:-1]) + " and " + parts[-1]


def _count(profile: ThreatProfile, label: str) -> int:
    return next((len(g.items) for g in profile.related if g.label == label), 0)


def verdict_for(lookup: ThreatLookup) -> Verdict:
    """A PROFILE verdict for a match; UNKNOWN when there's no single match."""
    if lookup.status == "unavailable":
        return Verdict(score=0, level="UNKNOWN", confidence="low",
                       headline="The threat knowledge base isn't available right now, so names can't be looked up.")
    if lookup.status == "not_found":
        return Verdict(score=0, level="UNKNOWN", confidence="low",
                       headline=f"No group, malware, tool, campaign, or technique in MITRE ATT&CK matches "
                                f"\"{lookup.query}\". It may be too new, or known by another name.")
    if lookup.status == "ambiguous":
        return Verdict(score=0, level="UNKNOWN", confidence="low",
                       headline=f"Several ATT&CK entries could match \"{lookup.query}\". Pick the one you mean below.")

    profile = lookup.profile
    entity = profile.entity
    documented = []
    if profile.techniques:
        documented.append(_plural(len(profile.techniques), "technique"))
    software = _count(profile, "Malware used") + _count(profile, "Tools used")
    if software:
        documented.append(_plural(software, "piece", "pieces") + " of software")
    campaigns = _count(profile, "Campaigns attributed to this group")
    if campaigns:
        documented.append(_plural(campaigns, "campaign"))
    users = _count(profile, "Used by groups")

    headline = f"{entity.name} ({entity.external_id}) is {KIND_PHRASES.get(entity.kind, entity.kind)} in MITRE ATT&CK"
    if documented:
        headline += ", documented with " + _join(documented)
    if users:
        headline += (", and" if documented else ",") + f" used by {_plural(users, 'group')}"
    headline += "."
    exact = not lookup.matched_on.startswith("similar")
    return Verdict(score=0, level="PROFILE", confidence="high" if exact else "medium", headline=headline,
                   rules_applied=[] if exact else
                   [f"\"{lookup.query}\" isn't an exact name, so ThreatLens picked the closest match "
                    f"({lookup.matched_on}). Check it's the one you meant."])


def as_source(lookup: ThreatLookup) -> SourceResult:
    """The profile as a source the AI report writer can cite, like NVD or VirusTotal.

    Kept compact, because every fact here is sent to the AI and counts toward free-tier limits.
    """
    profile = lookup.profile
    entity = profile.entity
    facts = {
        "attack_id": entity.external_id,
        "name": entity.name,
        "kind": entity.kind,
        "also_known_as": entity.aliases[:15],
        "description": entity.description[:1500],
    }
    for group in profile.related:
        if group.label == "Techniques used":
            continue  # sent below, with tactics
        facts[group.label.lower().replace(" ", "_")] = [f"{i.external_id} {i.name}" for i in group.items[:25]]
    if profile.techniques:
        facts["techniques_used"] = [
            f"{t.external_id} {t.name}" + (f" ({', '.join(t.tactics)})" if t.tactics else "")
            for t in profile.techniques[:MAX_TECHNIQUES_FOR_AI]
        ]
        facts["technique_count"] = len(profile.techniques)
        facts["techniques_per_tactic"] = {t.name: t.count for t in profile.tactics}
    if profile.mitigations:
        facts["defenses_covering_most_techniques"] = [
            f"{m.external_id} {m.name}: helps against {m.covers} of its techniques" for m in profile.mitigations
        ]
    if entity.kind == "technique":
        facts["tactics"] = [t["name"] for t in entity.details.get("tactics", [])]
        facts["platforms"] = entity.details.get("platforms", [])
    if entity.kind == "campaign":
        facts["first_seen"] = entity.details.get("first_seen")
        facts["last_seen"] = entity.details.get("last_seen")
    return SourceResult(source="MITRE ATT&CK", status=SourceStatus.OK, link=entity.url, facts=facts)
