"""Draft detection rules from a report: Sigma (for SIEMs) and YARA (for files).

Built by rule, never by AI, so a rule can only ever contain the indicator that was actually
investigated, never an invented one. Every rule is checked with the official pySigma library,
and converted to Splunk and Elastic searches with it.

What gets a rule:
  - IP addresses:  outbound and inbound connections (Windows network events and firewall logs)
  - domains:       DNS lookups and web proxy requests, including subdomains
  - file hashes:   processes and loaded modules with that hash (Sysmon), and a YARA rule
  - CVEs, threat and weakness profiles: no indicator to match, so instead links to the
                   community's maintained Sigma rules for that CVE or those ATT&CK techniques

Only MEDIUM risk and above: a rule for a low-risk or known-good indicator would mostly raise
false alarms. Everything is marked "experimental" and "a draft": a person reviews it first.
"""
import ipaddress
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import quote

import yaml

from app.models import IndicatorType, Investigation

NAMESPACE = uuid.UUID("2b7f6c1e-5b0a-4f7e-9a51-7a1d3c9e0f42")  # stable rule ids: same report, same ids
WORTH_A_RULE = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium"}
AUTHOR = "ThreatLens (automated draft)"
SIGMAHQ_SEARCH = "https://github.com/search?type=code&q=repo%3ASigmaHQ%2Fsigma+"


class _Dumper(yaml.SafeDumper):
    """Writes every value out in full: YAML aliases (&id001) confuse some Sigma tools."""

    def ignore_aliases(self, data):
        return True


@dataclass
class Item:
    """One indicator worth a rule."""
    type: IndicatorType
    value: str
    subtype: str | None
    level: str  # sigma level
    headline: str
    report_url: str | None
    key: str  # what makes the rule id stable


@dataclass
class RuleSet:
    sigma: str | None = None
    yara: str | None = None
    rules: list[dict] = field(default_factory=list)  # per Sigma rule: title, splunk, elastic
    notes: list[str] = field(default_factory=list)
    links: list[dict] = field(default_factory=list)  # community rules to look at instead
    indicators: int = 0

    def as_dict(self) -> dict:
        return {"sigma": self.sigma, "yara": self.yara, "rules": self.rules, "notes": self.notes,
                "links": self.links, "indicators": self.indicators}


def escape(value: str) -> str:
    """Sigma gives * ? and \\ special meaning; a matched value must contain them literally."""
    return value.replace("\\", "\\\\").replace("*", "\\*").replace("?", "\\?")


def _rule(title: str, key: str, description: str, logsource: dict, detection: dict, level: str,
          tags: list[str], references: list[str], falsepositives: list[str], today: str) -> dict:
    rule = {
        "title": title[:120],
        "id": str(uuid.uuid5(NAMESPACE, key)),
        "status": "experimental",
        "description": description,
        "references": references,
        "author": AUTHOR,
        "date": today,
        "tags": tags,
        "logsource": logsource,
        "detection": detection,
        "falsepositives": falsepositives,
        "level": level,
    }
    if not tags:
        del rule["tags"]
    if not references:
        del rule["references"]
    return rule


def _describe(items: list[Item], what: str) -> str:
    if len(items) == 1:
        return (f"{what} {items[0].value}. ThreatLens: {items[0].headline} "
                "Automated draft from a ThreatLens report: review before deploying.")
    return (f"{what} any of {len(items)} indicators that ThreatLens rated medium risk or above. "
            "Automated draft from a ThreatLens bulk lookup: review before deploying.")


def _level(items: list[Item]) -> str:
    order = ["medium", "high", "critical"]
    return max((i.level for i in items), key=order.index)


def _ip_rules(items, tags, refs, today, scope) -> list[dict]:
    values = [i.value for i in items]
    fp = ["Shared hosting, cloud or CDN addresses can also carry legitimate traffic",
          "Security scanners and threat-intelligence tools that look the address up"]
    return [
        _rule(f"Connection to a malicious IP address{_suffix(items)}", f"{scope}:ip:network",
              _describe(items, "Detects Windows network connections to or from"),
              {"category": "network_connection", "product": "windows"},
              {"selection_outbound": {"DestinationIp": values}, "selection_inbound": {"SourceIp": values},
               "condition": "1 of selection_*"},
              _level(items), tags, refs, fp, today),
        _rule(f"Firewall traffic with a malicious IP address{_suffix(items)}", f"{scope}:ip:firewall",
              _describe(items, "Detects firewall log entries to or from"),
              {"category": "firewall"},
              {"selection_dst": {"dst_ip": values}, "selection_src": {"src_ip": values}, "condition": "1 of selection_*"},
              _level(items), tags, refs, fp, today),
    ]


def _domain_rules(items, tags, refs, today, scope) -> list[dict]:
    exact = [escape(i.value) for i in items]
    subdomains = ["." + escape(i.value) for i in items]
    fp = ["Security tools and analysts looking the domain up", "A domain that has since changed owner"]
    return [
        _rule(f"DNS lookup of a malicious domain{_suffix(items)}", f"{scope}:domain:dns",
              _describe(items, "Detects DNS queries for"),
              {"category": "dns_query"},
              {"selection_exact": {"QueryName": exact}, "selection_subdomain": {"QueryName|endswith": subdomains},
               "condition": "1 of selection_*"},
              _level(items), tags, refs, fp, today),
        _rule(f"Web request to a malicious domain{_suffix(items)}", f"{scope}:domain:proxy",
              _describe(items, "Detects web proxy requests to"),
              {"category": "proxy"},
              {"selection_exact": {"cs-host": exact}, "selection_subdomain": {"cs-host|endswith": subdomains},
               "condition": "1 of selection_*"},
              _level(items), tags, refs, fp, today),
    ]


def _hash_rules(items, tags, refs, today, scope) -> list[dict]:
    # Sysmon writes hashes as "SHA256=ABC...,MD5=..." in one field
    values = [f"{(i.subtype or 'sha256').upper()}={i.value.upper()}" for i in items]
    fp = ["Very unlikely: a hash matches one exact file"]
    return [
        _rule(f"Process started from a malicious file{_suffix(items)}", f"{scope}:hash:process",
              _describe(items, "Detects a process started from the file with hash"),
              {"category": "process_creation", "product": "windows"},
              {"selection": {"Hashes|contains": values}, "condition": "selection"},
              _level(items), tags, refs, fp, today),
        _rule(f"Malicious file loaded as a module{_suffix(items)}", f"{scope}:hash:image_load",
              _describe(items, "Detects a DLL or module load of the file with hash"),
              {"category": "image_load", "product": "windows"},
              {"selection": {"Hashes|contains": values}, "condition": "selection"},
              _level(items), tags, refs, fp, today),
    ]


def _suffix(items: list[Item]) -> str:
    return f" ({items[0].value})" if len(items) == 1 else f" ({len(items)} indicators)"


def _yara(items: list[Item], today: str) -> str:
    lines = ['import "hash"', ""]
    for i in items:
        kind = (i.subtype or "sha256").lower()
        name = f"ThreatLens_{kind}_{i.value[:12].lower()}"
        lines += [
            f"rule {name}",
            "{",
            "    meta:",
            f'        description = "File ThreatLens rated {i.level} risk. Automated draft: review before deploying."',
            f'        author = "{AUTHOR}"',
            f'        date = "{today}"',
            f'        hash = "{i.value.lower()}"',
        ]
        if i.report_url:
            lines.append(f'        reference = "{i.report_url}"')
        lines += ["    condition:", f'        hash.{kind}(0, filesize) == "{i.value.lower()}"', "}", ""]
    return "\n".join(lines).rstrip() + "\n"


def _technique_tags(attack_map) -> list[str]:
    """ATT&CK tags in Sigma's format, only for techniques reported for this item (not merely linked)."""
    if not attack_map or getattr(attack_map, "status", "") != "ok":
        return []
    tags = []
    for tactic in attack_map.tactics:
        reported = [t for t in tactic.techniques if t.strength == "reported"]
        if reported:
            tags.append("attack." + tactic.shortname)
            tags += ["attack." + t.external_id.lower() for t in reported]
    return list(dict.fromkeys(tags))


def _convert(sigma_text: str) -> tuple[list[dict], list[str]]:
    """Check the rules with pySigma and convert each to a Splunk and an Elastic (Lucene) search."""
    from sigma.backends.elasticsearch import LuceneBackend
    from sigma.backends.splunk import SplunkBackend
    from sigma.collection import SigmaCollection

    collection = SigmaCollection.from_yaml(sigma_text)
    problems = [str(e) for rule in collection.rules for e in rule.errors]
    out = []
    splunk, elastic = SplunkBackend(), LuceneBackend()
    for rule in collection.rules:
        single = SigmaCollection([rule])
        out.append({"title": rule.title, "logsource": rule.logsource.category,
                    "splunk": " OR ".join(splunk.convert(single)), "elastic": " OR ".join(elastic.convert(single))})
    return out, problems


def build(investigations: list[Investigation], site_url: str | None, attack_maps: dict | None = None,
          scope: str | None = None) -> RuleSet:
    """Rules for one report, or one set for a whole bulk lookup (pass several investigations)."""
    result = RuleSet()
    today = datetime.now(timezone.utc).date().isoformat()
    attack_maps = attack_maps or {}
    scope = scope or ",".join(sorted(i.id or i.indicator.value for i in investigations))

    items: list[Item] = []
    skipped_low = 0
    for inv in investigations:
        kind = inv.indicator.type
        report_url = f"{site_url}/i/{inv.id}" if site_url and inv.id else None
        if kind in (IndicatorType.CVE, IndicatorType.THREAT):
            _links_for(inv, attack_maps.get(inv.id), result)
            continue
        level = WORTH_A_RULE.get(inv.verdict.level)
        if not level:
            skipped_low += 1
            continue
        if kind == IndicatorType.IP and not ipaddress.ip_address(inv.indicator.value).is_global:
            continue
        items.append(Item(kind, inv.indicator.value, inv.indicator.subtype, level, inv.verdict.headline, report_url,
                          inv.id or inv.indicator.value))

    if skipped_low:
        result.notes.append(
            f"{skipped_low} indicator{'s' if skipped_low != 1 else ''} rated low risk or unknown got no rule: "
            "a rule for something that's probably harmless mostly raises false alarms." if len(investigations) > 1
            else "No rule: ThreatLens rates this low risk or unknown, so a rule would mostly raise false alarms.")
    result.indicators = len(items)
    if not items:
        return result

    tags = list(dict.fromkeys(t for i in investigations for t in _technique_tags(attack_maps.get(i.id))))
    refs = [i.report_url for i in items if i.report_url][:10]
    rules: list[dict] = []
    for kind, maker in ((IndicatorType.IP, _ip_rules), (IndicatorType.DOMAIN, _domain_rules), (IndicatorType.HASH, _hash_rules)):
        group = [i for i in items if i.type == kind]
        if group:
            rules += maker(group, tags, refs, today, scope)

    result.sigma = "---\n".join(yaml.dump(r, Dumper=_Dumper, sort_keys=False, allow_unicode=True, width=1000) for r in rules)
    hashes = [i for i in items if i.type == IndicatorType.HASH]
    if hashes:
        result.yara = _yara(hashes, today)
    try:
        result.rules, problems = _convert(result.sigma)
        if problems:
            result.notes.append("pySigma found problems: " + "; ".join(problems))
    except Exception as exc:  # the rules are still useful without the converted searches
        result.notes.append(f"Couldn't convert the rules to searches ({type(exc).__name__}).")
    result.notes.append("Field names follow Sigma's standard (Sysmon-style). If your logs name fields differently, "
                        "map them, or convert the Sigma rule with a pipeline for your SIEM.")
    return result


def _links_for(inv: Investigation, attack_map, result: RuleSet) -> None:
    """A CVE or a profile has no indicator to match: point to maintained community rules instead."""
    if inv.indicator.type == IndicatorType.CVE:
        tag = "cve." + inv.indicator.value.lower().removeprefix("cve-")
        result.links.append({"label": f"SigmaHQ rules tagged {inv.indicator.value}",
                             "url": SIGMAHQ_SEARCH + quote(tag)})
        result.notes.append("A CVE isn't something a log contains, so there's no rule to generate from it. Detecting "
                            "exploitation needs a rule written for that exploit; the community's are linked below.")
    else:
        result.notes.append("A threat or weakness profile describes behaviour, not one indicator, so there's no rule "
                            "to generate from it. The community maintains rules per ATT&CK technique, linked below.")
    if attack_map and getattr(attack_map, "status", "") == "ok":
        techniques = [t for tactic in attack_map.tactics for t in tactic.techniques]
        techniques.sort(key=lambda t: t.strength != "reported")
        for t in techniques[:8]:
            result.links.append({"label": f"SigmaHQ rules for {t.external_id} {t.name}",
                                 "url": SIGMAHQ_SEARCH + quote("attack." + t.external_id.lower())})
