from datetime import datetime, timedelta, timezone

from app.known_good import KnownGoodResult
from app.models import Indicator, IndicatorType, Signal, SourceResult, SourceStatus, Verdict

ANSWERED = {SourceStatus.OK, SourceStatus.NOT_FOUND}


def level_for(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    return "LOW"


def parse_date(value: str | None) -> datetime | None:
    """Sources use different date formats. Return a UTC datetime or None."""
    if not value:
        return None
    text = str(value).strip().replace(" UTC", "").replace("Z", "+00:00")
    for candidate in (text, text.replace(" ", "T", 1)):
        try:
            parsed = datetime.fromisoformat(candidate)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _confidence(results: list[SourceResult]) -> str:
    if not results:
        return "low"
    answered = sum(r.status in ANSWERED for r in results)
    ratio = answered / len(results)
    return "high" if ratio >= 0.75 else "medium" if ratio >= 0.5 else "low"


def _facts(results: list[SourceResult], name: str) -> dict | None:
    for r in results:
        if r.source == name and r.status == SourceStatus.OK:
            return r.facts
    return None


# ---------------------------------------------------------------- CVE

def score_cve(indicator: Indicator, results: list[SourceResult], now: datetime | None = None) -> tuple[Verdict, list[Signal]]:
    now = now or datetime.now(timezone.utc)
    signals: list[Signal] = []
    rules: list[str] = []
    nvd, kev, epss = _facts(results, "NVD"), _facts(results, "CISA KEV"), _facts(results, "FIRST EPSS")

    if not (nvd or kev or epss):
        answered_any = any(r.status in ANSWERED for r in results)
        headline = (f"{indicator.value} wasn't found in NVD, CISA KEV, or EPSS. Check the ID; it may be reserved or not yet published."
                    if answered_any else f"ThreatLens couldn't reach the vulnerability sources for {indicator.value}. Try again shortly.")
        return Verdict(score=0, level="UNKNOWN", confidence=_confidence(results), headline=headline), signals

    # Severity (up to 40 points)
    cvss = (nvd or {}).get("cvss")
    if cvss and cvss.get("score") is not None:
        points = round(float(cvss["score"]) * 4)
        signals.append(Signal(id="cvss", label=f"CVSS {cvss['version']} severity {cvss['score']} ({cvss.get('severity') or 'n/a'})",
                              points=points, source="NVD", evidence=f"Base score {cvss['score']} out of 10 (x4 = {points} points)."))
    elif nvd:
        signals.append(Signal(id="cvss_missing", label="No CVSS score yet", points=15, source="NVD",
                              evidence="NVD hasn't scored this CVE yet, so severity is unknown. Treated as moderate until scored."))

    # Known exploitation (30 points, +5 for ransomware)
    if kev:
        signals.append(Signal(id="kev_listed", label="Exploited in real attacks (CISA KEV)", points=30, source="CISA KEV",
                              evidence=f"Added to KEV on {kev.get('date_added')}. CISA's remediation due date: {kev.get('due_date')}."))
        if kev.get("known_ransomware_use"):
            signals.append(Signal(id="kev_ransomware", label="Used in ransomware campaigns", points=5, source="CISA KEV",
                                  evidence="CISA marks this vulnerability as known to be used by ransomware groups."))
    elif any(r.source == "CISA KEV" and r.status == SourceStatus.NOT_FOUND for r in results):
        signals.append(Signal(id="kev_absent", label="Not in CISA KEV", points=0, source="CISA KEV",
                              evidence="No confirmed exploitation reported to CISA. That doesn't prove it's unexploited."))

    # Exploit likelihood (up to 20 points)
    if epss:
        probability = epss["probability"]
        points = 20 if probability >= 0.5 else 12 if probability >= 0.1 else 5 if probability >= 0.01 else 0
        signals.append(Signal(id="epss", label=f"Exploit likelihood {probability:.1%} in the next 30 days", points=points,
                              source="FIRST EPSS",
                              evidence=f"EPSS probability {probability:.4f}, higher than {epss['percentile']:.0%} of all CVEs. "
                                       "Points: 20 if at least 50%, 12 if at least 10%, 5 if at least 1%."))

    # Public exploit reference (5 points)
    if nvd and nvd.get("has_exploit_reference") and not kev:
        signals.append(Signal(id="exploit_reference", label="Public exploit reference", points=5, source="NVD",
                              evidence="NVD lists at least one reference tagged 'Exploit'."))

    # Newly published (5 points)
    published = parse_date((nvd or {}).get("published"))
    if published and now - published <= timedelta(days=30):
        signals.append(Signal(id="recent", label="Published in the last 30 days", points=5, source="NVD",
                              evidence=f"Published {published.date()}. Patches and detections may still be catching up."))

    score = max(0, min(100, sum(s.points for s in signals)))
    if kev and score < 60:
        rules.append(f"Raised score from {score} to 60: every vulnerability exploited in real attacks is at least HIGH.")
        score = 60

    level = level_for(score)
    parts = []
    if cvss and cvss.get("score") is not None:
        parts.append(f"CVSS {cvss['score']}")
    if epss:
        parts.append(f"{epss['probability']:.1%} exploit likelihood")
    parts.append("actively exploited (CISA KEV)" if kev else "not in CISA KEV")
    headline = f"{indicator.value} is {level} risk: " + ", ".join(parts) + "."
    return Verdict(score=score, level=level, confidence=_confidence(results), headline=headline, rules_applied=rules), signals


# ---------------------------------------------------------------- IP, domain, hash

def score_ioc(indicator: Indicator, results: list[SourceResult], known_good: KnownGoodResult | None,
              now: datetime | None = None) -> tuple[Verdict, list[Signal]]:
    now = now or datetime.now(timezone.utc)
    signals: list[Signal] = []
    rules: list[str] = []
    label = {IndicatorType.IP: "IP address", IndicatorType.DOMAIN: "domain", IndicatorType.HASH: "file"}[indicator.type]

    if known_good and known_good.skip_external_lookup:
        return Verdict(score=0, level="UNKNOWN", confidence="low",
                       headline=f"{indicator.value} is a private or reserved address, so it has no public reputation.",
                       rules_applied=[known_good.reason or ""]), signals

    if results and not any(r.status in ANSWERED for r in results):
        return Verdict(score=0, level="UNKNOWN", confidence="low",
                       headline="ThreatLens couldn't reach enough intelligence sources to judge this. Try again shortly."), signals

    vt = _facts(results, "VirusTotal")
    if vt:
        malicious, total = vt.get("malicious", 0), vt.get("engines_total", 0)
        points = 35 if malicious >= 10 else 25 if malicious >= 3 else 10 if malicious >= 1 else 0
        if points:
            note = " A few detections can be false positives." if malicious < 3 else ""
            signals.append(Signal(id="vt_malicious", label=f"Flagged malicious by {malicious} security vendors", points=points,
                                  source="VirusTotal", evidence=f"{malicious} of {total} engines flagged it malicious.{note}"))
        elif vt.get("suspicious", 0) >= 3:
            signals.append(Signal(id="vt_suspicious", label=f"Marked suspicious by {vt['suspicious']} vendors", points=5,
                                  source="VirusTotal", evidence="No malicious verdicts, but several suspicious ones."))

    abuse = _facts(results, "AbuseIPDB")
    if abuse:
        confidence = abuse.get("abuse_confidence", 0)
        points = 30 if confidence >= 75 else 15 if confidence >= 25 else 5 if confidence >= 1 else 0
        if points:
            signals.append(Signal(id="abuseipdb", label=f"Abuse confidence {confidence}%", points=points, source="AbuseIPDB",
                                  evidence=f"{abuse.get('total_reports', 0)} reports from {abuse.get('distinct_reporters', 0)} "
                                           f"users in 90 days. Last report: {abuse.get('last_reported') or 'unknown'}."))
        if abuse.get("is_tor"):
            signals.append(Signal(id="tor", label="Tor network address", points=10, source="AbuseIPDB",
                                  evidence="Tor hides who is behind the traffic. Not malicious by itself, but often worth a closer look."))

    threatfox = _facts(results, "ThreatFox")
    if threatfox:
        families = ", ".join(threatfox["malware_families"]) or "unnamed malware"
        signals.append(Signal(id="threatfox", label=f"Linked to malware: {families}", points=30, source="ThreatFox",
                              evidence=f"{threatfox['ioc_count']} matching IOC record(s), highest reporter confidence "
                                       f"{threatfox['max_confidence']}%. Threat: {', '.join(threatfox['threat_types']) or 'n/a'}."))

    urlhaus = _facts(results, "URLhaus")
    if urlhaus:
        if urlhaus["urls_online"]:
            signals.append(Signal(id="urlhaus_online", label="Currently hosting malware", points=30, source="URLhaus",
                                  evidence=f"{urlhaus['urls_online']} malware URL(s) still online out of {urlhaus['url_count']} recorded."))
        elif urlhaus["url_count"]:
            signals.append(Signal(id="urlhaus_past", label="Hosted malware in the past", points=15, source="URLhaus",
                                  evidence=f"{urlhaus['url_count']} malware URL(s) recorded, none currently online."))

    bazaar = _facts(results, "MalwareBazaar")
    if bazaar:
        signals.append(Signal(id="malwarebazaar", label=f"Known malware sample: {bazaar.get('malware_family') or 'unnamed family'}",
                              points=45, source="MalwareBazaar",
                              evidence=f"MalwareBazaar only stores malware. First seen {bazaar.get('first_seen') or 'unknown'}."))

    otx = _facts(results, "AlienVault OTX")
    if otx:
        count = otx["pulse_count"]
        points = 15 if count >= 5 else 8
        signals.append(Signal(id="otx", label=f"Mentioned in {count} community threat report(s)", points=points,
                              source="AlienVault OTX",
                              evidence="Recent: " + ("; ".join(otx["recent_pulses"][:3]) or "names not given")
                                       + ". Community reports vary in quality."))

    if vt and indicator.type == IndicatorType.DOMAIN:
        created = parse_date(vt.get("created"))
        if created and now - created <= timedelta(days=30):
            signals.append(Signal(id="new_domain", label="Newly registered domain", points=10, source="VirusTotal",
                                  evidence=f"Registered {created.date()}. Attackers often use brand-new domains."))

    # Correlation: independent sources agreeing is stronger than one alone
    threat_ids = {"vt_malicious", "abuseipdb", "threatfox", "urlhaus_online", "urlhaus_past", "malwarebazaar", "otx"}
    agreeing = sorted({s.source for s in signals if s.id in threat_ids})
    if len(agreeing) >= 2:
        signals.append(Signal(id="corroborated", label=f"{len(agreeing)} independent sources agree", points=10, source="ThreatLens",
                              evidence="Reported by " + ", ".join(agreeing) + "."))

    # Freshness of the malicious evidence
    evidence_dates = [parse_date(d) for d in (
        (abuse or {}).get("last_reported") if abuse and abuse.get("abuse_confidence") else None,
        (threatfox or {}).get("last_seen"), (urlhaus or {}).get("last_added"),
        (bazaar or {}).get("last_seen") or (bazaar or {}).get("first_seen"), (otx or {}).get("last_pulse"),
    )]
    evidence_dates = [d for d in evidence_dates if d]
    if agreeing and evidence_dates:
        latest = max(evidence_dates)
        age = now - latest
        if age <= timedelta(days=30):
            signals.append(Signal(id="recent_activity", label="Reported in the last 30 days", points=10, source="ThreatLens",
                                  evidence=f"Most recent report: {latest.date()}."))
        elif age > timedelta(days=365):
            signals.append(Signal(id="stale_evidence", label="Only old reports (over a year)", points=-15, source="ThreatLens",
                                  evidence=f"Most recent report: {latest.date()}. IPs and domains often change owners."))

    if known_good and known_good.is_known_good:
        signals.append(Signal(id="known_good", label="Known legitimate service", points=-40, source="ThreatLens",
                              evidence=known_good.reason or "On ThreatLens's known-good list."))
    if abuse and abuse.get("is_allowlisted"):
        signals.append(Signal(id="abuseipdb_allowlisted", label="On AbuseIPDB's allowlist", points=-20, source="AbuseIPDB",
                              evidence="AbuseIPDB marks this IP as belonging to a trusted service."))
    if known_good and known_good.caution:
        rules.append(known_good.caution)

    score = max(0, min(100, sum(s.points for s in signals)))
    if bazaar and score < 70:
        rules.append(f"Raised score from {score} to 70: a hash found in a malware sample database is confirmed malware.")
        score = 70

    level = level_for(score)
    if agreeing:
        headline = f"This {label} is {level} risk: reported by {', '.join(agreeing)}."
    elif known_good and known_good.is_known_good:
        headline = f"This {label} appears legitimate: {known_good.reason}"
    else:
        headline = (f"No intelligence source reported this {label} as malicious. "
                    "That lowers the risk but doesn't prove it's safe.")
    return Verdict(score=score, level=level, confidence=_confidence(results), headline=headline, rules_applied=rules), signals
