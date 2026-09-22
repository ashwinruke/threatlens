"""Figure out what the user entered, using simple rules (no AI).

Rules are faster, cheaper, and more predictable than asking an LLM,
and every decision can be explained exactly.
"""
import ipaddress
import re
from urllib.parse import urlsplit

from app.models import Indicator, IndicatorType


class DetectionError(ValueError):
    """Raised with a friendly message when input can't be understood."""


CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}
DOMAIN_LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
DOMAIN_RE = re.compile(rf"^(?:{DOMAIN_LABEL}\.)+(?:[a-z]{{2,63}}|xn--[a-z0-9-]{{2,59}})$")

# Common ways analysts "defang" indicators so nobody clicks them by accident.
DEFANG_REPLACEMENTS = [
    # Only change hxxp/fxp when they are a URL scheme, so a domain like "fxpro.com" stays intact
    (re.compile(r"\bhxxp(s?)(?=\[?:\]?//)", re.IGNORECASE), r"http\1"),
    (re.compile(r"\bfxp(?=\[?:\]?//)", re.IGNORECASE), "ftp"),
    (re.compile(r"\[\s*(?:\.|dot)\s*\]|\(\s*(?:\.|dot)\s*\)|\{\s*(?:\.|dot)\s*\}", re.IGNORECASE), "."),
    (re.compile(r"\[\s*:\s*\]"), ":"),
    (re.compile(r"\[\s*(?:@|at)\s*\]", re.IGNORECASE), "@"),
    (re.compile(r"\[/\]"), "/"),
]


def refang(text: str) -> tuple[str, bool]:
    """Undo defanging. Returns (clean_text, whether anything changed)."""
    cleaned = text
    for pattern, replacement in DEFANG_REPLACEMENTS:
        cleaned = pattern.sub(replacement, cleaned)
    return cleaned, cleaned != text


def _try_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    candidate = value
    # [2001:db8::1] or [2001:db8::1]:443
    if candidate.startswith("["):
        candidate = candidate[1:].split("]")[0]
    # 1.2.3.4:443 (only strip a port from IPv4-looking text)
    elif candidate.count(":") == 1:
        candidate = candidate.split(":")[0]
    try:
        return ipaddress.ip_address(candidate)
    except ValueError:
        return None


def detect(raw: str) -> Indicator:
    original = raw
    text = raw.strip().strip("'\"`<>")
    if not text:
        raise DetectionError("Please enter a CVE, IP address, domain, or file hash.")
    if any(ch.isspace() for ch in text):
        raise DetectionError(
            "That looks like more than one thing. Enter a single CVE, IP, domain, or hash. "
            "Bulk lookups are coming in a later version."
        )

    text, refanged = refang(text)
    notes: list[str] = []
    if refanged:
        notes.append("Removed defanging (like [.] or hxxp) to read the indicator.")

    # 1. CVE
    if CVE_RE.match(text):
        return Indicator(type=IndicatorType.CVE, value=text.upper(), original=original,
                         refanged=refanged, notes=notes)

    # 2. File hash
    if HEX_RE.match(text) and len(text) in HASH_LENGTHS:
        return Indicator(type=IndicatorType.HASH, value=text.lower(), original=original,
                         subtype=HASH_LENGTHS[len(text)], refanged=refanged, notes=notes)
    if HEX_RE.match(text) and len(text) >= 24:
        raise DetectionError(
            f"That looks like a hash, but it has {len(text)} characters. "
            "ThreatLens supports MD5 (32), SHA-1 (40), and SHA-256 (64)."
        )

    # 3. URL or email: investigate the host part
    if re.match(r"^[a-z][a-z0-9+.-]*://", text, re.IGNORECASE):
        host = urlsplit(text).hostname or ""
        if not host:
            raise DetectionError("That URL has no host name to investigate.")
        notes.append(f"Input was a URL, so ThreatLens investigates its host: {host}")
        text = host
    elif "@" in text and text.count("@") == 1:
        host = text.split("@")[1]
        notes.append(f"Input was an email address, so ThreatLens investigates its domain: {host}")
        text = host

    # 4. IP address
    ip = _try_ip(text)
    if ip is not None:
        return Indicator(type=IndicatorType.IP, value=str(ip), original=original,
                         subtype=f"ipv{ip.version}", refanged=refanged, notes=notes)

    # 5. Domain
    domain = text.lower().rstrip(".")
    if domain.startswith("www."):
        notes.append("Removed the leading 'www.' prefix.")
        domain = domain[4:]
    try:
        domain = domain.encode("idna").decode("ascii")  # international names -> xn--
    except UnicodeError:
        raise DetectionError("That domain name contains characters that can't be used in a domain.")
    if DOMAIN_RE.match(domain) and len(domain) <= 253:
        return Indicator(type=IndicatorType.DOMAIN, value=domain, original=original,
                         refanged=refanged, notes=notes)

    raise DetectionError(
        "ThreatLens couldn't recognize that. Try a CVE (CVE-2021-44228), an IP (203.0.113.7), "
        "a domain (example.com), or an MD5/SHA-1/SHA-256 hash."
    )
