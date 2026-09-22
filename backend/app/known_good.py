"""Checks that prevent common false alarms.

Real SOC teams lose a lot of time to alerts about harmless things,
like Google's DNS server or a Microsoft update domain.

Important: "known good" lowers the score but never hides evidence.
Attackers abuse trusted platforms, so the analyst always sees what sources said.
"""
import ipaddress
from dataclasses import dataclass

# Widely used public DNS resolvers. They appear in logs constantly and are almost always harmless.
PUBLIC_RESOLVERS = {
    "8.8.8.8": "Google Public DNS",
    "8.8.4.4": "Google Public DNS",
    "1.1.1.1": "Cloudflare DNS",
    "1.0.0.1": "Cloudflare DNS",
    "9.9.9.9": "Quad9 DNS",
    "149.112.112.112": "Quad9 DNS",
    "208.67.222.222": "Cisco OpenDNS",
    "208.67.220.220": "Cisco OpenDNS",
    "2001:4860:4860::8888": "Google Public DNS",
    "2001:4860:4860::8844": "Google Public DNS",
    "2606:4700:4700::1111": "Cloudflare DNS",
    "2606:4700:4700::1001": "Cloudflare DNS",
}

# Large, well-known organizations' own domains.
# A small starter list; a later phase can use a ranked list such as Tranco.
WELL_KNOWN_DOMAINS = {
    "google.com", "googleapis.com", "gstatic.com", "youtube.com",
    "microsoft.com", "windows.com", "windowsupdate.com", "office.com", "live.com", "azure.com",
    "apple.com", "icloud.com",
    "amazon.com",
    "cloudflare.com",
    "github.com",
    "mozilla.org",
    "wikipedia.org",
    "linkedin.com",
    "facebook.com", "whatsapp.com", "instagram.com",
    "ubuntu.com", "debian.org", "python.org", "npmjs.com",
}

# Platforms where ANYONE can host content under the trusted name.
# Attackers use these a lot, so a subdomain here is never treated as known good.
USER_CONTENT_PLATFORMS = {
    "github.io", "githubusercontent.com", "pages.dev", "workers.dev", "vercel.app",
    "netlify.app", "onrender.com", "herokuapp.com", "firebaseapp.com", "web.app",
    "blogspot.com", "wordpress.com", "sites.google.com", "docs.google.com", "drive.google.com",
    "storage.googleapis.com", "s3.amazonaws.com", "amazonaws.com", "azurewebsites.net",
    "blob.core.windows.net", "sharepoint.com", "onedrive.live.com", "dropbox.com",
    "ngrok.io", "ngrok-free.app", "trycloudflare.com", "duckdns.org", "no-ip.com",
    "000webhostapp.com", "weebly.com", "wixsite.com", "glitch.me", "replit.app",
}


@dataclass
class KnownGoodResult:
    is_known_good: bool
    skip_external_lookup: bool  # True for private/internal addresses
    reason: str | None = None
    caution: str | None = None  # warning for user-content platforms


def _matches(domain: str, entries: set[str]) -> str | None:
    """Return the entry if domain equals it or is a subdomain of it."""
    for entry in entries:
        if domain == entry or domain.endswith("." + entry):
            return entry
    return None


def check_ip(value: str) -> KnownGoodResult:
    ip = ipaddress.ip_address(value)
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast \
            or ip.is_reserved or ip.is_unspecified:
        return KnownGoodResult(
            is_known_good=False,
            skip_external_lookup=True,
            reason=(
                "This is a private or reserved address (for example, inside a company network). "
                "It has no public reputation, and sending internal addresses to outside services "
                "could leak information about your network, so ThreatLens doesn't look it up."
            ),
        )
    if value in PUBLIC_RESOLVERS:
        return KnownGoodResult(True, False, f"Well-known public DNS resolver ({PUBLIC_RESOLVERS[value]}).")
    return KnownGoodResult(False, False)


def check_domain(domain: str) -> KnownGoodResult:
    platform = _matches(domain, USER_CONTENT_PLATFORMS)
    if platform:
        return KnownGoodResult(
            is_known_good=False,
            skip_external_lookup=False,
            caution=(
                f"This is on {platform}, a platform where anyone can publish content. "
                "The platform is trusted, but this specific address might not be."
            ),
        )
    match = _matches(domain, WELL_KNOWN_DOMAINS)
    if match:
        return KnownGoodResult(True, False, f"Belongs to a well-known organization's domain ({match}).")
    return KnownGoodResult(False, False)
