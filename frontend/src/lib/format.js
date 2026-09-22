export const LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];

export const TYPE_NAMES = {
  cve: "Vulnerability (CVE)",
  ip: "IP address",
  domain: "Domain",
  hash: "File hash",
};

export const SUBTYPE_NAMES = { ipv4: "IPv4", ipv6: "IPv6", md5: "MD5", sha1: "SHA-1", sha256: "SHA-256" };

export function typeName(indicator) {
  const sub = indicator.subtype ? SUBTYPE_NAMES[indicator.subtype] || indicator.subtype : null;
  return TYPE_NAMES[indicator.type] + (sub ? ` (${sub})` : "");
}

export function timeAgo(iso) {
  const seconds = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (seconds < 60) return "just now";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} minute${minutes === 1 ? "" : "s"} ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} hour${hours === 1 ? "" : "s"} ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days} day${days === 1 ? "" : "s"} ago`;
  return new Date(iso).toLocaleDateString();
}

export function seconds(ms) {
  if (ms == null) return "";
  return ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`;
}

export function points(n) {
  return n > 0 ? `+${n}` : n < 0 ? `\u2212${Math.abs(n)}` : "0";
}

const ACRONYMS = { ioc: "IOC", cvss: "CVSS", asn: "ASN", epss: "EPSS", url: "URL", urls: "URLs", isp: "ISP", id: "ID", sha256: "SHA-256" };

// "abuse_confidence" -> "Abuse confidence", "ioc_count" -> "IOC count"
export function humanize(key) {
  const words = key.split("_").map((w) => ACRONYMS[w] || w);
  const text = words.join(" ");
  return text.charAt(0).toUpperCase() + text.slice(1);
}

export const SOURCE_STATUS_TEXT = {
  ok: "Found data",
  not_found: "No record",
  error: "Failed",
  timeout: "Timed out",
  rate_limited: "Rate limited",
  skipped: "Skipped",
};

export const STEP_KIND_TEXT = {
  detect: "Identify",
  decide: "Decide",
  fetch: "Look up",
  score: "Score",
  verdict: "Verdict",
  report: "Explain",
  save: "Save",
};
