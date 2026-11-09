"""Where watchlist alerts come from: NVD (new CVEs) and CISA KEV (CVEs newly confirmed exploited).

Products are named the way NVD names them in its CPE dictionary (vendor + product), so
"nginx" means f5:nginx, not every CVE whose text mentions nginx.

Two kinds of NVD lookup per product, because NVD is often days or weeks behind in tagging new
CVEs with products:
  - product match: CVEs NVD has tagged with the product, recently changed (so a CVE tagged
    late still turns up), published in the last 90 days
  - name match: new CVEs whose description names the product, before NVD tags them
"""
import re
from datetime import datetime, timedelta, timezone

import httpx2

from app.sources import kev
from app.sources.nvd import _best_cvss

CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CPE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
MAX_PRODUCT_AGE = timedelta(days=90)  # "new" means published in the last 90 days
NVD_MAX_RANGE = timedelta(days=119)  # NVD rejects date ranges over 120 days


def _nvd_time(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


def _clean(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", text.lower())


def product_words(product: str) -> str:
    return product.replace("_", " ").replace("\\", "")


async def search_products(query: str, client: httpx2.AsyncClient, api_key: str | None) -> list[dict]:
    """Products in NVD's dictionary matching a name, most common first."""
    response = await client.get(CPE_URL, params={"keywordSearch": query, "resultsPerPage": 500},
                                headers={"apiKey": api_key} if api_key else {}, timeout=20)
    response.raise_for_status()
    found: dict[tuple[str, str, str], dict] = {}
    for entry in response.json().get("products", []):
        cpe = entry.get("cpe", {})
        if cpe.get("deprecated"):
            continue
        parts = cpe.get("cpeName", "").split(":")
        if len(parts) < 6 or parts[2] not in ("a", "o", "h"):
            continue
        vendor, product, version = parts[3], parts[4], parts[5]
        title = next((t["title"] for t in cpe.get("titles", []) if t.get("lang") == "en"), "")
        if version not in ("*", "-", "") and title.endswith(version):
            title = title[: -len(version)].strip()
        key = (parts[2], vendor, product)
        if key not in found:
            found[key] = {"part": parts[2], "vendor": vendor, "product": product, "kind": {"a": "application", "o": "operating system", "h": "hardware"}[parts[2]],
                          "title": title or f"{vendor} {product_words(product)}", "versions": 0}
        found[key]["versions"] += 1
    wanted = _clean(query)
    ranked = sorted(found.values(), key=lambda p: (wanted not in _clean(p["product"]), -p["versions"]))
    return ranked[:10]


def _cve_summary(item: dict) -> dict:
    cve = item.get("cve", {})
    description = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    return {"cve": cve.get("id", "").upper(), "published": cve.get("published"), "description": description,
            "cvss": _best_cvss(cve.get("metrics", {}))}


async def _query(client: httpx2.AsyncClient, api_key: str | None, params: dict) -> list[dict]:
    response = await client.get(CVE_URL, params={**params, "resultsPerPage": 200},
                                headers={"apiKey": api_key} if api_key else {}, timeout=30)
    if response.status_code == 404:
        return []
    response.raise_for_status()
    return [_cve_summary(v) for v in response.json().get("vulnerabilities", [])]


async def new_cves(part: str, vendor: str, product: str, since: datetime, until: datetime,
                   client: httpx2.AsyncClient, api_key: str | None) -> list[dict]:
    """CVEs for one product that appeared since the last check. Each gets a "match" field."""
    since = max(since, until - NVD_MAX_RANGE)
    window = {"lastModStartDate": _nvd_time(since), "lastModEndDate": _nvd_time(until)}
    tagged = await _query(client, api_key, {"virtualMatchString": f"cpe:2.3:{part}:{vendor}:{product}", **window})
    oldest = until - MAX_PRODUCT_AGE
    found = {c["cve"]: {**c, "match": "product"} for c in tagged
             if c["published"] and datetime.fromisoformat(c["published"]).replace(tzinfo=timezone.utc) >= oldest}

    words = product_words(product)
    if len(words) >= 4:  # very short names ("go", "vim") would match far too much text
        named = await _query(client, api_key, {"keywordSearch": words, "pubStartDate": _nvd_time(since),
                                               "pubEndDate": _nvd_time(until)})
        pattern = re.compile(rf"\b{re.escape(words)}\b", re.IGNORECASE)
        for c in named:
            if c["cve"] not in found and pattern.search(c["description"]):
                found[c["cve"]] = {**c, "match": "name"}
    return list(found.values())


def kev_matches(entry: dict, vendor: str, product: str) -> bool:
    """Does a KEV entry ("Apache", "Log4j2") name this product ("apache", "log4j")?"""
    kev_vendor, kev_product = _clean(entry.get("vendorProject", "")), _clean(entry.get("product", ""))
    mine_vendor, mine_product = _clean(vendor), _clean(product)
    if not kev_product or not mine_product:
        return False
    vendor_ok = mine_vendor in kev_vendor or kev_vendor in mine_vendor
    product_ok = mine_product in kev_product or kev_product in mine_product
    return vendor_ok and product_ok


async def newly_exploited(since: datetime, client: httpx2.AsyncClient) -> list[dict]:
    """KEV entries added since the last check (KEV records the day, so the whole day counts)."""
    catalog = await kev.get_catalog(client)
    first_day = since.date()
    out = []
    for entry in catalog.values():
        try:
            added = datetime.strptime(entry.get("dateAdded", ""), "%Y-%m-%d").date()
        except ValueError:
            continue
        if added >= first_day:
            out.append(entry)
    return out
