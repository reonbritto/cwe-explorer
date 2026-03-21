"""NVD API 2.0 client with caching and rate limiting."""
import asyncio
from datetime import datetime, timedelta, timezone
import httpx
from typing import Optional, List
from .models import (
    CVEDetail, CVESearchResult, CVSSScores,
    AffectedProduct, Reference
)
from . import cache

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_TIMEOUT = 30.0

# Simple rate limiter: track last request time
_last_request_time = 0.0
_MIN_INTERVAL = 6.0  # ~5 requests per 30 seconds without API key


async def _rate_limited_get(client: httpx.AsyncClient,
                            url: str,
                            params: dict) -> httpx.Response:
    """Make a rate-limited GET request to NVD API."""
    global _last_request_time
    now = asyncio.get_event_loop().time()
    elapsed = now - _last_request_time
    if elapsed < _MIN_INTERVAL:
        await asyncio.sleep(_MIN_INTERVAL - elapsed)

    response = await client.get(url, params=params,
                                timeout=REQUEST_TIMEOUT)
    _last_request_time = asyncio.get_event_loop().time()
    return response


def parse_nvd_cve(vuln: dict) -> CVEDetail:
    """Parse a single NVD vulnerability object into CVEDetail model."""
    cve_data = vuln.get("cve", vuln)

    # CVE ID
    cve_id = cve_data.get("id", "")

    # Description (English)
    descriptions = cve_data.get("descriptions", [])
    description = ""
    for desc in descriptions:
        if desc.get("lang") == "en":
            description = desc.get("value", "")
            break

    # CVSS Scores
    metrics = cve_data.get("metrics", {})
    cvss = CVSSScores()

    # CVSS v3.1
    v31_metrics = metrics.get("cvssMetricV31", [])
    if not v31_metrics:
        v31_metrics = metrics.get("cvssMetricV30", [])
    if v31_metrics:
        v31 = v31_metrics[0].get("cvssData", {})
        cvss.v3_score = v31.get("baseScore")
        cvss.v3_vector = v31.get("vectorString")
        cvss.v3_severity = v31.get("baseSeverity")

    # CVSS v2
    v2_metrics = metrics.get("cvssMetricV2", [])
    if v2_metrics:
        v2 = v2_metrics[0].get("cvssData", {})
        cvss.v2_score = v2.get("baseScore")
        cvss.v2_vector = v2.get("vectorString")

    # CWE IDs
    cwe_ids = []
    weaknesses = cve_data.get("weaknesses", [])
    for w in weaknesses:
        for desc in w.get("description", []):
            val = desc.get("value", "")
            if val.startswith("CWE-"):
                cwe_ids.append(val)

    # Affected products from configurations
    affected_products = []
    configurations = cve_data.get("configurations", [])
    for config in configurations:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable"):
                    criteria = match.get("criteria", "")
                    parts = criteria.split(":")
                    if len(parts) >= 6:
                        affected_products.append(AffectedProduct(
                            vendor=parts[3] if len(parts) > 3 else "",
                            product=parts[4] if len(parts) > 4 else "",
                            version=parts[5] if len(parts) > 5 else "*"
                        ))

    # References
    references = []
    for ref in cve_data.get("references", []):
        references.append(Reference(
            url=ref.get("url", ""),
            source=ref.get("source", ""),
            tags=ref.get("tags", [])
        ))

    # Dates
    published = cve_data.get("published", "")
    modified = cve_data.get("lastModified", "")

    return CVEDetail(
        cve_id=cve_id,
        description=description,
        cvss=cvss,
        cwe_ids=cwe_ids,
        references=references,
        affected_products=affected_products,
        published=published,
        modified=modified
    )


async def get_cve(cve_id: str) -> Optional[CVEDetail]:
    """Fetch a single CVE by ID, using cache first."""
    # Check cache
    cached = cache.get_cached_cve(cve_id)
    if cached:
        return CVEDetail(**cached)

    # Fetch from NVD
    async with httpx.AsyncClient() as client:
        response = await _rate_limited_get(
            client, NVD_BASE_URL, {"cveId": cve_id}
        )
        if response.status_code != 200:
            return None

        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return None

        cve_detail = parse_nvd_cve(vulnerabilities[0])

        # Cache the result
        cache.set_cached_cve(cve_id, cve_detail.model_dump())

        return cve_detail


async def get_latest_cves(
    limit: int = 20
) -> List[CVESearchResult]:
    """Fetch the most recently published CVEs from NVD.

    Queries today's CVEs first.  If none are found (e.g.
    weekends / holidays) it widens the window to the last
    3 days so the homepage is never empty.  Single API
    call — no probe request needed.
    """
    cache_key = f"latest_cves_{limit}"
    cached = cache.get_cached_search(cache_key)
    if cached:
        return [CVESearchResult(**item) for item in cached]

    page_size = min(limit, 50)
    now = datetime.now(timezone.utc)

    # Try today first, then widen to 3 days if empty
    for days_back in (0, 3):
        start = now - timedelta(days=days_back)
        results = await _fetch_cves_by_date(
            start, now, page_size
        )
        if results:
            break

    # Sort by published date descending (newest first)
    results.sort(
        key=lambda x: x.published or "", reverse=True
    )

    if results:
        cache.set_cached_search(
            cache_key,
            [r.model_dump() for r in results]
        )
    return results


async def _fetch_cves_by_date(
    start: datetime, end: datetime, page_size: int
) -> List[CVESearchResult]:
    """Fetch one page of CVEs published between two dates."""
    async with httpx.AsyncClient() as client:
        response = await _rate_limited_get(
            client, NVD_BASE_URL,
            {
                "resultsPerPage": page_size,
                "pubStartDate": start.strftime(
                    "%Y-%m-%dT00:00:00.000"
                ),
                "pubEndDate": end.strftime(
                    "%Y-%m-%dT23:59:59.999"
                ),
            },
        )
        if response.status_code != 200:
            return []

        data = response.json()
        results = []
        for vuln in data.get("vulnerabilities", []):
            cve = parse_nvd_cve(vuln)
            results.append(CVESearchResult(
                cve_id=cve.cve_id,
                description=cve.description[:300],
                severity=cve.cvss.v3_severity,
                cvss_v3=cve.cvss.v3_score,
                published=cve.published
            ))
            cache.set_cached_cve(cve.cve_id, cve.model_dump())

        return results


async def search_cves(
    keyword: Optional[str] = None,
    cwe_id: Optional[str] = None,
    severity: Optional[str] = None,
    results_per_page: int = 20,
    start_index: int = 0
) -> List[CVESearchResult]:
    """Search CVEs using NVD API with optional filters.

    Uses a two-step approach: first a probe request to get
    totalResults, then fetches the *last* page so results
    are the most recently published CVEs.
    """
    page_size = min(results_per_page, 50)

    base_params: dict = {}
    if keyword:
        base_params["keywordSearch"] = keyword
    if cwe_id:
        base_params["cweId"] = cwe_id
    if severity:
        base_params["cvssV3Severity"] = severity.upper()

    # Cache key includes page info
    cache_key = str(sorted(
        {**base_params, "page_size": page_size,
         "start_index": start_index}.items()
    ))
    cached = cache.get_cached_search(cache_key)
    if cached:
        return [CVESearchResult(**item) for item in cached]

    async with httpx.AsyncClient() as client:
        # Step 1: probe to get totalResults
        probe = await _rate_limited_get(
            client, NVD_BASE_URL,
            {**base_params, "resultsPerPage": 1, "startIndex": 0}
        )
        if probe.status_code != 200:
            return []

        total = probe.json().get("totalResults", 0)
        if total == 0:
            return []

        # Step 2: jump to the last page for newest CVEs
        last_page_start = max(total - page_size, 0)
        real_start = max(last_page_start - start_index, 0)

        response = await _rate_limited_get(
            client, NVD_BASE_URL,
            {
                **base_params,
                "resultsPerPage": page_size,
                "startIndex": real_start,
            }
        )
        if response.status_code != 200:
            return []

        data = response.json()
        results = []
        for vuln in data.get("vulnerabilities", []):
            cve = parse_nvd_cve(vuln)
            results.append(CVESearchResult(
                cve_id=cve.cve_id,
                description=cve.description[:300],
                severity=cve.cvss.v3_severity,
                cvss_v3=cve.cvss.v3_score,
                published=cve.published
            ))
            cache.set_cached_cve(cve.cve_id, cve.model_dump())

        # Sort by published date descending (newest first)
        results.sort(
            key=lambda x: x.published or "", reverse=True
        )

        cache.set_cached_search(
            cache_key,
            [r.model_dump() for r in results]
        )

        return results
