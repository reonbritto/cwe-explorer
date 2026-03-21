"""FastAPI application for CVE Details - PureSecure."""
import os
from fastapi import FastAPI, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from typing import List, Optional
from .models import (
    CWEEntry, CVEDetail, CVESearchResult,
    SeverityDistribution, CWEStats, TrendPoint
)
from .cwe_parser import get_cwe_data, fetch_cwe_from_nvd
from .nvd_client import get_cve, search_cves, get_latest_cves
from .security import validate_cve_id, validate_cwe_id, sanitize_search_query
from . import cache
from . import analytics

app = FastAPI(
    title="CVE Details - PureSecure",
    description="Security vulnerability database with CWE mapping "
                "and analytics, built for Assimilate.",
    version="1.0.0"
)

# In-memory CWE data loaded at startup
cwe_data: List[CWEEntry] = []
cwe_dict: dict = {}


@app.on_event("startup")
async def startup_event():
    global cwe_data, cwe_dict
    cwe_data = get_cwe_data()
    cwe_dict = {entry.id: entry for entry in cwe_data}


# ── CVE Endpoints ───────────────────────────────────────────────


@app.get("/api/cve/latest", response_model=List[CVESearchResult])
async def api_latest_cves(
    limit: int = Query(20, le=50, description="Number of results")
):
    """Get the most recently published CVEs."""
    return await get_latest_cves(limit=limit)


@app.get("/api/cve/suggestions")
def api_cve_suggestions(
    q: str = Query(..., min_length=1, description="Search prefix")
):
    """Get search suggestions based on partial input."""
    q = sanitize_search_query(q)
    suggestions = []

    # Check if it looks like a CVE ID prefix
    q_upper = q.upper()
    if q_upper.startswith("CVE"):
        suggestions.append({
            "type": "tip",
            "text": "Enter full CVE ID (e.g., CVE-2021-44228)",
            "action": ""
        })

    # Suggest matching CWEs
    q_lower = q.lower()
    matched_cwes = [
        cwe for cwe in cwe_data
        if q_lower in cwe.name.lower()
        or q_lower in cwe.id
    ][:5]
    for cwe in matched_cwes:
        suggestions.append({
            "type": "cwe",
            "text": f"CWE-{cwe.id}: {cwe.name}",
            "action": f"/cwe.html?id={cwe.id}"
        })

    # Suggest common keyword searches
    common_topics = [
        "remote code execution", "sql injection",
        "cross-site scripting", "buffer overflow",
        "privilege escalation", "denial of service",
        "authentication bypass", "path traversal",
        "information disclosure", "memory corruption",
        "command injection", "deserialization",
        "log4j", "apache", "microsoft", "linux",
        "chrome", "openssl", "wordpress", "nginx"
    ]
    matched_topics = [
        t for t in common_topics if q_lower in t
    ][:4]
    for topic in matched_topics:
        suggestions.append({
            "type": "keyword",
            "text": topic.title(),
            "action": f"/search.html?keyword={topic}"
        })

    return suggestions[:8]


@app.get("/api/cve/search", response_model=List[CVESearchResult])
async def api_search_cves(
    keyword: Optional[str] = Query(
        None, description="Search keyword"
    ),
    cwe_id: Optional[str] = Query(
        None, description="Filter by CWE ID (e.g., CWE-79)"
    ),
    severity: Optional[str] = Query(
        None, description="Filter by severity: LOW, MEDIUM, HIGH, CRITICAL"
    ),
    limit: int = Query(20, le=50, description="Results per page"),
    offset: int = Query(0, ge=0, description="Start index")
):
    """Search CVEs by keyword, CWE, or severity."""
    if keyword:
        keyword = sanitize_search_query(keyword)
    if cwe_id:
        # Accept both "CWE-79" and "79" formats
        cwe_id_clean = cwe_id.replace("CWE-", "").strip()
        validate_cwe_id(cwe_id_clean)
        cwe_id = f"CWE-{cwe_id_clean}"

    results = await search_cves(
        keyword=keyword,
        cwe_id=cwe_id,
        severity=severity,
        results_per_page=limit,
        start_index=offset
    )
    return results


@app.get("/api/cve/{cve_id}", response_model=CVEDetail)
async def api_get_cve(cve_id: str):
    """Get full details for a specific CVE."""
    cve_id = validate_cve_id(cve_id)
    result = await get_cve(cve_id)
    if not result:
        raise HTTPException(status_code=404, detail="CVE not found")
    return result


# ── CWE Endpoints ───────────────────────────────────────────────


@app.get("/api/cwe", response_model=List[CWEEntry])
def api_search_cwes(
    query: str = Query(
        None, description="Search by ID or Name substring"
    ),
    limit: int = Query(10, le=100)
):
    """Search for CWEs by string query."""
    if not query:
        return cwe_data[:limit]

    query_lower = sanitize_search_query(query).lower()
    results = [
        cwe for cwe in cwe_data
        if query_lower in cwe.name.lower()
        or query_lower in cwe.id.lower()
    ]
    return results[:limit]


@app.get("/api/cwe/{cwe_id}", response_model=CWEEntry)
async def api_get_cwe(cwe_id: str):
    """Retrieve a single CWE by its numeric ID."""
    cwe_id = validate_cwe_id(cwe_id)
    # Check built-in data first
    if cwe_id in cwe_dict:
        return cwe_dict[cwe_id]
    # Fallback to live NVD lookup
    result = await fetch_cwe_from_nvd(cwe_id)
    if not result:
        raise HTTPException(status_code=404, detail="CWE not found")
    return result


@app.get("/api/cwe/{cwe_id}/cves", response_model=List[CVESearchResult])
async def api_get_cwe_cves(cwe_id: str):
    """Get CVEs associated with a specific CWE."""
    cwe_id = validate_cwe_id(cwe_id)
    results = await search_cves(cwe_id=f"CWE-{cwe_id}")
    return results


# ── Analytics Endpoints ─────────────────────────────────────────


@app.get("/api/analytics/severity", response_model=SeverityDistribution)
def api_severity_distribution():
    """Get severity distribution of all cached CVEs."""
    all_cves = cache.get_all_cached_cves()
    return analytics.severity_distribution(all_cves)


@app.get("/api/analytics/top-cwes", response_model=List[CWEStats])
def api_top_cwes(limit: int = Query(10, le=50)):
    """Get CWEs with the most associated CVEs."""
    all_cves = cache.get_all_cached_cves()
    return analytics.top_cwes(all_cves, cwe_dict, limit=limit)


@app.get("/api/analytics/trends", response_model=List[TrendPoint])
def api_trends():
    """Get severity trends over time."""
    all_cves = cache.get_all_cached_cves()
    return analytics.severity_trends(all_cves)


# ── Static Files (must be last) ─────────────────────────────────

static_dir = os.path.join(os.path.dirname(__file__), "static")
if not os.path.exists(static_dir):
    os.makedirs(static_dir)

app.mount(
    "/", StaticFiles(directory=static_dir, html=True), name="static"
)
