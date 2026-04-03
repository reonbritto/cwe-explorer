"""FastAPI application for CWE Explorer - PureSecure."""
import logging
import os
import time
import datetime
from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.routing import Route
from typing import List
from .models import (
    CWEEntry, CVEDetail, CVESearchResult, CWEStats, CWERiskScore,
)
from .cwe_parser import get_cwe_data, fetch_cwe_from_nvd
from .nvd_client import get_cve, search_cves
from .security import validate_cve_id, validate_cwe_id, sanitize_search_query
from .metrics import PrometheusMiddleware, metrics_endpoint
from .auth import get_current_user
from . import cache
from . import analytics
from . import attack_parser

def _uk_time(*args):
    """Return current time in Europe/London (GMT in winter, BST in summer)."""
    import zoneinfo
    tz = zoneinfo.ZoneInfo("Europe/London")
    return datetime.datetime.now(tz).timetuple()


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S %Z",
)
# Override formatter time converter on all root handlers to use UK time
for _handler in logging.root.handlers:
    if _handler.formatter:
        _handler.formatter.converter = _uk_time

logger = logging.getLogger("cwe-explorer")

# In-memory CWE data loaded at startup
cwe_data: List[CWEEntry] = []
cwe_dict: dict = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load CWE data at startup."""
    global cwe_data, cwe_dict
    cwe_data = get_cwe_data()
    cwe_dict = {entry.id: entry for entry in cwe_data}
    cache.cleanup_expired()   # no-op with Redis (TTL handles expiry)
    attack_ok = attack_parser.load_attack_data()
    logger.info(
        "Startup: loaded %d CWEs, Redis cache ready, "
        "max concurrent users: %d, ATT&CK data %s",
        len(cwe_data), cache.MAX_CONCURRENT_USERS,
        "loaded" if attack_ok else "unavailable",
    )
    yield


app = FastAPI(
    title="CWE Explorer - PureSecure",
    description="Security weakness database powered by MITRE CWE XML "
                "with NVD CVE cross-referencing.",
    version="2.0.0",
    lifespan=lifespan,
    routes=[Route("/metrics", metrics_endpoint)],
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# CORS — allow browser-based MSAL.js auth flow
_cors_raw = os.environ.get(
    "CORS_ORIGINS", "http://localhost:8000,http://127.0.0.1:8000,http://localhost:3000"
)
_cors_origins = [o.strip() for o in _cors_raw.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_headers=["Authorization", "Content-Type"],
    allow_methods=["GET"],
)

# Prometheus instrumentation
app.add_middleware(PrometheusMiddleware)


# -- Request logging ---------------------------------------------------


@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log every request with method, path, status, and duration."""
    start = time.perf_counter()
    response = await call_next(request)
    ms = (time.perf_counter() - start) * 1000
    logger.info("%s %s %d %.0fms",
                request.method, request.url.path,
                response.status_code, ms)
    return response


# -- Concurrent User Enforcement Middleware ----------------------------
# Tracks active user OIDs in Redis and rejects new users once the
# MAX_CONCURRENT_USERS cap is reached. Only enforced on auth-required
# endpoints (those that pass a Bearer token). Service API key calls
# and public endpoints bypass the check.

_PUBLIC_PATHS = {
    "/api/health", "/api/config", "/api/services", "/metrics",
    "/api/session/release", "/docs", "/redoc", "/openapi.json",
}


@app.middleware("http")
async def enforce_concurrent_users(request: Request, call_next):
    """Block new users if the concurrent-user cap has been reached."""
    path = request.url.path

    # Skip for public / static paths
    if (
        path in _PUBLIC_PATHS
        or not path.startswith("/api/")
    ):
        return await call_next(request)

    # Extract the Bearer token to get the user OID
    auth_header = request.headers.get("authorization", "")
    if not auth_header.lower().startswith("bearer "):
        return await call_next(request)

    token = auth_header[7:]

    # Service API key? Skip user-limit enforcement
    from .auth import SERVICE_API_KEY
    import secrets as _secrets
    if SERVICE_API_KEY and _secrets.compare_digest(token, SERVICE_API_KEY):
        return await call_next(request)

    # Decode the JWT without full validation (auth middleware handles that)
    # just to extract the user OID for tracking.
    try:
        import base64
        payload_b64 = token.split(".")[1]
        # Add padding
        payload_b64 += "=" * (4 - len(payload_b64) % 4)
        import json as _json
        claims = _json.loads(base64.urlsafe_b64decode(payload_b64))
        user_oid = claims.get("oid") or claims.get("sub") or ""
    except Exception:
        # If we can't decode, let the auth middleware reject it
        return await call_next(request)

    if not user_oid:
        return await call_next(request)

    # Try to register this user
    if not cache.register_active_user(user_oid):
        logger.warning(
            "Concurrent user limit reached (%d). Rejected OID: %s",
            cache.MAX_CONCURRENT_USERS, user_oid[:8],
        )
        return JSONResponse(
            status_code=429,
            content={
                "detail": (
                    f"Maximum concurrent users ({cache.MAX_CONCURRENT_USERS}) "
                    f"reached. Please try again later."
                ),
            },
        )

    # User admitted — refresh their session timestamp on every request
    cache.refresh_active_user(user_oid)
    return await call_next(request)


# -- Session Release Endpoint -----------------------------------------


@app.post("/api/session/release")
async def api_release_session(request: Request):
    """Explicitly release a user session (called on logout / tab close).

    Accepts a JSON body: {"oid": "user-object-id"}
    """
    try:
        body = await request.json()
        oid = body.get("oid", "")
        if oid:
            cache.remove_active_user(oid)
            return {"status": "released"}
    except Exception:
        pass
    return {"status": "no-op"}


# -- Public Endpoints (no auth) ----------------------------------------


@app.get("/api/health")
def api_health():
    """Health check with cache stats and active user count (public)."""
    stats = cache.get_cache_stats()
    return {
        "status": "healthy",
        "cwe_count": len(cwe_data),
        "cache": stats,
        "active_users": cache.get_active_user_count(),
        "max_concurrent_users": cache.MAX_CONCURRENT_USERS,
    }


@app.get("/api/config")
def api_config():
    """Return Entra ID client config for MSAL.js (public)."""
    return {
        "client_id": os.environ.get("AZURE_CLIENT_ID", ""),
        "tenant_id": os.environ.get("AZURE_TENANT_ID", ""),
    }


@app.get("/api/services")
def api_services():
    """Return monitoring and infra service URLs for the frontend nav (public)."""
    return {
        "grafana": os.environ.get("GRAFANA_URL", "http://localhost:3000"),
        "prometheus": os.environ.get("PROMETHEUS_URL", "http://localhost:9090"),
        "alertmanager": os.environ.get("ALERTMANAGER_URL", "http://localhost:9093"),
        "loki": os.environ.get("LOKI_URL", "http://localhost:3100"),
        "locust": os.environ.get("LOCUST_URL", "http://localhost:8089"),
        "argocd": os.environ.get("ARGOCD_URL", "https://argocd.reondev.top"),
        "redis": os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
        "redis-exporter": os.environ.get("REDIS_EXPORTER_URL", "http://localhost:9121"),
        "kube-state-metrics": os.environ.get("KUBE_STATE_METRICS_URL", "http://localhost:8080"),
        "node-exporter": os.environ.get("NODE_EXPORTER_URL", "http://localhost:9100"),
    }


# -- CWE Endpoints (auth required) ------------------------------------


# Curated well-known and trending CWE IDs for the homepage
FEATURED_CWE_IDS = [
    # OWASP Top 10 & high-profile weaknesses
    "79",   # Cross-site Scripting (XSS)
    "89",   # SQL Injection
    "78",   # OS Command Injection
    "287",  # Improper Authentication
    "862",  # Missing Authorization
    "22",   # Path Traversal
    "352",  # Cross-Site Request Forgery (CSRF)
    "502",  # Deserialization of Untrusted Data
    "918",  # Server-Side Request Forgery (SSRF)
    "611",  # XML External Entity (XXE)
    # Supply chain & modern threats
    "1357",  # Reliance on Insufficiently Trustworthy Component
    "494",  # Download of Code Without Integrity Check
    "829",  # Inclusion of Functionality from Untrusted Control Sphere
    "426",  # Untrusted Search Path
    "327",  # Use of a Broken or Risky Cryptographic Algorithm
    # Memory safety
    "787",  # Out-of-bounds Write
    "125",  # Out-of-bounds Read
    "416",  # Use After Free
    "476",  # NULL Pointer Dereference
    "119",  # Buffer Overflow
    # Access control & secrets
    "798",  # Hard-coded Credentials
    "200",  # Information Disclosure
    "269",  # Improper Privilege Management
    "434",  # Unrestricted File Upload
    # Injection & logic
    "94",   # Code Injection
    "20",   # Improper Input Validation
    "400",  # Uncontrolled Resource Consumption
    "362",  # Race Condition
    "601",  # Open Redirect
    "190",  # Integer Overflow
]


@app.get("/api/cwe/featured", response_model=List[CWEEntry])
def api_featured_cwes(
    _user: dict = Depends(get_current_user),
):
    """Return curated list of well-known and trending CWEs for the homepage."""
    featured = []
    for cwe_id in FEATURED_CWE_IDS:
        if cwe_id in cwe_dict:
            featured.append(cwe_dict[cwe_id])
    return featured


@app.get("/api/cwe", response_model=List[CWEEntry])
def api_search_cwes(
    query: str = Query(
        None, description="Search by ID or Name substring"
    ),
    limit: int = Query(10, le=100),
    _user: dict = Depends(get_current_user),
):
    """Search for CWEs by string query."""
    if not query:
        return cwe_data[:limit]

    query_lower = sanitize_search_query(query).lower()
    results = [
        cwe for cwe in cwe_data
        if query_lower in cwe.name.lower()
        or query_lower in cwe.id.lower()
        or query_lower in cwe.description.lower()
    ]
    return results[:limit]


@app.get("/api/cwe/suggestions")
def api_cwe_suggestions(
    q: str = Query(..., min_length=1, description="Search prefix"),
    _user: dict = Depends(get_current_user),
):
    """Get CWE search suggestions based on partial input."""
    q = sanitize_search_query(q)
    suggestions = []

    q_lower = q.lower()

    # Check if it looks like a CWE ID
    cwe_match = q.replace("CWE-", "").replace("cwe-", "").strip()
    if cwe_match.isdigit():
        matched = [
            cwe for cwe in cwe_data
            if cwe.id.startswith(cwe_match)
        ][:5]
        for cwe in matched:
            suggestions.append({
                "type": "cwe",
                "text": f"CWE-{cwe.id}: {cwe.name}",
                "action": f"/cwe/{cwe.id}"
            })
        if not matched:
            suggestions.append({
                "type": "tip",
                "text": f"No CWE found with ID starting with {cwe_match}",
                "action": ""
            })
        return suggestions[:8]

    # Suggest matching CWEs by name
    matched_cwes = [
        cwe for cwe in cwe_data
        if q_lower in cwe.name.lower()
        or q_lower in cwe.description.lower()
    ][:6]
    for cwe in matched_cwes:
        suggestions.append({
            "type": "cwe",
            "text": f"CWE-{cwe.id}: {cwe.name}",
            "action": f"/cwe/{cwe.id}"
        })

    # Suggest keyword searches for common weakness categories
    common_topics = [
        "injection", "authentication", "authorization",
        "buffer overflow", "cross-site scripting", "cryptographic",
        "input validation", "memory", "race condition",
        "deserialization", "path traversal", "privilege",
        "resource management", "information disclosure",
        "command injection", "file upload"
    ]
    matched_topics = [
        t for t in common_topics if q_lower in t
    ][:3]
    for topic in matched_topics:
        suggestions.append({
            "type": "keyword",
            "text": topic.title(),
            "action": f"/search?keyword={topic}"
        })

    return suggestions[:8]


@app.get("/api/cwe/{cwe_id}", response_model=CWEEntry)
async def api_get_cwe(
    cwe_id: str,
    _user: dict = Depends(get_current_user),
):
    """Retrieve a single CWE by its numeric ID."""
    cwe_id = validate_cwe_id(cwe_id)
    if cwe_id in cwe_dict:
        return cwe_dict[cwe_id]
    result = await fetch_cwe_from_nvd(cwe_id)
    if not result:
        raise HTTPException(status_code=404, detail="CWE not found")
    return result


@app.get("/api/cwe/{cwe_id}/cves", response_model=List[CVESearchResult])
async def api_get_cwe_cves(
    cwe_id: str,
    _user: dict = Depends(get_current_user),
):
    """Get CVEs associated with a specific CWE."""
    cwe_id = validate_cwe_id(cwe_id)
    results = await search_cves(cwe_id=f"CWE-{cwe_id}")
    return results


# -- CVE Detail Endpoint (cross-reference from CWE pages) -----------


@app.get("/api/cve/{cve_id}", response_model=CVEDetail)
async def api_get_cve(
    cve_id: str,
    _user: dict = Depends(get_current_user),
):
    """Get full details for a specific CVE."""
    cve_id = validate_cve_id(cve_id)
    result = await get_cve(cve_id)
    if not result:
        raise HTTPException(status_code=404, detail="CVE not found")
    return result


# -- CVE ATT&CK Mapping -----------------------------------------------


@app.get("/api/cve/{cve_id}/attack")
async def api_cve_attack_mapping(
    cve_id: str,
    _user: dict = Depends(get_current_user),
):
    """Get MITRE ATT&CK techniques mapped to a CVE via its CWE(s) and CAPEC."""
    cve_id = validate_cve_id(cve_id)
    result = await get_cve(cve_id)
    if not result:
        raise HTTPException(status_code=404, detail="CVE not found")

    all_capec_ids = []
    cwe_details = []
    for cwe_ref in result.cwe_ids:
        cwe_num = cwe_ref.replace("CWE-", "")
        cwe = cwe_dict.get(cwe_num)
        if cwe and cwe.related_attack_patterns:
            all_capec_ids.extend(cwe.related_attack_patterns)
            cwe_details.append({"id": cwe.id, "name": cwe.name})

    techniques = attack_parser.get_techniques_for_capec_list(all_capec_ids)
    tactics = attack_parser.get_tactics_for_techniques(techniques)

    return {
        "cve_id": cve_id,
        "cwe_sources": cwe_details,
        "capec_ids": list(set(all_capec_ids)),
        "tactics": [t.model_dump() for t in tactics],
        "techniques": [t.model_dump() for t in techniques],
    }


# -- ATT&CK Endpoints (auth required) --------------------------------


@app.get("/api/attack/tactics")
def api_attack_tactics(
    _user: dict = Depends(get_current_user),
):
    """Get all MITRE ATT&CK tactics."""
    tactics = attack_parser.get_tactics()
    return list(tactics.values())


@app.get("/api/attack/techniques")
def api_attack_techniques(
    tactic: str = Query(None, description="Filter by tactic ID"),
    _user: dict = Depends(get_current_user),
):
    """Get ATT&CK techniques, optionally filtered by tactic."""
    techniques = attack_parser.get_techniques()
    if tactic:
        return [
            t for t in techniques.values()
            if tactic in t.tactics and not t.is_subtechnique
        ]
    return [t for t in techniques.values() if not t.is_subtechnique]


@app.get("/api/attack/cwe-map")
def api_attack_cwe_map(
    _user: dict = Depends(get_current_user),
):
    """Return technique_id → list of mapped CWE IDs for matrix highlighting.

    Merges two mapping directions:
    1. Forward: CWE XML related_attack_patterns → CAPEC → ATT&CK
    2. Reverse: CAPEC STIX CWE refs → CAPEC → ATT&CK
    """
    tech_to_cwes: dict = {}

    # Direction 1: CWE XML → CAPEC → ATT&CK (original)
    for cwe in cwe_data:
        if not cwe.related_attack_patterns:
            continue
        techs = attack_parser.get_techniques_for_capec_list(
            cwe.related_attack_patterns
        )
        for tech in techs:
            tech_to_cwes.setdefault(tech.id, []).append({
                "id": cwe.id,
                "name": cwe.name,
            })

    # Direction 2: CAPEC STIX → CWE refs (reverse mapping)
    reverse_map = attack_parser.get_reverse_cwe_map()
    for tech_id, cwe_ids in reverse_map.items():
        existing = tech_to_cwes.setdefault(tech_id, [])
        existing_ids = {c["id"] for c in existing}
        for cwe_id in cwe_ids:
            if cwe_id not in existing_ids:
                cwe_entry = cwe_dict.get(cwe_id)
                name = cwe_entry.name if cwe_entry else f"CWE-{cwe_id}"
                existing.append({"id": cwe_id, "name": name})
                existing_ids.add(cwe_id)

    return tech_to_cwes


@app.get("/api/attack/technique/{technique_id}")
def api_attack_technique_detail(
    technique_id: str,
    _user: dict = Depends(get_current_user),
):
    """Get a single ATT&CK technique with its sub-techniques and mapped CWEs."""
    techniques = attack_parser.get_techniques()
    tech = techniques.get(technique_id)
    if not tech:
        raise HTTPException(status_code=404, detail="Technique not found")

    # Find sub-techniques
    subtechniques = [
        t for t in techniques.values()
        if t.parent_id == technique_id
    ]

    # Find CWEs that map to this technique via CAPEC (forward direction)
    mapped_cwes = []
    seen_cwe_ids = set()
    for cwe in cwe_data:
        for capec_id in cwe.related_attack_patterns:
            capec_techs = attack_parser.get_techniques_for_capec(capec_id)
            if any(t.id == technique_id for t in capec_techs):
                if cwe.id not in seen_cwe_ids:
                    mapped_cwes.append({
                        "id": cwe.id,
                        "name": cwe.name,
                    })
                    seen_cwe_ids.add(cwe.id)
                break

    # Add CWEs from reverse CAPEC→CWE mapping
    reverse_map = attack_parser.get_reverse_cwe_map()
    for cwe_id in reverse_map.get(technique_id, []):
        if cwe_id not in seen_cwe_ids:
            cwe_entry = cwe_dict.get(cwe_id)
            name = cwe_entry.name if cwe_entry else f"CWE-{cwe_id}"
            mapped_cwes.append({"id": cwe_id, "name": name})
            seen_cwe_ids.add(cwe_id)

    return {
        "technique": tech,
        "subtechniques": subtechniques,
        "mapped_cwes": mapped_cwes,
    }


# -- Analytics Endpoints ---------------------------------------------


@app.get("/api/analytics/top-cwes", response_model=List[CWEStats])
def api_top_cwes(
    limit: int = Query(10, le=50),
    _user: dict = Depends(get_current_user),
):
    """Get CWEs with the most associated CVEs."""
    all_cves = cache.get_all_cached_cves()
    return analytics.top_cwes(all_cves, cwe_dict, limit=limit)


@app.get("/api/analytics/cwe-risk", response_model=List[CWERiskScore])
def api_cwe_risk_scores(
    limit: int = Query(15, le=50),
    _user: dict = Depends(get_current_user),
):
    """CWE risk scores combining real-world frequency and severity.

    Cross-references CWE definitions (from MITRE XML) with cached
    CVE data (from NVD) to produce a composite risk ranking not
    available from either source alone.
    """
    all_cves = cache.get_all_cached_cves()
    return analytics.cwe_risk_scores(all_cves, cwe_dict, limit=limit)


# -- Static Files + SPA Fallback (must be last) --------------------

static_dir = os.path.join(os.path.dirname(__file__), "static")
if not os.path.exists(static_dir):
    os.makedirs(static_dir)

# Serve static assets (JS, CSS, images) from /assets
assets_dir = os.path.join(static_dir, "assets")
if not os.path.exists(assets_dir):
    os.makedirs(assets_dir)

app.mount(
    "/assets", StaticFiles(directory=assets_dir),
    name="static-assets",
)


# SPA fallback: any non-API, non-asset route serves index.html
_static_root = os.path.realpath(static_dir)

# Paths that must never be served — return 404 immediately instead of
# the SPA fallback so scanners/bots get no false-positive 200 signal.
_BLOCKED_PATHS = {
    # Environment / secrets files
    ".env", ".env.local", ".env.development", ".env.production",
    ".env.prod", ".env.staging", ".env.test", ".env.example",
    ".env.production.local", ".env.development.local",
    # Source control
    ".git", ".gitignore", ".gitconfig",
    # Config / infra files
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    "terraform.tfvars", "terraform.tfstate",
    ".terraform",
    # Dependency / package files
    "requirements.txt", "package.json", "package-lock.json",
    "yarn.lock", "Pipfile", "Pipfile.lock",
    # CI / secrets
    ".github", ".gitlab-ci.yml",
    # Server config files
    "web.config", ".htaccess", "nginx.conf",
    # Common scanner targets
    "phpinfo.php", "wp-admin", "wp-login.php",
    "server-status", "server-info",
    ".DS_Store",
}


@app.get("/{full_path:path}")
async def spa_fallback(full_path: str):
    """Serve index.html for all client-side routes (React Router)."""
    # Block sensitive filenames — return 404 instead of the SPA so
    # scanners don't receive a misleading 200 OK.
    top_segment = full_path.lstrip("/").split("/")[0] if full_path else ""
    if top_segment in _BLOCKED_PATHS:
        raise HTTPException(status_code=404, detail="Not Found")

    # Serve a real static file only if the resolved path stays inside
    # static_dir (prevents path traversal attacks like ../../etc/passwd).
    if full_path:
        safe_path = os.path.realpath(os.path.join(static_dir, full_path))
        if safe_path.startswith(_static_root + os.sep) and os.path.isfile(safe_path):
            return FileResponse(safe_path)

    # Otherwise serve the SPA entry point
    index_path = os.path.join(static_dir, "index.html")
    if os.path.isfile(index_path):
        return FileResponse(index_path)
    raise HTTPException(status_code=404, detail="Not Found")
