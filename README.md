# PureSecure CVE Explorer

**A real-time CVE vulnerability database with CWE mapping, analytics, observability, and Azure Entra ID authentication.**

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.135.1-009688)
![NVD API](https://img.shields.io/badge/NVD%20API-2.0-orange)
![Prometheus](https://img.shields.io/badge/Prometheus-v2.51.2-e6522c)
![Grafana](https://img.shields.io/badge/Grafana-10.4.2-f46800)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ed)
![License](https://img.shields.io/badge/License-MIT-green)

---

## Overview

PureSecure CVE Explorer is a web-based security vulnerability database that queries the **NIST National Vulnerability Database (NVD) API 2.0** in real time. It provides a clean, searchable interface for browsing CVEs (Common Vulnerabilities and Exposures), mapping them to CWE (Common Weakness Enumeration) classifications, and visualizing severity analytics.

The backend is built with **FastAPI** and serves a lightweight **vanilla JavaScript** frontend. An **SQLite caching layer** with a 24-hour TTL ensures fast responses while respecting NVD API rate limits. All API endpoints (except health and config) are protected by **Microsoft Entra ID (Azure AD) JWT authentication**. The full stack runs in **Docker Compose** with integrated **Prometheus** metrics, **Grafana** dashboards, and **Locust** load testing.

---

## Features

- **Real-time CVE Search** -- Debounced autocomplete suggestions with keyword, CWE, and severity filters
- **Detailed CVE Views** -- CVSS v2.0 and v3.1 scores with color-coded severity badges
- **Rich CWE Detail Pages** -- Full MITRE CWE data including consequences, mitigations, detection methods, taxonomy mappings, applicable platforms, and abstraction levels
- **Full CWE XML Dataset** -- Parses 969+ weakness definitions from the official MITRE CWE XML with auto-detected namespace versioning
- **Curated Homepage** -- 30 featured CWEs covering OWASP Top 10, supply chain attacks, memory safety, and modern threat categories
- **Severity Filtering** -- Filter by CRITICAL, HIGH, MEDIUM, or LOW
- **Analytics Dashboard** -- Severity distribution, top CWEs, and risk scoring
- **Azure Entra ID Authentication** -- JWT-based auth via MSAL.js and Microsoft JWKS
- **Prometheus Metrics** -- Request count, latency histograms, error rates, and in-progress gauges
- **Grafana Dashboards** -- Pre-provisioned dashboard with 18 panels across 5 sections
- **Locust Load Testing** -- Pre-built scenarios covering all API endpoints
- **Intelligent Caching** -- SQLite cache with 24-hour TTL and startup cleanup
- **Kubernetes Ready** -- Full Docker Desktop Kubernetes manifests with Ingress, ConfigMaps, Secrets, and AKS migration guide
- **Request Logging** -- Structured logs with method, path, status, and duration
- **Input Validation** -- Regex-based CVE/CWE ID validation and query sanitization
- **XSS Prevention** -- HTML escaping via `textContent` and `encodeURIComponent`
- **CI/CD Security Pipeline** -- Lint, SAST, SCA, secrets scan, SBOM, Trivy container scan, and Docker push
- **Dockerized** -- Single `docker compose up` deploys the full stack

---

## System Architecture

```mermaid
graph LR
    subgraph Frontend["Frontend (Vanilla JS + MSAL.js)"]
        direction TB
        A["index.html\nDashboard"]
        B["search.html\nSearch & Filter"]
        C["cve.html\nCVE Detail"]
        D["cwe.html\nCWE Detail"]
    end

    subgraph Backend["Backend (FastAPI)"]
        direction TB
        E["main.py\nAPI Routes + Middleware"]
        F["security.py\nInput Validation"]
        G["nvd_client.py\nNVD API Client"]
        H["cwe_parser.py\nCWE Data Provider"]
        I["analytics.py\nData Aggregation"]
        J["cache.py\nSQLite Cache Layer"]
        AA["auth.py\nEntra ID JWT Auth"]
        AB["metrics.py\nPrometheus Metrics"]
    end

    subgraph Observability["Observability Stack"]
        P["Prometheus\nMetrics Collection"]
        GR["Grafana\nDashboards"]
        LO["Locust\nLoad Testing"]
    end

    subgraph External["External Services"]
        K[("NVD API 2.0\nservices.nvd.nist.gov")]
        AZ[("Microsoft Entra ID\nlogin.microsoftonline.com")]
    end

    subgraph Storage["Local Storage"]
        L[("SQLite\ncache.db")]
    end

    A & B & C & D -- "Bearer Token\nHTTP / JSON" --> E
    E --> F
    E --> G
    E --> H
    E --> I
    E --> AA
    E --> AB
    G --> J
    H --> J
    J --> L
    G -- "Rate Limited\n~5 req / 30s" --> K
    I --> J
    AA -- "JWKS Validation" --> AZ
    AB -- "/metrics" --> P
    P --> GR
    LO -- "HTTP Traffic" --> E

    style A fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    style B fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    style C fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    style D fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    style E fill:#d1fae5,stroke:#10b981,color:#064e3b
    style F fill:#d1fae5,stroke:#10b981,color:#064e3b
    style G fill:#d1fae5,stroke:#10b981,color:#064e3b
    style H fill:#d1fae5,stroke:#10b981,color:#064e3b
    style I fill:#d1fae5,stroke:#10b981,color:#064e3b
    style J fill:#d1fae5,stroke:#10b981,color:#064e3b
    style AA fill:#fce7f3,stroke:#ec4899,color:#831843
    style AB fill:#fce7f3,stroke:#ec4899,color:#831843
    style P fill:#fff7ed,stroke:#f97316,color:#7c2d12
    style GR fill:#fff7ed,stroke:#f97316,color:#7c2d12
    style LO fill:#fff7ed,stroke:#f97316,color:#7c2d12
    style K fill:#fed7aa,stroke:#f97316,color:#7c2d12
    style AZ fill:#fed7aa,stroke:#f97316,color:#7c2d12
    style L fill:#e9d5ff,stroke:#7c3aed,color:#3b0764
```

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| **Backend Framework** | FastAPI 0.135.1 |
| **ASGI Server** | Uvicorn |
| **Language** | Python 3.10+ |
| **Async HTTP Client** | httpx |
| **Data Validation** | Pydantic v2 |
| **Database** | SQLite3 (caching, WAL mode) |
| **Authentication** | Microsoft Entra ID (Azure AD) via PyJWT + JWKS |
| **Metrics** | prometheus-client (Counter, Histogram, Gauge) |
| **Monitoring** | Prometheus v2.51.2 + Grafana 10.4.2 |
| **Load Testing** | Locust 2.24.1 |
| **XML Security** | defusedxml (XXE prevention) |
| **Frontend** | Vanilla JavaScript, HTML5, CSS3, MSAL.js |
| **Containerization** | Docker + Docker Compose |
| **Testing** | pytest, respx (HTTP mocking) |
| **Security Scanning** | bandit, flake8 |

---

## Project Structure

```
cve-new-bri/
├── app/                                # Application source code
│   ├── __init__.py
│   ├── main.py                         # FastAPI app, routes, middleware, lifespan
│   ├── models.py                       # Pydantic models (CVEDetail, CWEEntry, etc.)
│   ├── auth.py                         # Microsoft Entra ID JWT validation (JWKS)
│   ├── metrics.py                      # Prometheus middleware (count, latency, gauge)
│   ├── nvd_client.py                   # NVD API 2.0 client with rate limiting
│   ├── cwe_parser.py                   # Full MITRE CWE XML parser (969+ weaknesses)
│   ├── cache.py                        # SQLite cache (WAL mode, 24h TTL, cleanup)
│   ├── analytics.py                    # Top CWEs, risk scoring
│   ├── security.py                     # Input validation (CVE/CWE regex, sanitization)
│   └── static/                         # Frontend web assets
│       ├── index.html                  # Dashboard homepage
│       ├── search.html                 # Search with filters and pagination
│       ├── cve.html                    # CVE detail view (CVSS, CWEs, products)
│       ├── cwe.html                    # CWE detail view (consequences, mitigations, detections)
│       ├── login.html                  # Microsoft Entra ID login page
│       ├── 404.html                    # Custom 404 error page
│       ├── style.css                   # Design system with CSS variables
│       ├── common.js                   # Shared utilities (XSS prevention, fetch)
│       ├── auth.js                     # MSAL.js authentication logic
│       ├── dashboard.js                # Homepage logic
│       ├── search.js                   # Search with debounced suggestions
│       ├── cve.js                      # CVE detail rendering
│       └── cwe.js                      # CWE detail rendering
├── monitoring/                         # Observability configuration
│   ├── prometheus/
│   │   ├── prometheus.yml              # Scrape config (15s interval)
│   │   └── rules/
│   │       ├── recording_rules.yml     # 17 pre-computed queries
│   │       └── alerting_rules.yml      # 11 alert rules (errors, latency, traffic)
│   └── grafana/
│       ├── provisioning/
│       │   ├── datasources/
│       │   │   └── datasource.yml      # Auto-configure Prometheus datasource
│       │   └── dashboards/
│       │       └── dashboard.yml       # Auto-load dashboard JSON
│       └── dashboards/
│           └── cwe-explorer.json       # 18-panel monitoring dashboard
├── locust/
│   └── locustfile.py                   # Load test scenarios (all endpoints)
├── tests/                              # Test suite
│   ├── test_main.py                    # API endpoint integration tests
│   ├── test_auth.py                    # Authentication / JWT validation tests
│   ├── test_cwe_parser.py              # CWE data provider tests
│   ├── test_nvd_client.py              # NVD response parser tests
│   └── test_security.py               # Input validation tests
├── data/                               # Auto-created: SQLite cache database
├── k8s/                               # Kubernetes deployment manifests
│   ├── namespace.yaml                 # puresecure namespace
│   ├── ingress.yaml                   # NGINX Ingress (host-based routing)
│   ├── setup.sh                      # One-command Kubernetes deployment
│   ├── app/                           # Web app: Deployment, Service, ConfigMap, Secret, PVC
│   ├── prometheus/                    # Prometheus: Deployment, Service, ConfigMap
│   └── grafana/                       # Grafana: Deployment, Service, ConfigMaps, PVC
├── docs/
│   ├── REPORT.md                       # Security design report
│   └── kubernetes-deployment.md        # K8s deployment guide (Docker Desktop + AKS)
├── .env.example                        # Environment variable template
├── Dockerfile                          # Multi-stage Python 3.10-slim image
├── docker-compose.yml                  # Full stack: web, prometheus, grafana, locust
├── requirements.txt                    # Python dependencies
├── requirements-dev.txt                # Dev dependencies (pytest, bandit, flake8)
├── pyproject.toml                      # Project metadata, tool config
├── .gitignore
└── .dockerignore
```

---

## Installation & Usage

### Option 1: Docker Compose (Recommended)

This deploys the full stack: API, Prometheus, Grafana, and Locust.

```bash
# 1. Clone the repository
git clone <repository-url>
cd cve-new-bri

# 2. Create a .env file with your Azure Entra ID credentials
echo "AZURE_TENANT_ID=your-tenant-id" > .env
echo "AZURE_CLIENT_ID=your-client-id" >> .env

# 3. Build and start all services
docker compose up --build
```

#### Service URLs

| Service | URL | Credentials |
|---------|-----|-------------|
| **CWE Explorer API** | http://localhost:8000 | Azure Entra ID token |
| **API Docs (Swagger)** | http://localhost:8000/docs | — |
| **Prometheus** | http://localhost:9090 | — |
| **Grafana** | http://localhost:3000 | See `.env` (`GF_ADMIN_USER` / `GF_ADMIN_PASSWORD`) |
| **Locust** | http://localhost:8089 | — |

### Option 2: Local Development

```bash
# 1. Clone and enter the project
git clone <repository-url>
cd cve-new-bri

# 2. Create and activate a virtual environment
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set environment variables
set AZURE_TENANT_ID=your-tenant-id
set AZURE_CLIENT_ID=your-client-id

# 5. Start the server
uvicorn app.main:app --reload

# 6. Open in browser: http://localhost:8000
```

### Run Tests

```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Run all tests
pytest

# Verbose with short tracebacks
pytest -v --tb=short

# Security scan
bandit -r app/

# Lint check
flake8 app/
```

---

## Authentication

All API endpoints except `/api/health`, `/api/config`, and `/metrics` require a valid **Microsoft Entra ID (Azure AD) Bearer token**.

### How It Works

```mermaid
sequenceDiagram
    actor User
    participant FE as Frontend<br/>(MSAL.js)
    participant API as FastAPI<br/>(auth.py)
    participant AZ as Microsoft Entra ID

    User->>FE: Open app
    FE->>API: GET /api/config
    API-->>FE: {client_id, tenant_id}
    FE->>AZ: MSAL.js login (OAuth 2.0)
    AZ-->>FE: JWT access token
    User->>FE: Search for CVE
    FE->>API: GET /api/cwe?query=injection<br/>Authorization: Bearer <token>
    API->>AZ: Fetch JWKS (cached 1h)
    AZ-->>API: Signing keys
    API->>API: Validate JWT (RS256, audience check)
    API-->>FE: JSON response
    FE-->>User: Rendered results
```

### Configuration

| Environment Variable | Description |
|---------------------|-------------|
| `AZURE_TENANT_ID` | Your Azure AD tenant ID |
| `AZURE_CLIENT_ID` | App registration client ID (used as JWT `audience`) |

The auth module (`app/auth.py`) uses the Microsoft common JWKS endpoint with issuer validation disabled to support multi-tenant and personal Microsoft accounts.

---

## API Reference

### Public Endpoints (No Auth)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health` | Health check with cache stats |
| `GET` | `/api/config` | Entra ID client config for MSAL.js |
| `GET` | `/metrics` | Prometheus metrics (text format) |

### CWE Endpoints (Auth Required)

| Method | Endpoint | Description | Parameters |
|--------|----------|-------------|------------|
| `GET` | `/api/cwe` | List or search CWEs | `query`, `limit` (default: 10, max: 100) |
| `GET` | `/api/cwe/featured` | Curated well-known and trending CWEs | -- |
| `GET` | `/api/cwe/suggestions` | Autocomplete suggestions | `q` (required, min 1 char) |
| `GET` | `/api/cwe/{cwe_id}` | Single CWE detail | Path: numeric ID (e.g., `79`) |
| `GET` | `/api/cwe/{cwe_id}/cves` | CVEs for a specific CWE | Path: numeric ID |

### CVE Endpoints (Auth Required)

| Method | Endpoint | Description | Parameters |
|--------|----------|-------------|------------|
| `GET` | `/api/cve/{cve_id}` | Full CVE details | Path: CVE ID (e.g., `CVE-2021-44228`) |

### Analytics Endpoints (Auth Required)

| Method | Endpoint | Description | Parameters |
|--------|----------|-------------|------------|
| `GET` | `/api/analytics/top-cwes` | CWEs with most associated CVEs | `limit` (default: 10, max: 50) |
| `GET` | `/api/analytics/cwe-risk` | CWE risk scores (frequency × severity) | `limit` (default: 15, max: 50) |

### Example Requests

```bash
# Health check (no auth)
curl http://localhost:8000/api/health

# Prometheus metrics (no auth)
curl http://localhost:8000/metrics

# Search CWEs (requires Bearer token)
curl -H "Authorization: Bearer <token>" \
  http://localhost:8000/api/cwe?query=injection

# Get CVE detail (requires Bearer token)
curl -H "Authorization: Bearer <token>" \
  http://localhost:8000/api/cve/CVE-2021-44228
```

### Example Response -- Health Check

```json
{
  "status": "healthy",
  "cwe_count": 937,
  "cache": {
    "cve_entries": 42,
    "search_entries": 8,
    "db_size_bytes": 462848
  }
}
```

---

## Observability

### Prometheus Metrics

The FastAPI app exposes a `/metrics` endpoint with the following metrics:

| Metric | Type | Description |
|--------|------|-------------|
| `http_requests_total` | Counter | Total requests by method, endpoint, status |
| `http_request_duration_seconds` | Histogram | Request latency with percentile-friendly buckets |
| `http_requests_in_progress` | Gauge | Currently active requests |

Path normalization prevents high-cardinality label explosion (e.g., `/api/cwe/79` → `/api/cwe/{id}`).

### Recording Rules (Pre-computed Queries)

17 recording rules in `monitoring/prometheus/rules/recording_rules.yml`:

| Query | What It Computes |
|-------|------------------|
| `cwe:http_requests:rate1m` | Total requests/sec |
| `cwe:http_requests_by_endpoint:rate1m` | Requests/sec per endpoint |
| `cwe:http_errors_5xx:rate1m` | Server error rate |
| `cwe:http_error_ratio_5xx` | % of requests returning 5xx |
| `cwe:http_latency_p50:5m` | Median response time |
| `cwe:http_latency_p95:5m` | 95th percentile latency |
| `cwe:http_latency_p99:5m` | 99th percentile latency |
| `cwe:http_availability:5m` | Availability % (1 − error ratio) |
| `cwe:http_in_progress:total` | Current concurrent requests |

### Alerting Rules

11 alerting rules in `monitoring/prometheus/rules/alerting_rules.yml`:

| Alert | Condition | Severity |
|-------|-----------|----------|
| **APIDown** | `/metrics` unreachable 2 min | Critical |
| **HighServerErrorRate** | > 5% of requests are 5xx | Critical |
| **LowAvailability** | Availability < 99% | Critical |
| **TrafficSpike** | 10× normal request rate | Critical |
| **CriticalP95Latency** | p95 > 5 seconds | Critical |
| **HighClientErrorRate** | > 25% requests are 4xx | Warning |
| **HighP95Latency** | p95 > 1 second | Warning |
| **HighP99Latency** | p99 > 3 seconds | Warning |
| **SlowEndpoint** | Any endpoint p95 > 2s | Warning |
| **NoTraffic** | Zero requests 10 min | Warning |
| **HighConcurrency** | > 50 in-progress requests | Warning |

### Grafana Dashboard

The pre-provisioned dashboard ("CWE Explorer -- API Monitoring") has 18 panels in 5 sections:

1. **📊 Overview** -- Total, 2xx, 4xx, 5xx request counts (stat panels)
2. **🚦 Traffic** -- Requests/sec, cumulative traffic, pie charts by endpoint/method/status
3. **⏱️ Latency** -- p50/p95/p99 percentiles, per-endpoint p95, avg bar gauge, heatmap
4. **🔴 Errors & Connections** -- 5xx error rate, in-progress requests
5. **📋 Request Log** -- Full table of all requests with method, endpoint, status, count, rate, and avg response time

### Locust Load Testing

The `locust/locustfile.py` defines weighted scenarios:

| Scenario | Weight | Endpoint |
|----------|--------|----------|
| List CWEs | 5 | `GET /api/cwe` |
| Search CWEs | 4 | `GET /api/cwe?query=...` |
| CWE Detail | 3 | `GET /api/cwe/{id}` |
| Suggestions | 3 | `GET /api/cwe/suggestions` |
| CWE CVEs | 2 | `GET /api/cwe/{id}/cves` |
| Top CWEs | 2 | `GET /api/analytics/top-cwes` |
| Risk Scores | 1 | `GET /api/analytics/cwe-risk` |
| Health Check | 1 | `GET /` |

Access the Locust UI at http://localhost:8089 to configure users and spawn rate.

---

## Docker Architecture

```mermaid
graph TD
    subgraph Docker Compose
        WEB["web\nFastAPI App\n:8000"]
        PROM["prometheus\nprom/prometheus:v2.51.2\n:9090"]
        GRAF["grafana\ngrafana/grafana:10.4.2\n:3000"]
        LOC["locust\nlocustio/locust:2.24.1\n:8089"]
    end

    PROM -- "scrape /metrics\nevery 15s" --> WEB
    GRAF -- "query" --> PROM
    LOC -- "load test\nHTTP traffic" --> WEB

    WEB -.- V1[("cwe-data\n/app/data")]
    PROM -.- V2[("prometheus-data\n/prometheus")]
    GRAF -.- V3[("grafana-data\n/var/lib/grafana")]

    style WEB fill:#d1fae5,stroke:#10b981,color:#064e3b
    style PROM fill:#fff7ed,stroke:#f97316,color:#7c2d12
    style GRAF fill:#fff7ed,stroke:#f97316,color:#7c2d12
    style LOC fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    style V1 fill:#e9d5ff,stroke:#7c3aed,color:#3b0764
    style V2 fill:#e9d5ff,stroke:#7c3aed,color:#3b0764
    style V3 fill:#e9d5ff,stroke:#7c3aed,color:#3b0764
```

---

## Backend Module Dependencies

```mermaid
graph TD
    MAIN["main.py\nFastAPI App & Routes"]
    MODELS["models.py\nPydantic Models"]
    NVD["nvd_client.py\nNVD API Client"]
    CWE["cwe_parser.py\nCWE Data Provider"]
    SEC["security.py\nInput Validation"]
    CACHE["cache.py\nSQLite Cache"]
    ANALYTICS["analytics.py\nData Aggregation"]
    AUTH["auth.py\nEntra ID JWT"]
    METRICS["metrics.py\nPrometheus"]
    DB[("SQLite DB\ncache.db")]
    EXT[("NVD API 2.0")]
    AZ[("Microsoft\nEntra ID")]

    MAIN --> MODELS
    MAIN --> NVD
    MAIN --> CWE
    MAIN --> SEC
    MAIN --> CACHE
    MAIN --> ANALYTICS
    MAIN --> AUTH
    MAIN --> METRICS

    NVD --> MODELS
    NVD --> CACHE
    CWE --> MODELS
    CWE --> CACHE
    ANALYTICS --> MODELS

    CACHE --> DB
    NVD --> EXT
    CWE --> EXT
    AUTH --> AZ

    style MAIN fill:#d1fae5,stroke:#10b981,color:#064e3b
    style MODELS fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    style NVD fill:#fef3c7,stroke:#f59e0b,color:#78350f
    style CWE fill:#fef3c7,stroke:#f59e0b,color:#78350f
    style SEC fill:#fce7f3,stroke:#ec4899,color:#831843
    style CACHE fill:#e9d5ff,stroke:#7c3aed,color:#3b0764
    style ANALYTICS fill:#ccfbf1,stroke:#14b8a6,color:#134e4a
    style AUTH fill:#fce7f3,stroke:#ec4899,color:#831843
    style METRICS fill:#fce7f3,stroke:#ec4899,color:#831843
    style DB fill:#f3f4f6,stroke:#6b7280,color:#1f2937
    style EXT fill:#fed7aa,stroke:#f97316,color:#7c2d12
    style AZ fill:#fed7aa,stroke:#f97316,color:#7c2d12
```

---

## Security

### Security Layers

| Layer | Protection | Implementation |
|-------|-----------|----------------|
| **Authentication** | Microsoft Entra ID JWT (RS256, audience validation) | `auth.py` -- JWKS cached 1h, multi-tenant support |
| **CORS** | Origin allowlist, restricted methods/headers | `main.py` -- only localhost:8000 origins, GET only |
| **CVE ID Validation** | Strict regex `^CVE-\d{4}-\d{4,}$` | `security.py` -- rejects malformed IDs |
| **CWE ID Validation** | Numeric-only regex `^\d+$` | `security.py` -- prevents injection |
| **Query Sanitization** | 200 char limit, allowlist `[\w\s\-.,]` | `security.py` -- sanitizes all search input |
| **SQL Injection Prevention** | Parameterized queries with `?` placeholders | `cache.py` -- all database operations |
| **XXE Prevention** | `defusedxml` instead of stdlib XML | `cwe_parser.py` -- blocks entity injection |
| **XSS Prevention** | `escapeHTML()` via `textContent` | `common.js` -- all frontend rendering |
| **Non-root Container** | `appuser:appgroup` in Docker | `Dockerfile` -- least privilege |
| **Rate Limiting** | 6-second min interval for NVD requests | `nvd_client.py` -- async sleep-based |

### Request / Response Data Flow

```mermaid
sequenceDiagram
    actor User
    participant FE as Frontend<br/>(MSAL.js)
    participant API as FastAPI<br/>(main.py)
    participant AUTH as Auth<br/>(auth.py)
    participant SEC as Security<br/>(security.py)
    participant NVD as NVD Client<br/>(nvd_client.py)
    participant CACHE as Cache<br/>(cache.py)
    participant DB as SQLite<br/>(cache.db)
    participant EXT as NVD API 2.0

    User->>FE: Enter CVE ID
    FE->>API: GET /api/cve/CVE-2021-44228<br/>Authorization: Bearer <token>
    API->>AUTH: Validate JWT (RS256 + JWKS)
    AUTH-->>API: Claims payload

    API->>SEC: validate_cve_id()
    SEC-->>API: Validated ID

    API->>NVD: get_cve(cve_id)
    NVD->>CACHE: get_cached_cve(cve_id)
    CACHE->>DB: SELECT FROM cve_cache

    alt Cache Hit (within 24h TTL)
        DB-->>CACHE: Cached JSON
        CACHE-->>NVD: CVE data dict
        NVD-->>API: CVEDetail model
    else Cache Miss or Expired
        DB-->>CACHE: None
        CACHE-->>NVD: None
        NVD->>EXT: GET /rest/json/cves/2.0?cveId=...
        Note over NVD,EXT: Rate limited: 6s min interval
        EXT-->>NVD: NVD JSON response
        NVD->>NVD: parse_nvd_cve()
        NVD->>CACHE: set_cached_cve()
        CACHE->>DB: INSERT OR REPLACE
        NVD-->>API: CVEDetail model
    end

    API-->>FE: JSON response
    FE->>FE: Render with escapeHTML()
    FE-->>User: CVE detail page
```

---

## Database / Cache Schema

```mermaid
erDiagram
    cve_cache {
        TEXT cve_id PK "e.g. CVE-2021-44228"
        TEXT response_json "Full CVEDetail as JSON"
        TEXT fetched_at "ISO 8601 timestamp"
    }

    search_cache {
        TEXT query_hash PK "SHA-256 of query params"
        TEXT response_json "Search results as JSON"
        TEXT fetched_at "ISO 8601 timestamp"
    }
```

**Cache behavior:**
- Both tables use `INSERT OR REPLACE` for upserts
- TTL is **24 hours**, checked at read time via `_is_expired()`
- Expired entries are cleaned up at startup via `cleanup_expired()`
- WAL journal mode enables concurrent reads without blocking writes
- `query_hash` is a SHA-256 hex digest of the serialized query parameters
- The database file is auto-created at `data/cache.db`

---

## Data Models

All data models are defined in `app/models.py` using Pydantic v2.

| Model | Fields | Purpose |
|-------|--------|---------|
| **CWEEntry** | `id`, `name`, `description`, `abstraction`, `status`, `extended_description`, `common_consequences`, `potential_mitigations`, `detection_methods`, `affected_resources`, `taxonomy_mappings`, `applicable_platforms`, `related_weaknesses` | Full CWE weakness definition |
| **Consequence** | `scope`, `impact`, `likelihood` | CWE consequence (e.g., Confidentiality / Read Memory / High) |
| **Mitigation** | `phase`, `description`, `effectiveness` | CWE mitigation strategy |
| **DetectionMethod** | `method`, `description`, `effectiveness` | How to detect the weakness |
| **CVSSScores** | `v2_score`, `v2_vector`, `v3_score`, `v3_vector`, `v3_severity` | CVSS v2/v3 scoring data |
| **AffectedProduct** | `vendor`, `product`, `version` | Vulnerable software from CPE |
| **Reference** | `url`, `source`, `tags` | External advisory links |
| **CVEDetail** | `cve_id`, `description`, `cvss`, `cwe_ids`, `references`, `affected_products`, `published`, `modified` | Full vulnerability record |
| **CVESearchResult** | `cve_id`, `description`, `severity`, `cvss_v3`, `published` | Lightweight search result |
| **CWEStats** | `cwe_id`, `cwe_name`, `cve_count` | CWE popularity ranking |
| **CWERiskScore** | `cwe_id`, `cwe_name`, `risk_score`, ... | Composite risk ranking |

---

## Configuration

| Variable / Constant | Value | Location | Description |
|---------------------|-------|----------|-------------|
| `AZURE_TENANT_ID` | (env var) | `docker-compose.yml` | Azure AD tenant ID |
| `AZURE_CLIENT_ID` | (env var) | `docker-compose.yml` | App registration client ID |
| `TTL_HOURS` | `24` | `app/cache.py` | Cache expiration time |
| `DB_PATH` | `data/cache.db` | `app/cache.py` | SQLite database location |
| `NVD_BASE_URL` | `services.nvd.nist.gov/...` | `app/nvd_client.py` | NVD API endpoint |
| `REQUEST_TIMEOUT` | `30.0` | `app/nvd_client.py` | HTTP timeout (seconds) |
| `_MIN_INTERVAL` | `6.0` | `app/nvd_client.py` | Rate limit interval |
| `MAX_QUERY_LENGTH` | `200` | `app/security.py` | Max search query length |
| `_JWKS_TTL` | `1 hour` | `app/auth.py` | JWKS key cache duration |

---

## Testing

### Test Modules

| Module | Description |
|--------|-------------|
| `test_main.py` | API endpoint integration tests using `TestClient` and mocked NVD calls |
| `test_auth.py` | Authentication and JWT validation tests (token rejection, public endpoints) |
| `test_cwe_parser.py` | CWE data provider tests (XML parsing + fallback) |
| `test_nvd_client.py` | NVD response parser tests (CVSS v2/v3, CWE IDs, CPE products, dates) |
| `test_security.py` | Input validation tests including SQL injection and XSS payload rejection |

---

## CI/CD Pipeline

The project uses a GitHub Actions pipeline (`.github/workflows/ci-cd.yml`) with 9 stages following the shift-left security principle:

| Stage | Tool | Purpose |
|-------|------|---------|
| 1. Lint | Flake8 | Code quality and PEP 8 compliance |
| 2. SAST | Bandit | Python security pattern analysis |
| 3. SAST | CodeQL | Semantic code analysis (Python + JavaScript) |
| 4. SCA | Safety + pip-audit | Dependency vulnerability scanning |
| 5. Secrets | Gitleaks | Detect committed secrets in git history |
| 6. SBOM | CycloneDX | Software Bill of Materials (JSON + XML) |
| 7. Test | pytest | Unit and integration tests with coverage |
| 8. Docker Build | Docker Buildx | Build container image with GitHub Actions cache |
| 9. Trivy Scan | Trivy | Container vulnerability scanning (SARIF upload to GitHub Security) |
| 10. Docker Push | Docker Push | Push to DockerHub on main/master branch |

Stages 1--7 run in parallel on every push and pull request. Stages 8--10 run sequentially on push to `main`/`master` after all other stages pass.

### DockerHub Deployment

The pipeline automatically builds the Docker image and pushes it to DockerHub with two tags:

- **`latest`** -- always points to the most recent main branch build
- **`<short-sha>`** -- the 7-character commit SHA for precise version tracking

**Required repository secrets:**

| Secret | Description |
|--------|-------------|
| `DOCKERHUB_USERNAME` | DockerHub account username |
| `DOCKERHUB_TOKEN` | DockerHub access token ([create one here](https://hub.docker.com/settings/security)) |

### Running the Pipeline Locally

```bash
# Lint
flake8 app/ tests/ --max-line-length=100

# Security scan
bandit -r app/ -ll

# Tests with coverage
pytest tests/ -v --tb=short --cov=app

# Docker build (local)
docker build -t puresecure-cve-explorer .
```

---

## Kubernetes Deployment

The project includes full Kubernetes manifests for local development (Docker Desktop) and production (AKS).

```bash
# Quick start with Docker Desktop Kubernetes
chmod +x k8s/setup.sh
./k8s/setup.sh

# Or manually
# Ensure Kubernetes is enabled in Docker Desktop settings
kubectl apply -f k8s/namespace.yaml
kubectl create secret generic app-secrets -n puresecure \
  --from-literal=SERVICE_API_KEY="your-key" \
  --from-literal=GF_ADMIN_PASSWORD="admin" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f k8s/app/ -f k8s/prometheus/ -f k8s/grafana/ -f k8s/ingress.yaml

# Access via port-forward
kubectl port-forward svc/web 8000:8000 -n puresecure
```

See [docs/kubernetes-deployment.md](docs/kubernetes-deployment.md) for the full step-by-step guide, troubleshooting, and AKS migration notes.

---

## Acknowledgments

- **[NIST NVD](https://nvd.nist.gov/)** -- National Vulnerability Database, the source of all CVE data
- **[MITRE CWE](https://cwe.mitre.org/)** -- Common Weakness Enumeration definitions
- **[FastAPI](https://fastapi.tiangolo.com/)** -- Modern Python web framework
- **[Prometheus](https://prometheus.io/)** -- Metrics collection and alerting
- **[Grafana](https://grafana.com/)** -- Observability dashboards
- **[Locust](https://locust.io/)** -- Load testing framework
- **[Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/)** -- Identity platform
