# PureSecure CVE Explorer -- Main Report

---

## 1. System Functionality Summary

### What the System Does

PureSecure CVE Explorer is a web-based security intelligence platform that analyses the global vulnerability landscape by querying the **NIST National Vulnerability Database (NVD) API 2.0** in real time. It collects, processes, and presents CVE (Common Vulnerabilities and Exposures) data to help security professionals, developers, and researchers understand emerging threats and prioritise remediation efforts.

### Security Threat Landscape Analysis

The system performs the following analyses to provide actionable security insights:

**Vulnerability Discovery and Search** -- Users can search the entire NVD database by keyword (e.g., "log4j", "remote code execution"), by CWE classification (e.g., CWE-79 for Cross-Site Scripting), or by CVSS severity level (CRITICAL, HIGH, MEDIUM, LOW). The search engine uses a two-step probe approach: it first queries the NVD to determine the total number of matching results, then fetches the most recently published page, ensuring users always see the newest threats first.

**Severity Scoring and Risk Assessment** -- Each vulnerability is displayed with both CVSS v2.0 and CVSS v3.1 scores, vector strings, and severity classifications. Colour-coded badges provide immediate visual risk identification -- a CRITICAL vulnerability (score 9.0-10.0) is instantly distinguishable from a LOW one (score 0.1-3.9). This enables rapid triage of which vulnerabilities demand urgent attention.

**Weakness Classification Mapping** -- The system maps every CVE to its underlying CWE (Common Weakness Enumeration) category. This allows analysts to identify not just individual vulnerabilities but systemic weakness patterns -- for example, discovering that a software vendor has repeated SQL Injection (CWE-89) issues indicates a fundamental input validation gap in their development practices. The system includes 37 built-in CWE definitions for the most commonly referenced weaknesses, with live NVD API fallback for less common ones.

**Trend Analytics** -- Three analytics engines aggregate cached vulnerability data to reveal patterns in the threat landscape:
- **Severity Distribution** counts how many cached CVEs fall into each severity category, showing whether the current threat environment skews towards critical or lower-risk issues.
- **Top CWEs** ranks weakness categories by frequency, revealing which vulnerability types (e.g., Out-of-bounds Write, Cross-Site Scripting) are most prevalent across the industry.
- **Severity Trends** groups vulnerabilities by year and severity level, enabling analysts to observe whether high-severity vulnerabilities are increasing or decreasing over time.

**Affected Product Identification** -- For each CVE, the system parses CPE (Common Platform Enumeration) data to identify exactly which vendors, products, and versions are affected. This enables organisations to cross-reference their software inventory against known vulnerabilities, supporting asset-based vulnerability management.

**Intelligent Caching for Continuous Monitoring** -- An SQLite caching layer with a 24-hour TTL stores previously fetched vulnerability data locally. This serves a dual purpose: it respects NVD API rate limits (~5 requests per 30 seconds without an API key) while also building a local vulnerability database that powers the analytics engine. As users search and browse, the cached dataset grows, providing increasingly comprehensive trend analysis.

---

## 2. Significant Design Decision for Secure Software

### Defence-in-Depth Input Validation Architecture

The most significant design decision for security is the **multi-layered input validation architecture** implemented across `security.py`, `cache.py`, and `common.js`. Rather than relying on a single validation point, the system enforces security at every boundary where untrusted data enters the application -- a textbook application of the defence-in-depth principle.

#### The Design

The system processes three categories of user input: CVE identifiers (e.g., `CVE-2021-44228`), CWE identifiers (e.g., `79`), and free-text search queries. Each category has its own dedicated validation function in the `security.py` module, following the principle of **allowlisting over denylisting** -- rather than attempting to block known malicious patterns (which attackers can bypass), the validators define exactly what constitutes valid input and reject everything else.

```
User Input --> FastAPI Route --> security.py Validation --> Business Logic --> cache.py (Parameterised SQL) --> SQLite
                                      |                                             |
                                 Reject invalid                              No string interpolation
                                 (HTTP 400)                                  (? placeholders only)
```

**CVE ID validation** uses the strict regex `^CVE-\d{4}-\d{4,}$`, which permits only the exact format defined by the MITRE CVE specification: the literal prefix "CVE-", followed by a four-digit year, a hyphen, and four or more digits. Input is normalised (stripped and uppercased) before validation. Any deviation -- including SQL injection attempts like `CVE-2021-44228' OR '1'='1` -- is rejected with HTTP 400 before reaching any business logic.

**CWE ID validation** uses the regex `^\d+$`, permitting only numeric characters. This is deliberately restrictive: while the application could accept the "CWE-" prefix, stripping it to a pure numeric value at the validation boundary eliminates an entire class of injection vectors.

**Search query sanitisation** applies a 200-character length limit and an allowlist regex `[\w\s\-.,]` that permits only word characters, whitespace, hyphens, dots, and commas. This removes control characters, angle brackets, quotes, semicolons, and other characters commonly used in SQL injection, XSS, and command injection attacks.

#### Why This Design is Significant

This design addresses **OWASP Top 10 A03:2021 (Injection)** -- the third most critical web application security risk. The decision to implement validation as a separate `security.py` module rather than inline within route handlers is architecturally important for three reasons:

1. **Centralisation prevents inconsistency.** Every route that accepts a CVE ID calls `validate_cve_id()`. If validation were implemented inline in each route handler, a developer adding a new endpoint might forget to validate, creating an injection vulnerability. The dedicated module makes validation a conscious, importable dependency that appears explicitly in each route's code.

2. **Testability enables confidence.** The `test_security.py` test suite includes specific test cases for SQL injection payloads (e.g., `CVE-2021-44228'; DROP TABLE--`), XSS payloads, and boundary conditions. Because validation is isolated in its own module, these security properties can be tested independently of the web framework, database, and external API.

3. **Layered defence tolerates individual failures.** Even if a validation function were bypassed (e.g., through a future code change), the cache layer provides a second line of defence: all SQL operations in `cache.py` use parameterised queries with `?` placeholders, never string interpolation. The database layer cannot be compromised by injection even if the validation layer fails. Similarly, the frontend provides a third layer: all user-derived data rendered in the browser passes through `escapeHTML()`, which uses the DOM's `textContent` property for safe encoding -- preventing stored XSS even if malicious data somehow reached the database.

This three-layer approach (input validation, parameterised queries, output encoding) means that no single point of failure can result in an injection vulnerability. Each layer independently prevents a different attack vector, and an attacker would need to bypass all three simultaneously to achieve exploitation.

---

## 3. Significant Implementation Decision for Secure Software

### Parameterised SQL Queries in the Cache Layer

The most significant implementation decision for security is the **exclusive use of parameterised queries** throughout `cache.py`, the module responsible for all SQLite database operations. This implementation directly prevents SQL injection -- the most dangerous and prevalent class of web application vulnerability (OWASP A03:2021).

#### The Implementation

Every database operation in `cache.py` passes user-influenced values through parameterised query placeholders (`?`) rather than string concatenation or f-string interpolation. Consider the core retrieval function:

```python
# cache.py, line 44-46 -- SECURE: parameterised query
cursor = conn.execute(
    "SELECT response_json, fetched_at FROM cve_cache WHERE cve_id = ?",
    (cve_id,)
)
```

The `cve_id` value -- which ultimately originates from user input in the URL path `/api/cve/{cve_id}` -- is passed as a parameter tuple `(cve_id,)`, separate from the SQL statement string. The SQLite driver handles escaping and quoting internally, making it structurally impossible for the value to alter the SQL statement's logic, regardless of what characters it contains.

This pattern is applied consistently across all six database operations in the module:

| Function | Line | SQL Operation | Parameterised |
|----------|------|---------------|---------------|
| `get_cached_cve()` | 44 | `SELECT ... WHERE cve_id = ?` | `(cve_id,)` |
| `set_cached_cve()` | 60 | `INSERT OR REPLACE ... VALUES (?, ?, ?)` | `(cve_id, json, timestamp)` |
| `get_cached_search()` | 78 | `SELECT ... WHERE query_hash = ?` | `(query_hash,)` |
| `set_cached_search()` | 95 | `INSERT OR REPLACE ... VALUES (?, ?, ?)` | `(hash, json, timestamp)` |
| `get_all_cached_cves()` | 111 | `SELECT response_json FROM cve_cache` | No user input |
| `_get_connection()` | 16 | `CREATE TABLE IF NOT EXISTS ...` | Schema only, no user input |

The search cache adds an additional defensive layer: the `_hash_query()` function (line 69-70) converts query parameters into a SHA-256 hash before using them as cache keys. This means that even the search cache lookup operates on a fixed-length hexadecimal string rather than raw user input, further reducing the attack surface.

```python
def _hash_query(query: str) -> str:
    return hashlib.sha256(query.encode()).hexdigest()
```

#### Why This Implementation is Significant

**Preventing real attack scenarios.** The application's test suite (`test_main.py`) includes an explicit SQL injection test case:

```python
def test_get_cve_sql_injection(self):
    response = self.client.get("/api/cve/CVE-2021-44228' OR '1'='1")
    assert response.status_code == 400
```

This test verifies that a classic SQL injection payload is rejected. However, the parameterised query implementation ensures that even if this payload somehow bypassed input validation and reached the database layer, the `?` placeholder would treat the entire string `CVE-2021-44228' OR '1'='1` as a literal value to match against the `cve_id` column -- the injected SQL clause `OR '1'='1'` would never be interpreted as SQL syntax.

**Contrast with the insecure alternative.** If the implementation had used string formatting:

```python
# INSECURE -- NOT used in this codebase
cursor = conn.execute(
    f"SELECT response_json FROM cve_cache WHERE cve_id = '{cve_id}'"
)
```

An attacker providing the input `' UNION SELECT sql FROM sqlite_master--` could extract the database schema, and further payloads could read or modify any data in the cache. The parameterised approach makes this structurally impossible at the database driver level, not merely blocked by application-level filtering.

**Defence in depth with connection management.** The implementation also demonstrates secure resource management: every database function follows a `try/finally` pattern that guarantees connection closure regardless of whether an exception occurs. This prevents connection leaks that could lead to denial-of-service conditions under load, and ensures that database locks are released promptly -- a subtle but important aspect of secure, reliable software.

```python
conn = _get_connection()
try:
    # database operation
finally:
    conn.close()
```

**Alignment with secure coding standards.** This implementation follows OWASP's SQL Injection Prevention Cheat Sheet (Defence Option 1: Prepared Statements with Parameterised Queries), CWE-89 (SQL Injection) mitigation guidance, and Python's `sqlite3` module best practices. The consistency of applying this pattern across every single database operation -- with no exceptions -- demonstrates that secure coding is a systematic practice in this codebase, not an afterthought applied selectively.

---

## 4. Significant DevSecOps Decision -- Multi-Stage CI/CD Security Pipeline

### The Decision

The most significant DevSecOps decision is the design of an **eight-stage CI/CD pipeline** that implements automated security gates at every phase of the build lifecycle, following the "shift-left" principle of detecting security issues as early and cheaply as possible.

### Pipeline Architecture

The `.github/workflows/ci-cd.yml` pipeline executes stages in this deliberate order:

| Stage | Tool | Purpose | Shift-Left Position |
|-------|------|---------|-------------------|
| 1. Lint | Flake8 | Code quality and style (PEP 8) | Earliest -- catches syntax issues |
| 2. SAST | Bandit | Python-specific security patterns | Pre-build static analysis |
| 3. SAST | CodeQL | Semantic code analysis (Python + JS) | Deep static analysis |
| 4. SCA | Safety + pip-audit | Dependency vulnerability scanning | Supply chain verification |
| 5. Secrets | Gitleaks | Detect committed secrets in git history | Repository-level scanning |
| 6. SBOM | CycloneDX | Software Bill of Materials generation | Supply chain transparency |
| 7. Test | pytest | Unit and integration tests with coverage | Functional verification |
| 8. Docker | Docker Build & Push | Build image and push to DockerHub | Deployment artefact |

### Why This Order Matters

The pipeline follows the **fail-fast principle**: cheap, fast checks (linting, static analysis) run before expensive, slow checks (integration tests, Docker build). If a flake8 style violation or a bandit-flagged insecure pattern is detected, the developer receives feedback within seconds rather than waiting for the full pipeline to complete. This ordering is prescribed by the OWASP DevSecOps Guideline and NIST SP 800-218 (Secure Software Development Framework), which recommend integrating security verification at every stage of the software lifecycle.

### Tool Selection Rationale

**Redundant SAST (Bandit + CodeQL):** Bandit specialises in Python-specific security patterns (e.g., use of `eval()`, hardcoded passwords, insecure `subprocess` calls) and produces results in seconds. CodeQL performs deeper semantic analysis, including taint tracking across function boundaries in both Python and JavaScript. Running both provides defence-in-depth: Bandit catches Python-specific issues CodeQL might miss, while CodeQL's cross-language dataflow analysis catches vulnerabilities that Bandit's pattern matching cannot detect.

**Redundant SCA (Safety + pip-audit):** Safety checks dependencies against the PyUp.io vulnerability database, while pip-audit queries the Python Packaging Advisory Database (PyPI). Different databases have different coverage and update cadences. Running both maximises the probability of detecting a known vulnerability in a dependency -- critical for a security-focused application where a vulnerable library would undermine the entire value proposition.

**Gitleaks for Secret Detection:** Gitleaks scans the entire git history, not just the current commit. This is essential because a secret committed and subsequently deleted remains in the git history unless the repository is rewritten. The tool detects API keys, private keys, tokens, and passwords using configurable regex patterns.

**CycloneDX for SBOM:** The Software Bill of Materials (SBOM) is generated in both JSON and XML formats (CycloneDX specification). SBOMs are increasingly required by regulatory frameworks -- US Executive Order 14028 on Improving the Nation's Cybersecurity mandates SBOM generation for software sold to federal agencies. Even for a prototype, demonstrating SBOM generation shows awareness of supply chain transparency requirements.

**Docker Build & Push:** The final pipeline stage builds the application Docker image and pushes it to DockerHub with both a `latest` tag and a short commit SHA tag. This uses Docker Buildx with GitHub Actions cache (`type=gha`) for efficient layer caching across builds. The Docker image follows container security best practices: non-root execution (`appuser:appgroup`), minimal base image (`python:3.10-slim`), and a built-in health check. The image is only pushed on merges to main/master, ensuring that only code that passes all security gates reaches the container registry.

### Why This Decision is Significant

This pipeline implements the NIST SP 800-218 SSDF practices PW.7 (Review and Analyse Code for Vulnerabilities) and PW.8 (Test Software for Vulnerabilities) as automated, repeatable processes rather than manual activities. Every commit is subjected to the same security analysis, eliminating the risk of human oversight. The pipeline runs identically for every developer, ensuring consistent security standards regardless of individual expertise.

The pipeline's security reports (Bandit JSON, CodeQL SARIF, pip-audit JSON, coverage XML) are uploaded as CI/CD artefacts and retained for audit purposes, supporting the traceability requirements of ISO 27001 and SOC 2 compliance frameworks.

---

## 5. Secure XML Processing Decision

### The Decision

The system downloads and parses the official CWE XML dataset from MITRE (`cwec_latest.xml.zip`) to provide comprehensive weakness definitions. The implementation uses the `defusedxml` library instead of Python's built-in `xml.etree.ElementTree` to prevent XML External Entity (XXE) injection attacks.

### The Implementation

The `cwe_parser.py` module implements a three-tier data loading strategy:

```
1. Check for locally cached XML file (data/cwec_*.xml)
        |
        v (not found)
2. Download cwec_latest.xml.zip from cwe.mitre.org
   Extract XML, parse with defusedxml.ElementTree
        |
        v (download or parse fails)
3. Fall back to built-in COMMON_CWES list (37 entries)
```

The critical security choice is at step 2: the XML is parsed using `defusedxml.ElementTree.parse()` rather than the standard library's `xml.etree.ElementTree.parse()`. The `defusedxml` library disables external entity resolution, DTD processing, and entity expansion by default -- mitigating three classes of XML attack:

**XXE (CWE-611):** An attacker who could modify the XML in transit (man-in-the-middle) or compromise the MITRE distribution could embed external entity declarations like `<!ENTITY xxe SYSTEM "file:///etc/passwd">`. The standard library's parser would resolve this entity, leaking local file contents. `defusedxml` raises a `DTDForbidden` exception instead.

**Billion Laughs (CWE-776):** An exponential entity expansion attack (`<!ENTITY a0 "dos"><!ENTITY a1 "&a0;&a0;&a0;...">`) can consume gigabytes of memory from a few kilobytes of XML. `defusedxml` limits entity expansion depth, preventing this denial-of-service vector.

**External DTD Retrieval:** A malicious DTD reference could trigger server-side requests to attacker-controlled URLs (a form of SSRF). `defusedxml` blocks all external DTD loading.

### Why This Decision is Significant

There is a deliberate irony in this implementation: the system processes CWE-611 (XML External Entity) definitions from the MITRE dataset while being explicitly protected against CWE-611 attacks in its own XML processing. This is not accidental -- it demonstrates that the developers understand the vulnerabilities they are cataloguing and apply the corresponding mitigations in their own code.

The fallback to built-in data when the XML download fails represents a conscious tradeoff between **data freshness** and **availability**. The system prioritises being operational (serving the 37 most common CWEs) over being comprehensive (serving 900+ CWEs). This follows the resilience principle: a security intelligence tool that cannot start because a single external download failed is less useful than one that starts with partial data and upgrades when the full dataset becomes available. The module-level cache (`_xml_cwe_data`) ensures the XML is downloaded and parsed only once per application lifetime, avoiding repeated network requests.

---

## 6. Testing Strategy

### Approach

The testing strategy follows the **test pyramid** model: a broad base of unit tests covering individual functions, supported by integration tests that verify API endpoint behaviour with mocked external dependencies. Tests are organised into four modules corresponding to the application's architectural layers.

### Security-Focused Test Coverage

**Input Validation Tests (`test_security.py` -- 18 tests)**

The security test suite is the most critical component of the testing strategy. It verifies that the input validation layer in `security.py` correctly rejects adversarial payloads:

- **SQL Injection payloads:** Tests like `test_invalid_cve_id_sql_injection` submit `'; DROP TABLE cves;--` and verify an HTTP 400 response. This is not just defensive testing -- it documents the specific attack vectors the validation is designed to prevent, serving as living documentation of the threat model.
- **Format enforcement:** Tests verify that CVE IDs must match `^CVE-\d{4}-\d{4,}$` exactly, that CWE IDs accept only numeric characters, and that search queries are stripped of control characters, angle brackets, and SQL-significant characters like semicolons and quotes.
- **Boundary conditions:** Tests for empty strings, whitespace-only input, and inputs exceeding the 200-character length limit ensure that edge cases do not bypass validation.

**API Endpoint Tests (`test_main.py` -- 10 tests)**

Integration tests use FastAPI's `TestClient` to verify end-to-end request/response behaviour. External NVD API calls are mocked using `unittest.mock.patch` to ensure tests are deterministic, fast, and do not depend on network availability. Key tests include:

- CVE retrieval with valid IDs, not-found handling, and SQL injection rejection at the route level
- CWE search functionality and invalid ID handling
- Analytics endpoints returning correct response structures

**NVD Client Tests (`test_nvd_client.py` -- 8 tests)**

Tests for the `parse_nvd_cve()` function verify correct extraction of all data fields from NVD's JSON response format: basic CVE fields, CVSS v2 and v3 scores, CWE IDs, affected products from CPE data, references, and publication dates. A dedicated `test_parse_empty_vuln` test verifies graceful handling of minimal/empty NVD responses, ensuring the parser does not crash on unexpected data.

**CWE Parser Tests (`test_cwe_parser.py` -- 8 tests)**

Tests verify both the XML parsing capability and the fallback mechanism. The `test_parse_cwe_xml_extracts_weaknesses` test creates a temporary XML file with the CWE namespace and verifies correct extraction of Weakness elements including their `Related_Weaknesses` relationships. The `test_load_cwe_data_falls_back_on_failure` test mocks a failed XML download and verifies that the system falls back to the built-in `COMMON_CWES` dataset -- testing the resilience path.

### CI Integration

Tests run in the CI/CD pipeline with coverage reporting (`pytest --cov=app --cov-report=xml --cov-report=html`). Coverage reports are uploaded as pipeline artefacts, providing visibility into which code paths are exercised by tests and which remain untested. This supports continuous improvement of test coverage as the application evolves.

### Why This Strategy is Significant

The testing strategy directly supports the defence-in-depth architecture described in Section 2. Each security layer (input validation, parameterised SQL, output encoding) has its own dedicated test coverage, ensuring that changes to one layer do not silently break security guarantees. The use of mocked external dependencies ensures that security tests are deterministic -- a test that passes locally will also pass in CI/CD, eliminating the "works on my machine" class of false positives that undermine confidence in security testing.

---

## 7. Authentication Architecture -- Microsoft Entra ID

### The Decision

The application implements **token-based authentication** using Microsoft Entra ID (Azure AD) Bearer JWT tokens. All data-access API endpoints require a valid access token, while infrastructure endpoints (`/api/health`, `/api/config`, `/metrics`) remain public.

### The Implementation

The `auth.py` module provides a FastAPI dependency (`get_current_user`) that validates incoming JWTs against Microsoft's JWKS (JSON Web Key Set) endpoint. The validation process:

1. **Extract** the Bearer token from the `Authorization` header via FastAPI's `HTTPBearer` security scheme
2. **Fetch signing keys** from `https://login.microsoftonline.com/common/discovery/v2.0/keys` (cached for 1 hour to avoid repeated network calls)
3. **Decode and verify** the token using RS256 algorithm with audience validation against `AZURE_CLIENT_ID`
4. **Return claims** on success, or raise HTTP 401 with `WWW-Authenticate: Bearer` on failure

```
Browser → MSAL.js → Entra ID → JWT token → API → auth.py → JWKS validation → Claims
```

The `common` JWKS endpoint is used with issuer validation disabled (`verify_iss: False`) to support multi-tenant and personal Microsoft accounts. This is an intentional tradeoff: it broadens access to any valid Entra ID token with the correct audience, while the audience check ensures only tokens issued for this specific application are accepted.

### CORS Configuration

The application configures CORS middleware to support the browser-based MSAL.js authentication flow:

- **Origins**: `http://localhost:8000` and `http://127.0.0.1:8000`
- **Methods**: GET only (read-only API, no mutation endpoints)
- **Headers**: `Authorization` and `Content-Type`

This minimises the attack surface by rejecting cross-origin requests from unexpected domains and restricting HTTP methods to the minimum required.

### Frontend Integration

The `/api/config` endpoint exposes the `client_id` and `tenant_id` to the frontend without hardcoding credentials in JavaScript. The frontend uses MSAL.js to perform the OAuth 2.0 authorization code flow, acquire an access token, and attach it as a Bearer header to all subsequent API requests. This separation means credentials are configured via environment variables in `docker-compose.yml` and never committed to the repository.

### Why This Decision is Significant

Moving from unauthenticated access to Entra ID JWT authentication addresses **OWASP A07:2021 (Identification and Authentication Failures)**. Even though NVD data is publicly available, the API provides curated analytics and cross-referenced intelligence that justifies access control. The JWT approach is stateless (no server-side sessions to manage or expire), scales horizontally without sticky sessions, and integrates with enterprise identity infrastructure.

---

## 8. Observability Stack -- Prometheus, Grafana, and Load Testing

### The Decision

The application implements a comprehensive **observability stack** using Prometheus for metrics collection, Grafana for visualisation, and Locust for load testing. This enables monitoring of application health, performance, and behaviour under load -- capabilities essential for operating a security-critical service reliably.

### Metrics Instrumentation

The `metrics.py` module implements a Starlette middleware (`PrometheusMiddleware`) that instruments every HTTP request with three metric types:

| Metric | Type | Labels | Purpose |
|--------|------|--------|---------|
| `http_requests_total` | Counter | method, endpoint, status | Track request volume and error rates |
| `http_request_duration_seconds` | Histogram | method, endpoint | Compute latency percentiles (p50/p95/p99) |
| `http_requests_in_progress` | Gauge | method, endpoint | Monitor concurrency and detect overload |

**Path normalisation** (`_normalize_path()`) replaces dynamic path segments (e.g., `/api/cwe/79`) with placeholders (e.g., `/api/cwe/{id}`) to prevent high-cardinality label explosion -- a common pitfall that can cause Prometheus storage bloat and slow dashboard queries.

The histogram uses 11 carefully chosen bucket boundaries (0.005s to 10s) that map to meaningful latency thresholds for an API service, enabling accurate percentile computation at the Prometheus query level.

### Recording and Alerting Rules

**17 recording rules** pre-compute common queries (request rates, error ratios, latency percentiles, availability) so dashboards render instantly without computing aggregations on every page load.

**11 alerting rules** define thresholds for automated problem detection:

- **Critical alerts**: API down, >5% server errors, availability <99%, 10× traffic spike, p95 >5s
- **Warning alerts**: Elevated client errors, p95 >1s, slow individual endpoints, no traffic, high concurrency

These rules follow the Google SRE "four golden signals" approach: latency, traffic, errors, and saturation.

### Grafana Dashboard

A pre-provisioned dashboard with 18 panels across 5 sections provides immediate visibility without manual configuration:

1. **Overview** -- Total, success, client error, and server error counts (stat panels with colour-coded backgrounds)
2. **Traffic** -- Request rate timeseries, cumulative traffic, pie charts by endpoint/method/status
3. **Latency** -- p50/p95/p99 percentiles with colour-coding (green/orange/red), per-endpoint breakdown, average bar gauge, duration heatmap
4. **Errors & Connections** -- 5xx rate timeseries, stacked in-progress gauge with threshold colouring
5. **Request Log** -- Sortable table with every endpoint's method, status, total count, req/s, and average response time (with emoji status indicators)

The dashboard is provisioned automatically via Grafana's file-based provisioning system -- no manual import required.

### Load Testing

The Locust configuration (`locust/locustfile.py`) defines weighted scenarios that simulate realistic developer traffic patterns:

- Search and list operations (highest weight: 4-5)
- Detail lookups and suggestions (medium weight: 3)
- Analytics and cross-reference queries (lower weight: 1-2)
- Health checks (weight: 1)

Users configure load parameters (concurrent users, spawn rate) via the Locust web UI at port 8089. This enables performance characterisation under controlled conditions and helps identify bottlenecks before production deployment.

### Why This Decision is Significant

Observability transforms the application from a black box into a transparent system. For a security intelligence platform, operational visibility is a security requirement: an unmonitored API could be silently failing, serving stale data, or experiencing abuse without anyone knowing. The combination of metrics, dashboards, alerts, and load testing provides confidence that the system is functioning correctly and will surface problems before they impact users.

---

## 9. Containerised Deployment

### The Decision

The application is containerised using a **Dockerfile** for the FastAPI service and a **Docker Compose** configuration that orchestrates four services: the web application, Prometheus, Grafana, and Locust.

### Container Security

The Dockerfile implements several security best practices:

- **Non-root execution**: A dedicated `appuser:appgroup` is created, and the application runs as this unprivileged user via the `USER` directive. This follows the principle of least privilege -- even if the application is compromised, the attacker has minimal system access.
- **No compiled bytecode**: `PYTHONDONTWRITEBYTECODE=1` prevents `.pyc` file creation, reducing the writable surface and image size.
- **Layer caching**: Dependencies are installed in a separate layer before application code is copied, ensuring that code changes do not trigger a full dependency reinstall.
- **Minimal base image**: `python:3.10-slim` provides a smaller attack surface than the full Python image.

### Docker Compose Architecture

The `docker-compose.yml` defines four services with explicit dependency ordering:

```
web → prometheus → grafana
web → locust
```

All services use **pinned image versions** (e.g., `prom/prometheus:v2.51.2`, `grafana/grafana:10.4.2`, `locustio/locust:2.24.1`) rather than `latest` tags, ensuring reproducible builds and avoiding supply chain risks from unexpected image updates.

Named volumes (`cwe-data`, `prometheus-data`, `grafana-data`) persist state across container restarts. The `.dockerignore` excludes development files (`venv/`, `__pycache__/`, `monitoring/`, `locust/`, `docs/`) from the build context, keeping the image lean.

Environment variables for Entra ID credentials (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`) are passed through from the host environment or `.env` file, ensuring secrets are never baked into the image.

### Health Checking

The web service includes a Docker health check that calls the `/api/health` endpoint every 30 seconds. This endpoint is public (no auth required) and returns cache statistics, providing both liveness and readiness information. Docker uses this to determine whether the container should receive traffic and whether dependent services should start.

### Why This Decision is Significant

Containerisation ensures that the application runs identically across development, CI/CD, and production environments -- eliminating "works on my machine" deployment failures. The single `docker compose up --build` command deploys the entire stack including monitoring, making the application immediately operational with full observability. Pinning image versions and implementing container security best practices addresses supply chain and runtime security concerns that are critical for a security-focused application.
