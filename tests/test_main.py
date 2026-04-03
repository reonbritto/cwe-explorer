"""Tests for FastAPI application endpoints."""
import os
import pytest
from unittest.mock import patch, AsyncMock
from fastapi.testclient import TestClient
from backend.main import app
from backend.auth import get_current_user
from backend.models import CVEDetail, CVSSScores


# Override auth dependency for all tests — return a fake user
MOCK_USER = {"sub": "test-user", "name": "Test User"}


async def _mock_user():
    return MOCK_USER


app.dependency_overrides[get_current_user] = _mock_user


@pytest.fixture(scope="module", autouse=True)
def _ensure_spa_index():
    """Create a minimal index.html in backend/static/ for SPA fallback tests.

    In production, Docker copies the React build output here.
    In tests, backend/static/ is empty, so we create a placeholder.
    """
    static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                              "backend", "static")
    assets_dir = os.path.join(static_dir, "assets")
    index_path = os.path.join(static_dir, "index.html")

    os.makedirs(assets_dir, exist_ok=True)

    created = not os.path.exists(index_path)
    if created:
        with open(index_path, "w") as f:
            f.write("<!doctype html><html><body><div id='root'></div></body></html>")

    yield

    if created and os.path.exists(index_path):
        os.remove(index_path)


@pytest.fixture(scope="module")
def client():
    """Create test client that triggers startup events."""
    with TestClient(app) as c:
        yield c


MOCK_CVE = CVEDetail(
    cve_id="CVE-2021-44228",
    description="Apache Log4j2 RCE vulnerability",
    cvss=CVSSScores(
        v3_score=10.0,
        v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        v3_severity="CRITICAL",
        v2_score=9.3,
        v2_vector="AV:N/AC:M/Au:N/C:C/I:C/A:C"
    ),
    cwe_ids=["CWE-917"],
    references=[],
    affected_products=[],
    published="2021-12-10T10:15:09.143",
    modified="2023-04-03T20:15:07.553"
)


class TestCVEEndpoint:
    @patch("backend.main.get_cve", new_callable=AsyncMock,
           return_value=MOCK_CVE)
    def test_get_cve_success(self, mock_get, client):
        response = client.get("/api/cve/CVE-2021-44228")
        assert response.status_code == 200
        data = response.json()
        assert data["cve_id"] == "CVE-2021-44228"
        assert data["cvss"]["v3_score"] == 10.0

    @patch("backend.main.get_cve", new_callable=AsyncMock,
           return_value=None)
    def test_get_cve_not_found(self, mock_get, client):
        response = client.get("/api/cve/CVE-9999-99999")
        assert response.status_code == 404

    def test_get_cve_invalid_format(self, client):
        response = client.get("/api/cve/invalid-id")
        assert response.status_code == 400


class TestCWEEndpoints:
    def test_search_cwes_no_query(self, client):
        response = client.get("/api/cwe")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) > 0

    def test_search_cwes_by_keyword(self, client):
        response = client.get("/api/cwe?query=injection")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    def test_cwe_suggestions(self, client):
        response = client.get("/api/cwe/suggestions?q=injection")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) > 0

    def test_cwe_suggestions_by_id(self, client):
        response = client.get("/api/cwe/suggestions?q=79")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert any("CWE-79" in item.get("text", "")
                   for item in data)

    def test_cwe_suggestions_use_react_routes(self, client):
        """Suggestions should return React-style routes, not .html URLs."""
        response = client.get("/api/cwe/suggestions?q=79")
        data = response.json()
        for item in data:
            action = item.get("action", "")
            if action:
                assert ".html" not in action, \
                    f"Suggestion action still uses .html: {action}"

    def test_cwe_suggestions_keyword_uses_react_routes(self, client):
        """Keyword suggestions should use /search?keyword= not /search.html."""
        response = client.get("/api/cwe/suggestions?q=injection")
        data = response.json()
        for item in data:
            action = item.get("action", "")
            if action and "keyword" in action:
                assert action.startswith("/search?keyword="), \
                    f"Keyword suggestion uses old route: {action}"
                assert ".html" not in action

    def test_get_cwe_invalid_id(self, client):
        response = client.get("/api/cwe/abc")
        assert response.status_code == 400


class TestFeaturedCWEs:
    def test_featured_cwes_returns_list(self, client):
        response = client.get("/api/cwe/featured")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) > 0

    def test_featured_cwes_contain_known_entries(self, client):
        response = client.get("/api/cwe/featured")
        data = response.json()
        ids = [cwe["id"] for cwe in data]
        assert "79" in ids   # XSS
        assert "89" in ids   # SQLi


class TestAnalyticsEndpoints:
    def test_top_cwes(self, client):
        response = client.get("/api/analytics/top-cwes")
        assert response.status_code == 200
        assert isinstance(response.json(), list)

    def test_cwe_risk_scores(self, client):
        response = client.get("/api/analytics/cwe-risk")
        assert response.status_code == 200
        assert isinstance(response.json(), list)


class TestPublicEndpoints:
    def test_health_endpoint(self, client):
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "cwe_count" in data
        assert "active_users" in data

    def test_config_endpoint(self, client):
        response = client.get("/api/config")
        assert response.status_code == 200
        data = response.json()
        assert "client_id" in data
        assert "tenant_id" in data

    def test_services_endpoint(self, client):
        response = client.get("/api/services")
        assert response.status_code == 200
        data = response.json()
        assert "grafana" in data
        assert "prometheus" in data


class TestSPAFallback:
    """Tests for React SPA fallback — all client-side routes serve index.html."""

    def test_root_serves_spa(self, client):
        response = client.get("/")
        assert response.status_code == 200

    def test_login_route_serves_spa(self, client):
        response = client.get("/login")
        assert response.status_code == 200

    def test_search_route_serves_spa(self, client):
        response = client.get("/search")
        assert response.status_code == 200

    def test_cwe_detail_route_serves_spa(self, client):
        response = client.get("/cwe/79")
        assert response.status_code == 200

    def test_cve_detail_route_serves_spa(self, client):
        response = client.get("/cve/CVE-2021-44228")
        assert response.status_code == 200

    def test_attack_route_serves_spa(self, client):
        response = client.get("/attack")
        assert response.status_code == 200

    def test_unknown_route_serves_spa(self, client):
        """Unknown routes should still serve index.html for React Router 404."""
        response = client.get("/nonexistent-page")
        assert response.status_code == 200

    def test_old_html_routes_no_longer_exist(self, client):
        """Old .html file routes should not serve old files (they're deleted)."""
        # These should still return 200 (SPA fallback) but serve
        # index.html, not the old HTML pages
        for path in ["/login.html", "/search.html", "/cwe.html",
                     "/cve.html", "/attack.html", "/404.html"]:
            response = client.get(path)
            # SPA fallback returns index.html for these too
            assert response.status_code == 200
            # Verify it's NOT serving old content — old files are deleted
            # so this should be the React SPA index.html
            static_dir = os.path.join(
                os.path.dirname(os.path.dirname(__file__)), "backend", "static"
            )
            old_file = os.path.join(static_dir, path.lstrip("/"))
            assert not os.path.exists(old_file), \
                f"Old file {path} should have been removed"

    def test_api_routes_not_affected_by_spa(self, client):
        """API routes should NOT be caught by the SPA fallback."""
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"

    def test_sensitive_paths_return_404(self, client):
        """Sensitive filenames must return 404 — not the SPA index.html.

        These paths should never return 200 OK, which would give scanners
        a false-positive signal that the file exists.
        """
        blocked = [
            "/.env",
            "/.env.local",
            "/.env.production",
            "/.env.prod",
            "/.env.production.local",
            "/.env.development.local",
            "/.env.staging",
            "/.env.example",
            "/.git",
            "/.gitignore",
            "/Dockerfile",
            "/docker-compose.yml",
            "/docker-compose.yaml",
            "/terraform.tfvars",
            "/terraform.tfstate",
            "/requirements.txt",
            "/package.json",
            "/package-lock.json",
            "/.github",
            "/.htaccess",
            "/phpinfo.php",
            "/wp-login.php",
            "/server-status",
            "/.DS_Store",
        ]
        for path in blocked:
            response = client.get(path)
            assert response.status_code == 404, (
                f"Expected 404 for {path!r} but got {response.status_code} — "
                "sensitive path must not return 200 OK"
            )
