"""Tests for FastAPI application endpoints."""
from unittest.mock import patch, AsyncMock
from fastapi.testclient import TestClient
from app.main import app
from app.models import CVEDetail, CVSSScores

client = TestClient(app)


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


class TestCVEEndpoints:
    @patch("app.main.get_cve", new_callable=AsyncMock,
           return_value=MOCK_CVE)
    def test_get_cve_success(self, mock_get):
        response = client.get("/api/cve/CVE-2021-44228")
        assert response.status_code == 200
        data = response.json()
        assert data["cve_id"] == "CVE-2021-44228"
        assert data["cvss"]["v3_score"] == 10.0

    @patch("app.main.get_cve", new_callable=AsyncMock,
           return_value=None)
    def test_get_cve_not_found(self, mock_get):
        response = client.get("/api/cve/CVE-9999-99999")
        assert response.status_code == 404

    def test_get_cve_invalid_format(self):
        response = client.get("/api/cve/invalid-id")
        assert response.status_code == 400

    def test_get_cve_sql_injection(self):
        response = client.get("/api/cve/'; DROP TABLE--")
        assert response.status_code == 400


class TestCWEEndpoints:
    def test_search_cwes_no_query(self):
        response = client.get("/api/cwe")
        assert response.status_code == 200
        assert isinstance(response.json(), list)

    def test_get_cwe_invalid_id(self):
        response = client.get("/api/cwe/abc")
        assert response.status_code == 400


class TestAnalyticsEndpoints:
    def test_severity_distribution(self):
        response = client.get("/api/analytics/severity")
        assert response.status_code == 200
        data = response.json()
        assert "critical" in data
        assert "high" in data

    def test_top_cwes(self):
        response = client.get("/api/analytics/top-cwes")
        assert response.status_code == 200
        assert isinstance(response.json(), list)

    def test_trends(self):
        response = client.get("/api/analytics/trends")
        assert response.status_code == 200
        assert isinstance(response.json(), list)
