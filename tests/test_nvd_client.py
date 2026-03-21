"""Tests for NVD API client with mocked responses."""
from app.nvd_client import parse_nvd_cve
from app.models import CVEDetail


SAMPLE_NVD_RESPONSE = {
    "cve": {
        "id": "CVE-2021-44228",
        "descriptions": [
            {
                "lang": "en",
                "value": "Apache Log4j2 allows remote code execution."
            }
        ],
        "metrics": {
            "cvssMetricV31": [
                {
                    "cvssData": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                        "baseScore": 10.0,
                        "baseSeverity": "CRITICAL"
                    }
                }
            ],
            "cvssMetricV2": [
                {
                    "cvssData": {
                        "version": "2.0",
                        "vectorString": "AV:N/AC:M/Au:N/C:C/I:C/A:C",
                        "baseScore": 9.3
                    }
                }
            ]
        },
        "weaknesses": [
            {
                "description": [
                    {"lang": "en", "value": "CWE-917"},
                    {"lang": "en", "value": "CWE-502"}
                ]
            }
        ],
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
                            }
                        ]
                    }
                ]
            }
        ],
        "references": [
            {
                "url": "https://logging.apache.org/log4j/2.x/security.html",
                "source": "cve@mitre.org",
                "tags": ["Vendor Advisory"]
            }
        ],
        "published": "2021-12-10T10:15:09.143",
        "lastModified": "2023-04-03T20:15:07.553"
    }
}


class TestParseNvdCve:
    def test_parse_basic_fields(self):
        result = parse_nvd_cve(SAMPLE_NVD_RESPONSE)
        assert isinstance(result, CVEDetail)
        assert result.cve_id == "CVE-2021-44228"
        assert "Log4j2" in result.description

    def test_parse_cvss_v3(self):
        result = parse_nvd_cve(SAMPLE_NVD_RESPONSE)
        assert result.cvss.v3_score == 10.0
        assert result.cvss.v3_severity == "CRITICAL"
        assert "CVSS:3.1" in result.cvss.v3_vector

    def test_parse_cvss_v2(self):
        result = parse_nvd_cve(SAMPLE_NVD_RESPONSE)
        assert result.cvss.v2_score == 9.3
        assert result.cvss.v2_vector is not None

    def test_parse_cwe_ids(self):
        result = parse_nvd_cve(SAMPLE_NVD_RESPONSE)
        assert "CWE-917" in result.cwe_ids
        assert "CWE-502" in result.cwe_ids

    def test_parse_affected_products(self):
        result = parse_nvd_cve(SAMPLE_NVD_RESPONSE)
        assert len(result.affected_products) > 0
        product = result.affected_products[0]
        assert product.vendor == "apache"
        assert product.product == "log4j"

    def test_parse_references(self):
        result = parse_nvd_cve(SAMPLE_NVD_RESPONSE)
        assert len(result.references) > 0
        ref = result.references[0]
        assert "apache.org" in ref.url
        assert "Vendor Advisory" in ref.tags

    def test_parse_dates(self):
        result = parse_nvd_cve(SAMPLE_NVD_RESPONSE)
        assert result.published.startswith("2021-12-10")
        assert result.modified.startswith("2023")

    def test_parse_empty_vuln(self):
        """Parsing minimal data should not crash."""
        result = parse_nvd_cve({"cve": {"id": "CVE-2000-0001",
                                        "descriptions": [],
                                        "metrics": {},
                                        "weaknesses": [],
                                        "configurations": [],
                                        "references": [],
                                        "published": "",
                                        "lastModified": ""}})
        assert result.cve_id == "CVE-2000-0001"
        assert result.description == ""
        assert result.cvss.v3_score is None
