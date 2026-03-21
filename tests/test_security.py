"""Tests for input validation and sanitization."""
import pytest
from fastapi import HTTPException
from app.security import validate_cve_id, validate_cwe_id, sanitize_search_query


class TestValidateCveId:
    def test_valid_cve_id(self):
        assert validate_cve_id("CVE-2021-44228") == "CVE-2021-44228"

    def test_valid_cve_id_lowercase(self):
        assert validate_cve_id("cve-2021-44228") == "CVE-2021-44228"

    def test_valid_cve_id_with_spaces(self):
        assert validate_cve_id("  CVE-2021-44228  ") == "CVE-2021-44228"

    def test_valid_cve_id_five_digits(self):
        assert validate_cve_id("CVE-2023-12345") == "CVE-2023-12345"

    def test_invalid_cve_id_sql_injection(self):
        with pytest.raises(HTTPException) as exc:
            validate_cve_id("'; DROP TABLE cves;--")
        assert exc.value.status_code == 400

    def test_invalid_cve_id_empty(self):
        with pytest.raises(HTTPException):
            validate_cve_id("")

    def test_invalid_cve_id_wrong_format(self):
        with pytest.raises(HTTPException):
            validate_cve_id("CWE-79")

    def test_invalid_cve_id_short_number(self):
        with pytest.raises(HTTPException):
            validate_cve_id("CVE-2021-123")


class TestValidateCweId:
    def test_valid_cwe_id(self):
        assert validate_cwe_id("79") == "79"

    def test_valid_cwe_id_with_spaces(self):
        assert validate_cwe_id("  89  ") == "89"

    def test_invalid_cwe_id_letters(self):
        with pytest.raises(HTTPException):
            validate_cwe_id("abc")

    def test_invalid_cwe_id_injection(self):
        with pytest.raises(HTTPException):
            validate_cwe_id("79; DROP TABLE")

    def test_invalid_cwe_id_with_prefix(self):
        with pytest.raises(HTTPException):
            validate_cwe_id("CWE-79")


class TestSanitizeSearchQuery:
    def test_normal_query(self):
        assert sanitize_search_query("log4j") == "log4j"

    def test_query_with_spaces(self):
        assert sanitize_search_query("  apache log4j  ") == "apache log4j"

    def test_query_length_limit(self):
        long_query = "a" * 300
        result = sanitize_search_query(long_query)
        assert len(result) == 200

    def test_empty_query(self):
        assert sanitize_search_query("") == ""

    def test_strips_special_chars(self):
        result = sanitize_search_query("test<script>alert(1)</script>")
        assert "<" not in result
        assert ">" not in result
