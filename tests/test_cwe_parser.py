"""Tests for CWE data provider."""
from app.cwe_parser import get_cwe_data, COMMON_CWES


def test_get_cwe_data_returns_list():
    """get_cwe_data should return a list of CWE entries."""
    result = get_cwe_data()
    assert isinstance(result, list)
    assert len(result) > 0


def test_get_cwe_data_contains_common_cwes():
    """Should include well-known CWEs like XSS and SQLi."""
    result = get_cwe_data()
    ids = [r.id for r in result]
    assert "79" in ids  # XSS
    assert "89" in ids  # SQL Injection
    assert "787" in ids  # Out-of-bounds Write


def test_cwe_entries_have_required_fields():
    """Each CWE entry should have id, name, description."""
    for cwe in COMMON_CWES:
        assert cwe.id
        assert cwe.name
        assert cwe.description


def test_get_cwe_data_returns_copy():
    """Should return a copy, not the original list."""
    data1 = get_cwe_data()
    data2 = get_cwe_data()
    assert data1 is not data2


def test_xss_entry_details():
    """Verify XSS entry has correct name."""
    result = get_cwe_data()
    xss = next(r for r in result if r.id == "79")
    assert "XSS" in xss.name or "Scripting" in xss.name
