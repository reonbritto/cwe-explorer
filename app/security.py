"""Input validation and sanitization utilities."""
import re
from fastapi import HTTPException

CVE_ID_PATTERN = re.compile(r'^CVE-\d{4}-\d{4,}$')
CWE_ID_PATTERN = re.compile(r'^\d+$')
MAX_QUERY_LENGTH = 200


def validate_cve_id(cve_id: str) -> str:
    """Validate CVE ID format (e.g., CVE-2021-44228)."""
    cve_id = cve_id.strip().upper()
    if not CVE_ID_PATTERN.match(cve_id):
        raise HTTPException(
            status_code=400,
            detail="Invalid CVE ID format. Expected: CVE-YYYY-NNNNN"
        )
    return cve_id


def validate_cwe_id(cwe_id: str) -> str:
    """Validate CWE ID format (numeric only, e.g., '79')."""
    cwe_id = cwe_id.strip()
    if not CWE_ID_PATTERN.match(cwe_id):
        raise HTTPException(
            status_code=400,
            detail="Invalid CWE ID format. Expected numeric ID."
        )
    return cwe_id


def sanitize_search_query(query: str) -> str:
    """Sanitize and limit search query length."""
    if not query:
        return ""
    query = query.strip()
    if len(query) > MAX_QUERY_LENGTH:
        query = query[:MAX_QUERY_LENGTH]
    # Remove control characters but keep alphanumeric, spaces, hyphens
    query = re.sub(r'[^\w\s\-.,]', '', query)
    return query
