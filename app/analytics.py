"""Analytics engine for CVE data aggregation and statistics."""
from collections import Counter
from typing import List
from .models import SeverityDistribution, CWEStats, TrendPoint


def severity_distribution(cves: List[dict]) -> SeverityDistribution:
    """Calculate severity distribution from cached CVE data."""
    dist = SeverityDistribution()
    for cve in cves:
        cvss = cve.get("cvss", {})
        severity = (cvss.get("v3_severity") or "").upper()
        if severity == "CRITICAL":
            dist.critical += 1
        elif severity == "HIGH":
            dist.high += 1
        elif severity == "MEDIUM":
            dist.medium += 1
        elif severity == "LOW":
            dist.low += 1
        else:
            dist.none += 1
    return dist


def top_cwes(cves: List[dict],
             cwe_dict: dict,
             limit: int = 10) -> List[CWEStats]:
    """Find the CWEs with the most associated CVEs."""
    cwe_counter = Counter()
    for cve in cves:
        for cwe_id in cve.get("cwe_ids", []):
            cwe_counter[cwe_id] += 1

    results = []
    for cwe_id, count in cwe_counter.most_common(limit):
        # Strip 'CWE-' prefix to look up in dict
        numeric_id = cwe_id.replace("CWE-", "")
        cwe_entry = cwe_dict.get(numeric_id)
        cwe_name = cwe_entry.name if cwe_entry else cwe_id
        results.append(CWEStats(
            cwe_id=cwe_id,
            cwe_name=cwe_name,
            cve_count=count
        ))
    return results


def severity_trends(cves: List[dict]) -> List[TrendPoint]:
    """Group CVEs by year and severity for trend analysis."""
    year_severity = Counter()
    for cve in cves:
        published = cve.get("published", "")
        if len(published) >= 4:
            year = int(published[:4])
        else:
            continue

        cvss = cve.get("cvss", {})
        severity = (cvss.get("v3_severity") or "UNKNOWN").upper()
        year_severity[(year, severity)] += 1

    results = []
    for (year, severity), count in sorted(year_severity.items()):
        results.append(TrendPoint(
            year=year, severity=severity, count=count
        ))
    return results
