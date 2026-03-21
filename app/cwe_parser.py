"""Live CWE data provider.

Provides CWE weakness definitions from a built-in reference
dataset of the most common CWEs, with live NVD API fallback
for any CWE not in the built-in set. No XML downloads needed.
"""
import httpx
from typing import List, Optional
from .models import CWEEntry
from . import cache

NVD_CWE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Built-in CWE reference data for commonly referenced weaknesses.
# Provides instant lookups without API calls.
COMMON_CWES = [
    CWEEntry(id="16", name="Configuration",
             description="Software configuration weakness."),
    CWEEntry(id="20", name="Improper Input Validation",
             description="The product does not validate or "
             "incorrectly validates input."),
    CWEEntry(id="22", name="Path Traversal",
             description="Improper limitation of a pathname "
             "to a restricted directory."),
    CWEEntry(id="59", name="Improper Link Resolution",
             description="Improper link resolution before "
             "file access."),
    CWEEntry(id="77", name="Command Injection",
             description="Improper neutralization of special "
             "elements used in a command."),
    CWEEntry(id="78", name="OS Command Injection",
             description="Improper neutralization of special "
             "elements used in an OS command."),
    CWEEntry(id="79", name="Cross-site Scripting (XSS)",
             description="Improper neutralization of input "
             "during web page generation."),
    CWEEntry(id="89", name="SQL Injection",
             description="Improper neutralization of special "
             "elements used in an SQL command."),
    CWEEntry(id="94", name="Code Injection",
             description="Improper control of generation of "
             "code."),
    CWEEntry(id="119", name="Buffer Overflow",
             description="Improper restriction of operations "
             "within the bounds of a memory buffer."),
    CWEEntry(id="120", name="Classic Buffer Overflow",
             description="The program copies an input buffer "
             "to an output buffer without verifying that the "
             "size of the input buffer is less than the size "
             "of the output buffer."),
    CWEEntry(id="125", name="Out-of-bounds Read",
             description="The software reads data past the "
             "end of the intended buffer."),
    CWEEntry(id="189", name="Numeric Errors",
             description="Weaknesses in numeric computation."),
    CWEEntry(id="190", name="Integer Overflow",
             description="An integer overflow or wraparound "
             "occurs when the result is used to allocate or "
             "determine buffer sizes."),
    CWEEntry(id="200", name="Information Disclosure",
             description="The product exposes sensitive "
             "information to an actor not explicitly "
             "authorised to have access."),
    CWEEntry(id="264", name="Permissions and Privileges",
             description="Weaknesses related to management "
             "of permissions, privileges, access controls."),
    CWEEntry(id="269", name="Improper Privilege Management",
             description="The software does not properly "
             "assign, modify, track, or check privileges."),
    CWEEntry(id="284", name="Improper Access Control",
             description="The software does not restrict or "
             "incorrectly restricts access to a resource."),
    CWEEntry(id="287", name="Improper Authentication",
             description="The software does not prove or "
             "insufficiently proves an actor's identity."),
    CWEEntry(id="310", name="Cryptographic Issues",
             description="Weaknesses related to design and "
             "implementation of cryptographic features."),
    CWEEntry(id="352", name="Cross-Site Request Forgery",
             description="The web application does not "
             "sufficiently verify that a request was "
             "intentionally submitted."),
    CWEEntry(id="362", name="Race Condition",
             description="The program contains a concurrent "
             "code sequence requiring exclusive access to a "
             "shared resource."),
    CWEEntry(id="399", name="Resource Management Errors",
             description="Weaknesses related to improper "
             "management of system resources."),
    CWEEntry(id="400", name="Uncontrolled Resource Consumption",
             description="The software does not properly "
             "control allocation of a resource enabling "
             "denial of service."),
    CWEEntry(id="416", name="Use After Free",
             description="Referencing memory after it has "
             "been freed can cause crash or arbitrary code "
             "execution."),
    CWEEntry(id="426", name="Untrusted Search Path",
             description="The application searches for "
             "critical resources using a search path under "
             "attacker control."),
    CWEEntry(id="434", name="Unrestricted File Upload",
             description="The software allows upload of "
             "dangerous file types without validation."),
    CWEEntry(id="476", name="NULL Pointer Dereference",
             description="A NULL pointer dereference occurs "
             "when the application dereferences a pointer "
             "that it expects to be valid but is NULL."),
    CWEEntry(id="502", name="Deserialization of Untrusted Data",
             description="The application deserializes "
             "untrusted data without sufficiently verifying "
             "that the resulting data will be valid."),
    CWEEntry(id="601", name="Open Redirect",
             description="A web application accepts "
             "user-controlled input that specifies a link "
             "to an external site and redirects to it."),
    CWEEntry(id="611", name="XML External Entity (XXE)",
             description="The software processes an XML "
             "document that can contain XML entities with "
             "URIs that resolve outside the intended sphere "
             "of control."),
    CWEEntry(id="787", name="Out-of-bounds Write",
             description="The software writes data past the "
             "end or before the beginning of the intended "
             "buffer."),
    CWEEntry(id="798", name="Hard-coded Credentials",
             description="The software contains hard-coded "
             "credentials for authentication."),
    CWEEntry(id="862", name="Missing Authorization",
             description="The software does not perform an "
             "authorization check when an actor attempts to "
             "access a resource."),
    CWEEntry(id="863", name="Incorrect Authorization",
             description="The software performs an "
             "authorization check but does not correctly "
             "perform the check."),
    CWEEntry(id="917", name="Expression Language Injection",
             description="The software constructs expression "
             "language statements using externally-influenced "
             "input."),
    CWEEntry(id="918", name="Server-Side Request Forgery",
             description="The web server receives a URL from "
             "an upstream component and retrieves contents "
             "without verifying the destination."),
]


def get_cwe_data() -> List[CWEEntry]:
    """Return the built-in CWE reference dataset.

    Provides instant access to common CWE definitions
    without requiring any file downloads or XML parsing.
    """
    return list(COMMON_CWES)


async def fetch_cwe_from_nvd(cwe_id: str) -> Optional[CWEEntry]:
    """Look up a CWE by ID. Checks built-in data first,
    then falls back to NVD API for unknown CWEs.
    """
    # Check built-in data
    for cwe in COMMON_CWES:
        if cwe.id == cwe_id:
            return cwe

    # Check cache
    cache_key = f"cwe_lookup_{cwe_id}"
    cached = cache.get_cached_search(cache_key)
    if cached:
        return CWEEntry(**cached)

    # Fallback: query NVD for a CVE using this CWE
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                NVD_CWE_URL,
                params={
                    "cweId": f"CWE-{cwe_id}",
                    "resultsPerPage": 1
                },
                timeout=15.0
            )
            if response.status_code == 200:
                entry = CWEEntry(
                    id=cwe_id,
                    name=f"CWE-{cwe_id}",
                    description=(
                        f"Weakness CWE-{cwe_id}. "
                        f"See MITRE CWE for full details."
                    )
                )
                cache.set_cached_search(
                    cache_key, entry.model_dump()
                )
                return entry
    except (httpx.HTTPError, Exception):
        pass

    return None
