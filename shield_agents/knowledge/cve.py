"""CVE database interface for Shield Agents."""

# Known CVEs relevant to common vulnerabilities
KNOWN_CVES = {
    "CVE-2021-44228": {
        "title": "Log4Shell - Remote Code Injection in Log4j",
        "severity": "CRITICAL",
        "affected": "Apache Log4j 2.0-beta9 through 2.14.1",
        "description": "Remote code execution via JNDI lookups in Log4j",
    },
    "CVE-2022-22965": {
        "title": "Spring4Shell - RCE in Spring Framework",
        "severity": "CRITICAL",
        "affected": "Spring Framework 5.3.0 to 5.3.17, 5.2.0 to 5.2.19",
        "description": "Remote code execution via data binding",
    },
    "CVE-2023-44487": {
        "title": "HTTP/2 Rapid Reset Attack",
        "severity": "HIGH",
        "affected": "Multiple HTTP/2 implementations",
        "description": "Denial of service via HTTP/2 stream cancellation",
    },
    "CVE-2021-41773": {
        "title": "Apache HTTP Server Path Traversal",
        "severity": "HIGH",
        "affected": "Apache HTTP Server 2.4.49",
        "description": "Path traversal and file disclosure",
    },
    "CVE-2020-9484": {
        "title": "Apache Tomcat Session Deserialization",
        "severity": "HIGH",
        "affected": "Apache Tomcat 10.0.0-M1 to 10.0.0-M4, 9.0.0.M1 to 9.0.34",
        "description": "Deserialization of session data leading to RCE",
    },
}


def lookup_cve(cve_id: str) -> dict:
    """Look up a CVE by ID.
    
    Args:
        cve_id: CVE identifier (e.g., 'CVE-2021-44228').
    
    Returns:
        CVE information dictionary, or empty dict if not found.
    """
    return KNOWN_CVES.get(cve_id, {})


def search_cves(keyword: str) -> list:
    """Search for CVEs matching a keyword.
    
    Args:
        keyword: Search keyword.
    
    Returns:
        List of matching CVE dictionaries.
    """
    results = []
    keyword_lower = keyword.lower()
    for cve_id, info in KNOWN_CVES.items():
        if (keyword_lower in info["title"].lower() or
            keyword_lower in info["description"].lower()):
            results.append({"id": cve_id, **info})
    return results
