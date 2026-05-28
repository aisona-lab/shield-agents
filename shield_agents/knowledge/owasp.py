"""OWASP Top 10 knowledge base for Shield Agents."""

OWASP_TOP_10_2021 = {
    "A01": {
        "name": "Broken Access Control",
        "description": "Access control enforces policy such that users cannot act outside their intended permissions.",
        "url": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    },
    "A02": {
        "name": "Cryptographic Failures",
        "description": "Failures related to cryptography which often lead to sensitive data exposure.",
        "url": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
    },
    "A03": {
        "name": "Injection",
        "description": "SQL injection, NoSQL injection, OS command injection, and LDAP injection.",
        "url": "https://owasp.org/Top10/A03_2021-Injection/",
    },
    "A04": {
        "name": "Insecure Design",
        "description": "Missing or ineffective security controls and architecture flaws.",
        "url": "https://owasp.org/Top10/A04_2021-Insecure_Design/",
    },
    "A05": {
        "name": "Security Misconfiguration",
        "description": "Missing security hardening, unnecessary features enabled, default accounts.",
        "url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    },
    "A06": {
        "name": "Vulnerable and Outdated Components",
        "description": "Using components with known vulnerabilities.",
        "url": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
    },
    "A07": {
        "name": "Identification and Authentication Failures",
        "description": "Authentication and session management weaknesses.",
        "url": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
    },
    "A08": {
        "name": "Software and Data Integrity Failures",
        "description": "Code and infrastructure not protected against integrity violations.",
        "url": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
    },
    "A09": {
        "name": "Security Logging and Monitoring Failures",
        "description": "Insufficient logging, monitoring, and alerting.",
        "url": "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
    },
    "A10": {
        "name": "Server-Side Request Forgery",
        "description": "Application fetches remote resources without validating user-supplied URLs.",
        "url": "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
    },
}


def get_owasp_category(vulnerability_type: str) -> dict:
    """Get OWASP category for a vulnerability type.
    
    Args:
        vulnerability_type: Type of vulnerability (e.g., 'sql_injection', 'xss').
    
    Returns:
        OWASP category dictionary.
    """
    mapping = {
        "sql_injection": "A03",
        "xss": "A03",
        "command_injection": "A03",
        "path_traversal": "A01",
        "broken_access_control": "A01",
        "sensitive_data_exposure": "A02",
        "crypto_failure": "A02",
        "security_misconfiguration": "A05",
        "auth_failure": "A07",
        "ssrf": "A10",
        "deserialization": "A08",
        "outdated_component": "A06",
        "logging_failure": "A09",
        "injection": "A03",
        "insecure_design": "A04",
    }
    
    category_id = mapping.get(vulnerability_type.lower(), "A03")
    return OWASP_TOP_10_2021.get(category_id, OWASP_TOP_10_2021["A03"])
