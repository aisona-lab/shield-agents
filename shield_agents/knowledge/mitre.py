"""MITRE ATT&CK knowledge base for Shield Agents."""

MITRE_TECHNIQUES = {
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversaries may exploit weaknesses in public-facing applications.",
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries may abuse command and script interpreters.",
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Defense Evasion",
        "description": "Adversaries may use stolen credentials.",
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques.",
    },
    "T1053": {
        "name": "Scheduled Task/Job",
        "tactic": "Execution",
        "description": "Adversaries may abuse task scheduling.",
    },
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": "Adversaries may steal data through C2 channel.",
    },
    "T1566": {
        "name": "Phishing",
        "tactic": "Initial Access",
        "description": "Adversaries may use phishing to gain access.",
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Adversaries may use application layer protocols for C2.",
    },
}


def get_mitre_technique(vulnerability_type: str) -> dict:
    """Get MITRE ATT&CK technique for a vulnerability type."""
    mapping = {
        "sql_injection": "T1190",
        "xss": "T1190",
        "command_injection": "T1059",
        "credential_theft": "T1110",
        "brute_force": "T1110",
        "phishing": "T1566",
        "exfiltration": "T1041",
        "c2_communication": "T1071",
        "injection": "T1190",
    }
    tech_id = mapping.get(vulnerability_type.lower(), "T1190")
    return MITRE_TECHNIQUES.get(tech_id, MITRE_TECHNIQUES["T1190"])
