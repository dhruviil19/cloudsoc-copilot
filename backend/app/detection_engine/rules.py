MITRE_MAPPINGS = {
    "brute_force": {
        "tactic": "Credential Access",
        "technique": "T1110 Brute Force",
    },
    "valid_accounts": {
        "tactic": "Initial Access",
        "technique": "T1078 Valid Accounts",
    },
    "cloud_persistence": {
        "tactic": "Persistence",
        "technique": "T1098 Account Manipulation",
    },
    "privilege_escalation": {
        "tactic": "Privilege Escalation",
        "technique": "T1098 Account Manipulation",
    },
    "network_service_discovery": {
        "tactic": "Discovery",
        "technique": "T1046 Network Service Discovery",
    },
    "exploit_public_facing_application": {
        "tactic": "Initial Access",
        "technique": "T1190 Exploit Public-Facing Application",
    },
    "command_and_control": {
        "tactic": "Command and Control",
        "technique": "T1071 Application Layer Protocol",
    },
    "web_reconnaissance": {
        "tactic": "Reconnaissance",
        "technique": "T1595 Active Scanning",
    },
}

RULES = [
    {
        "id": "cloudsoc-001",
        "name": "Failed login burst",
        "description": "Detects many failed logins from the same source IP in a short window.",
        "threshold": 10,
        "window_minutes": 5,
        "mapping": MITRE_MAPPINGS["brute_force"],
    },
    {
        "id": "cloudsoc-002",
        "name": "Successful login after failures",
        "description": "Detects a successful login after repeated failures from the same IP or user.",
        "threshold": 5,
        "window_minutes": 10,
        "mapping": MITRE_MAPPINGS["valid_accounts"],
    },
    {
        "id": "cloudsoc-003",
        "name": "AWS access key created after suspicious login",
        "description": "Detects access key creation after suspicious authentication activity.",
        "window_minutes": 30,
        "mapping": MITRE_MAPPINGS["cloud_persistence"],
    },
    {
        "id": "cloudsoc-004",
        "name": "Suricata high severity IDS alert",
        "description": "Detects high or critical Suricata IDS alerts.",
        "mapping": MITRE_MAPPINGS["exploit_public_facing_application"],
    },
    {
        "id": "cloudsoc-005",
        "name": "Port scan detection",
        "description": "Detects scan behavior from Suricata alerts or network events.",
        "mapping": MITRE_MAPPINGS["network_service_discovery"],
    },
    {
        "id": "cloudsoc-006",
        "name": "CISA KEV vulnerability prioritization",
        "description": "Prioritizes Nmap services that map to a CVE present in the local CISA KEV sample catalog.",
        "mapping": MITRE_MAPPINGS["exploit_public_facing_application"],
    },
    {
        "id": "cloudsoc-007",
        "name": "Suspicious web request",
        "description": "Detects suspicious web paths and common exploitation probes in access logs.",
        "mapping": MITRE_MAPPINGS["web_reconnaissance"],
    },
]
