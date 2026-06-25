from typing import Iterable

RISK_WEIGHTS = {
    "failed_login_burst": 30,
    "successful_login_after_failures": 40,
    "new_ip": 10,
    "access_key_created": 25,
    "privilege_change": 25,
    "cloud_persistence": 25,
    "ids_high_severity": 45,
    "ids_critical_severity": 60,
    "port_scan": 35,
    "risky_open_port": 25,
    "known_exploited_vulnerability": 60,
    "public_facing_asset": 20,
    "high_cvss": 20,
    "web_suspicious_request": 30,
    "web_exploitation_pattern": 45,
}


def score_from_factors(factors: Iterable[str]) -> int:
    score = sum(RISK_WEIGHTS.get(factor, 0) for factor in factors)
    return min(score, 100)


def severity_from_score(score: int) -> str:
    if score >= 81:
        return "Critical"
    if score >= 61:
        return "High"
    if score >= 31:
        return "Medium"
    return "Low"
