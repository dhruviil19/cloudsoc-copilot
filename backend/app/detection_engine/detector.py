import json
from collections import defaultdict
from datetime import timedelta
from typing import Dict, List, Tuple
from sqlalchemy.orm import Session
from ..models import NormalizedEvent, Alert, IncidentEvidence
from ..risk_engine.risk_score import score_from_factors, severity_from_score
from ..ai_engine.summary_generator import generate_summary
from .rules import MITRE_MAPPINGS


def _event_to_dict(event: NormalizedEvent) -> Dict:
    return {
        "id": event.id,
        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
        "source": event.source,
        "event_type": event.event_type,
        "user": event.user,
        "source_ip": event.source_ip,
        "country": event.country,
        "host": event.host,
        "action": event.action,
        "status": event.status,
        "raw_event_id": event.raw_event_id,
        "raw_event": event.raw_event,
    }


def _raw_json(event: NormalizedEvent) -> Dict:
    try:
        return json.loads(event.raw_event or "{}")
    except Exception:
        return {}


def _evidence_payload(events: List[NormalizedEvent], evidence_type: str) -> List[Dict]:
    return [{"evidence_type": evidence_type, "event": _event_to_dict(event)} for event in events]


def _source_label(source: str) -> str:
    labels = {
        "aws_cloudtrail": "AWS",
        "linux_auth": "SSH",
        "suricata_eve": "Suricata",
        "nmap_scan": "Nmap",
        "web_access": "Web",
    }
    return labels.get(source, source or "Unknown")


def _create_alert(
    db: Session,
    title: str,
    description: str,
    factors: List[str],
    events: List[NormalizedEvent],
    evidence_type: str,
    mapping: Dict[str, str],
) -> Alert:
    score = score_from_factors(factors)
    severity = severity_from_score(score)
    first = events[0] if events else None

    alert_dict = {
        "title": title,
        "severity": severity,
        "risk_score": score,
        "user": first.user if first else None,
        "source_ip": first.source_ip if first else None,
        "host": first.host if first else None,
        "status": "Open",
        "mitre_tactic": mapping.get("tactic"),
        "mitre_technique": mapping.get("technique"),
        "description": description,
    }

    summary = generate_summary(alert_dict, _evidence_payload(events, evidence_type))
    alert = Alert(**alert_dict, ai_summary=summary)
    db.add(alert)
    db.flush()

    for event in events:
        db.add(IncidentEvidence(alert_id=alert.id, event_id=event.id, evidence_type=evidence_type))
    return alert


def _clear_old_alerts(db: Session) -> None:
    db.query(IncidentEvidence).delete()
    db.query(Alert).delete()
    db.commit()


def _failed_events_before(
    events: List[NormalizedEvent],
    success: NormalizedEvent,
    minutes: int,
    threshold: int,
) -> List[NormalizedEvent]:
    start = success.timestamp - timedelta(minutes=minutes)
    failures = []
    for event in events:
        if event.event_type != "login_failure":
            continue
        same_ip = event.source_ip and event.source_ip == success.source_ip
        same_user = event.user and event.user == success.user
        in_window = start <= event.timestamp <= success.timestamp
        if in_window and (same_ip or same_user):
            failures.append(event)
    return failures if len(failures) >= threshold else []


def detect_cloud_compromise(db: Session, events: List[NormalizedEvent]) -> int:
    created = 0
    successes = [event for event in events if event.event_type == "login_success" and event.source == "aws_cloudtrail"]
    access_events = [event for event in events if event.event_type == "aws_access_key_created"]
    privilege_events = [event for event in events if event.event_type == "privilege_change"]

    for success in successes:
        failures = _failed_events_before(events, success, minutes=15, threshold=5)
        if not failures:
            continue

        after_start = success.timestamp
        after_end = success.timestamp + timedelta(minutes=30)
        access_after = [event for event in access_events if after_start <= event.timestamp <= after_end and event.user == success.user]
        privilege_after = [event for event in privilege_events if after_start <= event.timestamp <= after_end and event.user == success.user]

        if not access_after and not privilege_after:
            continue

        evidence_events = failures + [success] + access_after + privilege_after
        factors = ["failed_login_burst", "successful_login_after_failures", "new_ip"]
        if access_after:
            factors.append("access_key_created")
        if privilege_after:
            factors.append("privilege_change")

        _create_alert(
            db=db,
            title="Possible AWS account compromise",
            description=(
                "Repeated AWS console login failures were followed by a successful login and sensitive IAM activity "
                "such as access key creation or privilege changes."
            ),
            factors=factors,
            events=evidence_events,
            evidence_type="aws_compromise_sequence",
            mapping=MITRE_MAPPINGS["cloud_persistence"],
        )
        created += 1
    return created


def detect_failed_login_bursts(db: Session, events: List[NormalizedEvent]) -> int:
    created = 0
    groups: Dict[Tuple[str, str], List[NormalizedEvent]] = defaultdict(list)

    for event in events:
        if event.event_type == "login_failure" and event.source_ip:
            groups[(event.source or "unknown", event.source_ip)].append(event)

    for (_source, _ip), items in groups.items():
        items = sorted(items, key=lambda e: e.timestamp)
        left = 0
        for right, current in enumerate(items):
            while current.timestamp - items[left].timestamp > timedelta(minutes=5):
                left += 1
            window_events = items[left:right + 1]
            if len(window_events) >= 10:
                source_label = _source_label(current.source)
                _create_alert(
                    db=db,
                    title=f"{source_label} brute force login attempt",
                    description="Multiple failed login attempts were detected from the same source IP within 5 minutes.",
                    factors=["failed_login_burst"],
                    events=window_events,
                    evidence_type="failed_login_burst",
                    mapping=MITRE_MAPPINGS["brute_force"],
                )
                created += 1
                break
    return created


def detect_success_after_failures(db: Session, events: List[NormalizedEvent]) -> int:
    created = 0
    for success in [event for event in events if event.event_type == "login_success"]:
        failures = _failed_events_before(events, success, minutes=10, threshold=5)
        if not failures:
            continue

        source_label = _source_label(success.source)
        evidence_events = failures + [success]
        _create_alert(
            db=db,
            title=f"{source_label} successful login after brute force",
            description="A successful login occurred after repeated failed attempts from the same source IP or user.",
            factors=["failed_login_burst", "successful_login_after_failures", "new_ip"],
            events=evidence_events,
            evidence_type="successful_login_after_failures",
            mapping=MITRE_MAPPINGS["valid_accounts"],
        )
        created += 1
    return created


def detect_suricata_alerts(db: Session, events: List[NormalizedEvent]) -> int:
    created = 0
    for event in [item for item in events if item.source == "suricata_eve" and item.event_type == "suricata_alert"]:
        factors = ["ids_high_severity"]
        if event.status == "critical":
            factors.append("ids_critical_severity")
        mapping = MITRE_MAPPINGS["exploit_public_facing_application"]
        title = "Suricata high-severity IDS alert"
        if "c2" in (event.action or "").lower() or "command" in (event.action or "").lower():
            mapping = MITRE_MAPPINGS["command_and_control"]
            title = "Possible command and control traffic"
        _create_alert(
            db=db,
            title=title,
            description="A high-severity Suricata IDS alert was observed and should be triaged by a SOC analyst.",
            factors=factors,
            events=[event],
            evidence_type="suricata_alert",
            mapping=mapping,
        )
        created += 1
    return created


def detect_port_scans(db: Session, events: List[NormalizedEvent]) -> int:
    created = 0
    scan_events = [event for event in events if event.event_type == "port_scan"]
    groups: Dict[str, List[NormalizedEvent]] = defaultdict(list)
    for event in scan_events:
        if event.source_ip:
            groups[event.source_ip].append(event)

    for source_ip, items in groups.items():
        if not items:
            continue
        _create_alert(
            db=db,
            title="Possible port scan detected",
            description=f"Source IP {source_ip} generated scan-like IDS events, indicating possible reconnaissance.",
            factors=["port_scan"],
            events=items,
            evidence_type="port_scan",
            mapping=MITRE_MAPPINGS["network_service_discovery"],
        )
        created += 1
    return created


def detect_vulnerability_priorities(db: Session, events: List[NormalizedEvent]) -> int:
    created = 0
    for event in [item for item in events if item.source == "nmap_scan" and item.event_type == "nmap_service"]:
        raw = _raw_json(event)
        cve_match = raw.get("cve_match") or {}
        risky_port = bool(raw.get("risky_port"))
        cve_id = cve_match.get("cve_id")
        kev = bool(cve_match.get("cisa_kev"))
        cvss = float(cve_match.get("cvss") or 0)

        if not cve_id and not risky_port:
            continue

        factors = ["public_facing_asset"]
        if risky_port:
            factors.append("risky_open_port")
        if cve_id and cvss >= 7:
            factors.append("high_cvss")
        if kev:
            factors.append("known_exploited_vulnerability")

        title = "Exposed risky service detected"
        if kev:
            title = "Known exploited vulnerability match"

        _create_alert(
            db=db,
            title=title,
            description=(
                f"Nmap identified {event.action}. The service is prioritized because it is exposed, "
                f"mapped to {cve_id or 'a risky service'}, and may require remediation."
            ),
            factors=factors,
            events=[event],
            evidence_type="vulnerability_priority",
            mapping=MITRE_MAPPINGS["exploit_public_facing_application"],
        )
        created += 1
    return created


def detect_web_suspicious_requests(db: Session, events: List[NormalizedEvent]) -> int:
    created = 0
    suspicious = [item for item in events if item.source == "web_access" and item.event_type == "web_suspicious_request"]
    groups: Dict[str, List[NormalizedEvent]] = defaultdict(list)
    for event in suspicious:
        groups[event.source_ip or "unknown"].append(event)

    for source_ip, items in groups.items():
        factors = ["web_suspicious_request"]
        action_text = " ".join(event.action or "" for event in items).lower()
        if any(token in action_text for token in ["../", "etc/passwd", "union select", "' or 1=1", "<script", ".env"]):
            factors.append("web_exploitation_pattern")
        _create_alert(
            db=db,
            title="Suspicious web activity detected",
            description=f"Source IP {source_ip} requested suspicious web paths or exploit-like payloads.",
            factors=factors,
            events=items[:20],
            evidence_type="web_suspicious_requests",
            mapping=MITRE_MAPPINGS["web_reconnaissance"],
        )
        created += 1
    return created


def run_detection(db: Session) -> Dict[str, int]:
    _clear_old_alerts(db)
    events = db.query(NormalizedEvent).order_by(NormalizedEvent.timestamp.asc()).all()

    counts = {
        "cloud_compromise": detect_cloud_compromise(db, events),
        "failed_login_bursts": detect_failed_login_bursts(db, events),
        "success_after_failures": detect_success_after_failures(db, events),
        "suricata_alerts": detect_suricata_alerts(db, events),
        "port_scans": detect_port_scans(db, events),
        "vulnerability_priorities": detect_vulnerability_priorities(db, events),
        "web_suspicious_requests": detect_web_suspicious_requests(db, events),
    }
    db.commit()
    counts["total_alerts"] = sum(counts.values())
    return counts
