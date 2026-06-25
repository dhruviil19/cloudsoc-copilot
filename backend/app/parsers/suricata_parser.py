import json
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List


def _parse_time(value: str) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    clean = value.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(clean)
    except ValueError:
        return datetime.now(timezone.utc)


def _iter_records(text: str) -> Iterable[Dict[str, Any]]:
    stripped = text.strip()
    if not stripped:
        return []

    try:
        parsed = json.loads(stripped)
        if isinstance(parsed, list):
            return [item for item in parsed if isinstance(item, dict)]
        if isinstance(parsed, dict):
            if isinstance(parsed.get("events"), list):
                return [item for item in parsed["events"] if isinstance(item, dict)]
            return [parsed]
    except Exception:
        pass

    records = []
    for line in stripped.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except Exception:
            continue
        if isinstance(item, dict):
            records.append(item)
    return records


def _suricata_event_type(record: Dict[str, Any]) -> str:
    alert = record.get("alert") or {}
    signature = str(alert.get("signature") or "").lower()
    category = str(alert.get("category") or "").lower()
    event_type = str(record.get("event_type") or "")

    if "scan" in signature or "scan" in category:
        return "port_scan"
    if event_type == "alert" or alert:
        return "suricata_alert"
    return "suricata_event"


def _severity_label(record: Dict[str, Any]) -> str:
    alert = record.get("alert") or {}
    sev = alert.get("severity")
    try:
        value = int(sev)
    except Exception:
        return "unknown"
    if value <= 1:
        return "critical"
    if value == 2:
        return "high"
    if value == 3:
        return "medium"
    return "low"


def parse_suricata_eve(text: str) -> List[Dict[str, Any]]:
    events = []
    for index, record in enumerate(_iter_records(text)):
        if "alert" not in record and record.get("event_type") not in {"alert", "flow", "dns", "http", "tls"}:
            continue
        alert = record.get("alert") or {}
        signature = alert.get("signature") or record.get("event_type") or "Suricata event"
        src_ip = record.get("src_ip")
        dest_ip = record.get("dest_ip")
        dest_port = record.get("dest_port")
        action = signature if dest_port is None else f"{signature} -> {dest_ip}:{dest_port}"
        event_type = _suricata_event_type(record)

        events.append({
            "timestamp": _parse_time(record.get("timestamp")),
            "source": "suricata_eve",
            "event_type": event_type,
            "user": None,
            "source_ip": src_ip,
            "country": None,
            "host": dest_ip,
            "action": action,
            "status": _severity_label(record),
            "raw_event_id": str(alert.get("signature_id") or record.get("flow_id") or f"suricata-{index}"),
            "raw_event": json.dumps(record, indent=2),
        })
    return events
