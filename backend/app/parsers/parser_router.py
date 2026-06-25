import json
from typing import Any, Dict, List
from .aws_parser import parse_aws_cloudtrail
from .linux_auth_parser import parse_linux_auth
from .suricata_parser import parse_suricata_eve
from .nmap_parser import parse_nmap_xml
from .web_access_parser import parse_web_access


def _json_records(text: str):
    data = json.loads(text)
    if isinstance(data, dict):
        return data.get("Records", data.get("events", [data]))
    if isinstance(data, list):
        return data
    return []


def parse_uploaded_log(filename: str, text: str) -> List[Dict[str, Any]]:
    lower = filename.lower()
    stripped = text.strip()

    if lower.endswith(".xml") or "<nmaprun" in stripped[:500].lower():
        return parse_nmap_xml(text)

    if lower.endswith(".json") or lower.endswith(".jsonl") or lower.endswith(".ndjson"):
        try:
            records = _json_records(text) if lower.endswith(".json") else []
            if records and isinstance(records[0], dict) and (
                "eventSource" in records[0] or "eventName" in records[0] or "userIdentity" in records[0]
            ):
                return parse_aws_cloudtrail(text)
        except Exception:
            pass

        suricata_events = parse_suricata_eve(text)
        if suricata_events:
            return suricata_events

        try:
            # If this was JSON but not a supported JSON security format, show a clearer error.
            json.loads(stripped)
        except Exception as exc:
            raise ValueError(f"Invalid JSON log file: {exc}") from exc

    linux_events = parse_linux_auth(text)
    if linux_events:
        return linux_events

    web_events = parse_web_access(text)
    if web_events:
        return web_events

    raise ValueError(
        "Unsupported log format. Upload AWS CloudTrail JSON, Linux auth logs, Suricata eve.json, Nmap XML, or Apache/Nginx access logs."
    )
