import json
from datetime import datetime, timezone
from typing import Any, Dict, List


def _parse_time(value: str) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    clean = value.replace("Z", "+00:00")
    return datetime.fromisoformat(clean)


def _get_user(record: Dict[str, Any]) -> str:
    identity = record.get("userIdentity") or {}
    for key in ("userName", "arn", "principalId", "type"):
        if identity.get(key):
            return str(identity.get(key))
    return "unknown"


def _console_login_status(record: Dict[str, Any]) -> str:
    response = record.get("responseElements") or {}
    value = response.get("ConsoleLogin")
    if value == "Success":
        return "success"
    if value == "Failure":
        return "failed"
    error = record.get("errorCode") or record.get("errorMessage")
    if error:
        return "failed"
    return "unknown"


def _event_type(record: Dict[str, Any]) -> str:
    event_name = record.get("eventName", "")
    status = _console_login_status(record)

    if event_name == "ConsoleLogin" and status == "failed":
        return "login_failure"
    if event_name == "ConsoleLogin" and status == "success":
        return "login_success"
    if event_name == "CreateAccessKey":
        return "aws_access_key_created"
    if event_name in {"AttachUserPolicy", "PutUserPolicy", "AddUserToGroup", "AttachGroupPolicy"}:
        return "privilege_change"
    return event_name.lower() if event_name else "aws_event"


def parse_aws_cloudtrail(text: str) -> List[Dict[str, Any]]:
    data = json.loads(text)
    records = data.get("Records", data if isinstance(data, list) else [])
    events = []

    for index, record in enumerate(records):
        if not isinstance(record, dict):
            continue
        event_name = record.get("eventName", "Unknown")
        event_type = _event_type(record)
        status = _console_login_status(record) if event_name == "ConsoleLogin" else "success"
        account_id = (record.get("recipientAccountId") or "aws-account-demo")

        events.append({
            "timestamp": _parse_time(record.get("eventTime")),
            "source": "aws_cloudtrail",
            "event_type": event_type,
            "user": _get_user(record),
            "source_ip": record.get("sourceIPAddress"),
            "country": record.get("awsRegion"),
            "host": account_id,
            "action": event_name,
            "status": status,
            "raw_event_id": record.get("eventID") or f"aws-{index}",
            "raw_event": json.dumps(record, indent=2),
        })
    return events
