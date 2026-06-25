import json
import re
from datetime import datetime
from typing import Any, Dict, List

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

FAILED_RE = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\S+)"
)

ACCEPTED_RE = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+Accepted password for (?P<user>\S+) from (?P<ip>\S+)"
)


def _parse_syslog_time(mon: str, day: str, time_value: str) -> datetime:
    year = 2026
    hour, minute, second = [int(part) for part in time_value.split(":")]
    return datetime(year, MONTHS.get(mon, 1), int(day), hour, minute, second)


def _event(match: re.Match, event_type: str, status: str, line: str, index: int) -> Dict[str, Any]:
    group = match.groupdict()
    return {
        "timestamp": _parse_syslog_time(group["mon"], group["day"], group["time"]),
        "source": "linux_auth",
        "event_type": event_type,
        "user": group.get("user"),
        "source_ip": group.get("ip"),
        "country": None,
        "host": group.get("host"),
        "action": "ssh_login",
        "status": status,
        "raw_event_id": f"linux-{index}",
        "raw_event": line,
    }


def parse_linux_auth(text: str) -> List[Dict[str, Any]]:
    events = []
    for index, line in enumerate(text.splitlines()):
        line = line.strip()
        if not line:
            continue

        failed = FAILED_RE.search(line)
        if failed:
            events.append(_event(failed, "login_failure", "failed", line, index))
            continue

        accepted = ACCEPTED_RE.search(line)
        if accepted:
            events.append(_event(accepted, "login_success", "success", line, index))
            continue
    return events
