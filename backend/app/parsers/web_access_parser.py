import re
from datetime import datetime
from typing import Any, Dict, List

ACCESS_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<proto>[^"]+)"\s+(?P<status>\d{3})\s+(?P<size>\S+)(\s+"[^"]*"\s+"(?P<ua>[^"]*)")?'
)

SUSPICIOUS_PATTERNS = [
    "/.env", "/wp-login.php", "/phpmyadmin", "/admin", "../", "etc/passwd", "' or 1=1", "union select", "<script", "/.git/config"
]


def _parse_time(value: str) -> datetime:
    # Example: 14/Jun/2026:10:01:40 +0000
    return datetime.strptime(value.split()[0], "%d/%b/%Y:%H:%M:%S")


def parse_web_access(text: str) -> List[Dict[str, Any]]:
    events = []
    for index, line in enumerate(text.splitlines()):
        line = line.strip()
        if not line:
            continue
        match = ACCESS_RE.search(line)
        if not match:
            continue
        data = match.groupdict()
        path = data.get("path") or ""
        method = data.get("method") or "GET"
        lowered = path.lower()
        suspicious = any(pattern in lowered for pattern in SUSPICIOUS_PATTERNS)
        events.append({
            "timestamp": _parse_time(data["time"]),
            "source": "web_access",
            "event_type": "web_suspicious_request" if suspicious else "web_request",
            "user": None,
            "source_ip": data.get("ip"),
            "country": None,
            "host": "web-server-demo",
            "action": f"{method} {path}",
            "status": data.get("status"),
            "raw_event_id": f"web-{index}",
            "raw_event": line,
        })
    return events
