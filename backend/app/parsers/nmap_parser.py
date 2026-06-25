import json
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from ..threat_intel.cisa_kev import get_kev_record

SERVICE_CVE_MAP = {
    "apache struts": {
        "cve_id": "CVE-2017-5638",
        "cvss": 10.0,
        "reason": "Apache Struts service/version is mapped to a known remote code execution demo CVE."
    },
    "apache httpd 2.4.49": {
        "cve_id": "CVE-2021-41773",
        "cvss": 7.5,
        "reason": "Apache HTTP Server 2.4.49 is mapped to a path traversal demo CVE."
    },
    "moveit": {
        "cve_id": "CVE-2023-34362",
        "cvss": 9.8,
        "reason": "MOVEit Transfer is mapped to a known exploited SQL injection demo CVE."
    }
}

RISKY_PORTS = {21, 22, 23, 3389, 3306, 5432, 6379, 27017, 9200}


def _host_address(host: ET.Element) -> str:
    for addr in host.findall("address"):
        if addr.get("addr"):
            return str(addr.get("addr"))
    return "unknown-host"


def _service_text(service: Optional[ET.Element]) -> str:
    if service is None:
        return "unknown"
    parts = [
        service.get("name"),
        service.get("product"),
        service.get("version"),
        service.get("extrainfo"),
    ]
    return " ".join(str(part) for part in parts if part).strip() or "unknown"


def _match_cve(service_text: str) -> Optional[Dict[str, Any]]:
    lower = service_text.lower()
    for needle, value in SERVICE_CVE_MAP.items():
        if needle in lower:
            cve_id = value["cve_id"]
            kev_record = get_kev_record(cve_id)
            enriched = dict(value)
            enriched["cisa_kev"] = bool(kev_record)
            enriched["kev_record"] = kev_record
            return enriched
    return None


def parse_nmap_xml(text: str) -> List[Dict[str, Any]]:
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError(f"Invalid Nmap XML file: {exc}") from exc

    events = []
    now = datetime.now(timezone.utc)
    for host_index, host in enumerate(root.findall("host")):
        address = _host_address(host)
        for port_index, port in enumerate(host.findall(".//port")):
            state = port.find("state")
            if state is not None and state.get("state") != "open":
                continue
            service = port.find("service")
            service_desc = _service_text(service)
            port_id = int(port.get("portid") or 0)
            protocol = port.get("protocol") or "tcp"
            cve_match = _match_cve(service_desc)
            is_risky_port = port_id in RISKY_PORTS
            raw = {
                "host": address,
                "port": port_id,
                "protocol": protocol,
                "service": service_desc,
                "risky_port": is_risky_port,
                "cve_match": cve_match,
                "asset_exposure": "public-facing-demo",
            }
            events.append({
                "timestamp": now,
                "source": "nmap_scan",
                "event_type": "nmap_service",
                "user": None,
                "source_ip": None,
                "country": None,
                "host": address,
                "action": f"open {protocol}/{port_id} {service_desc}",
                "status": "open",
                "raw_event_id": f"nmap-{host_index}-{port_index}",
                "raw_event": json.dumps(raw, indent=2),
            })
    return events
