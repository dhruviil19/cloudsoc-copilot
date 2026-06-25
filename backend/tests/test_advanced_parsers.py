from pathlib import Path
from app.parsers.parser_router import parse_uploaded_log

SAMPLE_DIR = Path(__file__).resolve().parents[1] / "sample_logs"


def test_suricata_parser_ingests_eve_json():
    events = parse_uploaded_log("suricata_eve.json", (SAMPLE_DIR / "suricata_eve.json").read_text())
    assert len(events) >= 2
    assert any(event["source"] == "suricata_eve" for event in events)
    assert any(event["event_type"] == "port_scan" for event in events)


def test_nmap_parser_ingests_services_and_cve_context():
    events = parse_uploaded_log("nmap_scan.xml", (SAMPLE_DIR / "nmap_scan.xml").read_text())
    assert len(events) >= 2
    assert all(event["source"] == "nmap_scan" for event in events)
    assert any("CVE-2017-5638" in event["raw_event"] for event in events)


def test_web_parser_ingests_suspicious_paths():
    events = parse_uploaded_log("web_access.log", (SAMPLE_DIR / "web_access.log").read_text())
    assert len(events) >= 3
    assert any(event["event_type"] == "web_suspicious_request" for event in events)
