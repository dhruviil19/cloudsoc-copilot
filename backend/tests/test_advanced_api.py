from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_advanced_demo_creates_expected_alert_categories():
    assert client.post("/api/demo/reset").status_code == 200
    load = client.post("/api/demo/load-samples")
    assert load.status_code == 200
    assert load.json()["events_ingested"] > 20

    detect = client.post("/api/detect/run")
    assert detect.status_code == 200
    results = detect.json()["results"]
    assert results["suricata_alerts"] >= 1
    assert results["vulnerability_priorities"] >= 1
    assert results["web_suspicious_requests"] >= 1

    mitre = client.get("/api/mitre/coverage")
    assert mitre.status_code == 200
    assert mitre.json()["coverage"]

    rules = client.get("/api/detections/rules")
    assert rules.status_code == 200
    assert len(rules.json()) >= 5

    vulns = client.get("/api/vulnerabilities/priorities")
    assert vulns.status_code == 200
    assert any(item.get("cisa_kev") for item in vulns.json())
