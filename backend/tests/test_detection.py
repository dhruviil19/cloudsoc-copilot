from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_demo_detection_flow():
    reset = client.post("/api/demo/reset")
    assert reset.status_code == 200

    load = client.post("/api/demo/load-samples")
    assert load.status_code == 200
    assert load.json()["events_ingested"] > 0

    detect = client.post("/api/detect/run")
    assert detect.status_code == 200
    assert detect.json()["results"]["total_alerts"] > 0

    alerts = client.get("/api/alerts")
    assert alerts.status_code == 200
    assert len(alerts.json()) > 0
