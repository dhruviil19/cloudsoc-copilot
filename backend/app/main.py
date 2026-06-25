import json
from pathlib import Path
from typing import Dict, List
import yaml
from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from .database import Base, engine, get_db
from .models import NormalizedEvent, Alert, IncidentEvidence
from .parsers.parser_router import parse_uploaded_log
from .detection_engine.detector import run_detection
from .report_generator.markdown_report import generate_markdown_report
from .detection_engine.rules import MITRE_MAPPINGS
from .threat_intel.cisa_kev import load_kev_catalog

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="CloudSOC Copilot API",
    description="Advanced API for SOC-style log ingestion, detection, triage, MITRE mapping, vulnerability prioritization, IDS support, and reporting.",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def event_to_dict(event: NormalizedEvent, include_raw: bool = False) -> Dict:
    data = {
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
    }
    if include_raw:
        data["raw_event"] = event.raw_event
    return data


def alert_to_dict(alert: Alert) -> Dict:
    return {
        "id": alert.id,
        "title": alert.title,
        "severity": alert.severity,
        "risk_score": alert.risk_score,
        "user": alert.user,
        "source_ip": alert.source_ip,
        "host": alert.host,
        "status": alert.status,
        "mitre_tactic": alert.mitre_tactic,
        "mitre_technique": alert.mitre_technique,
        "description": alert.description,
        "ai_summary": alert.ai_summary,
        "created_at": alert.created_at.isoformat() if alert.created_at else None,
    }


def evidence_for_alert(db: Session, alert_id: int) -> List[Dict]:
    rows = (
        db.query(IncidentEvidence)
        .filter(IncidentEvidence.alert_id == alert_id)
        .order_by(IncidentEvidence.id.asc())
        .all()
    )
    return [
        {
            "evidence_type": row.evidence_type,
            "event": event_to_dict(row.event, include_raw=True),
        }
        for row in rows
    ]


def project_root() -> Path:
    current = Path(__file__).resolve()
    for parent in current.parents:
        if (parent / "detections").exists() or (parent / "README.md").exists():
            return parent
    return current.parents[1]


@app.get("/")
def root():
    return {
        "name": "CloudSOC Copilot",
        "version": "2.0.0-advanced",
        "status": "running",
        "message": "Upload logs, run detections, review alerts, map MITRE ATT&CK, prioritize vulnerabilities, and export reports.",
    }


@app.post("/api/upload")
async def upload_log(file: UploadFile = File(...), db: Session = Depends(get_db)):
    content = await file.read()
    text = content.decode("utf-8", errors="replace")

    try:
        parsed_events = parse_uploaded_log(file.filename or "uploaded.log", text)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    for event in parsed_events:
        db.add(NormalizedEvent(**event))
    db.commit()

    return {
        "filename": file.filename,
        "events_ingested": len(parsed_events),
    }


@app.post("/api/demo/reset")
def reset_demo(db: Session = Depends(get_db)):
    db.query(IncidentEvidence).delete()
    db.query(Alert).delete()
    db.query(NormalizedEvent).delete()
    db.commit()
    return {"message": "Database reset complete."}


@app.post("/api/demo/load-samples")
def load_sample_logs(db: Session = Depends(get_db)):
    sample_dir = Path(__file__).resolve().parents[1] / "sample_logs"
    files = [
        sample_dir / "aws_compromise.json",
        sample_dir / "linux_ssh_bruteforce.log",
        sample_dir / "suricata_eve.json",
        sample_dir / "nmap_scan.xml",
        sample_dir / "web_access.log",
    ]
    total = 0
    loaded_files = []

    for path in files:
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        parsed_events = parse_uploaded_log(path.name, text)
        for event in parsed_events:
            db.add(NormalizedEvent(**event))
        total += len(parsed_events)
        loaded_files.append(path.name)

    db.commit()
    return {"message": "Sample logs loaded.", "events_ingested": total, "files": loaded_files}


@app.post("/api/detect/run")
def run_detection_endpoint(db: Session = Depends(get_db)):
    counts = run_detection(db)
    return {"message": "Detection completed.", "results": counts}


@app.get("/api/events")
def get_events(limit: int = 500, db: Session = Depends(get_db)):
    events = db.query(NormalizedEvent).order_by(NormalizedEvent.timestamp.desc()).limit(limit).all()
    return [event_to_dict(event) for event in events]


@app.get("/api/timeline")
def get_timeline(db: Session = Depends(get_db)):
    events = db.query(NormalizedEvent).order_by(NormalizedEvent.timestamp.asc()).all()
    return [event_to_dict(event) for event in events]


@app.get("/api/alerts")
def get_alerts(db: Session = Depends(get_db)):
    alerts = db.query(Alert).order_by(Alert.risk_score.desc(), Alert.created_at.desc()).all()
    return [alert_to_dict(alert) for alert in alerts]


@app.get("/api/alerts/{alert_id}")
def get_alert_detail(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"alert": alert_to_dict(alert), "evidence": evidence_for_alert(db, alert_id)}


@app.post("/api/alerts/{alert_id}/report")
def create_report(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert_data = alert_to_dict(alert)
    evidence = evidence_for_alert(db, alert_id)
    path = generate_markdown_report(alert_data, evidence)
    return {"message": "Report generated.", "report_path": str(path), "download_url": f"/api/reports/{path.name}"}


@app.get("/api/reports/{filename}")
def download_report(filename: str):
    report_path = Path("../reports") / filename
    if not report_path.exists():
        report_path = Path("/reports") / filename
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(path=report_path, filename=filename, media_type="text/markdown")


@app.get("/api/metrics")
def get_metrics(db: Session = Depends(get_db)):
    alerts = db.query(Alert).all()
    events_count = db.query(NormalizedEvent).count()
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for alert in alerts:
        severity_counts[alert.severity] = severity_counts.get(alert.severity, 0) + 1

    top_ips = {}
    high_risk_users = {}
    mitre_tactics = {}
    sources = {}
    for alert in alerts:
        if alert.source_ip:
            top_ips[alert.source_ip] = top_ips.get(alert.source_ip, 0) + 1
        if alert.user and alert.risk_score >= 61:
            high_risk_users[alert.user] = high_risk_users.get(alert.user, 0) + 1
        if alert.mitre_tactic:
            mitre_tactics[alert.mitre_tactic] = mitre_tactics.get(alert.mitre_tactic, 0) + 1
    for source, count in db.query(NormalizedEvent.source, NormalizedEvent.id).all():
        sources[source] = sources.get(source, 0) + 1

    return {
        "events": events_count,
        "alerts": len(alerts),
        "critical_alerts": severity_counts.get("Critical", 0),
        "high_alerts": severity_counts.get("High", 0),
        "severity_counts": severity_counts,
        "top_source_ips": sorted(top_ips.items(), key=lambda x: x[1], reverse=True)[:5],
        "high_risk_users": sorted(high_risk_users.items(), key=lambda x: x[1], reverse=True)[:5],
        "mitre_tactics": sorted(mitre_tactics.items(), key=lambda x: x[1], reverse=True),
        "sources": sorted(sources.items(), key=lambda x: x[1], reverse=True),
    }


@app.get("/api/mitre/coverage")
def mitre_coverage(db: Session = Depends(get_db)):
    alerts = db.query(Alert).all()
    coverage = {}
    for alert in alerts:
        tactic = alert.mitre_tactic or "Unmapped"
        technique = alert.mitre_technique or "Unmapped"
        coverage.setdefault(tactic, {})
        coverage[tactic][technique] = coverage[tactic].get(technique, 0) + 1
    return {
        "coverage": coverage,
        "available_mappings": MITRE_MAPPINGS,
    }


@app.get("/api/detections/rules")
def detection_rules():
    rules_dir = project_root() / "detections"
    rules = []
    if not rules_dir.exists():
        return rules
    for path in sorted(rules_dir.rglob("*.yml")):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except Exception:
            data = {"title": path.stem, "parse_error": True}
        data["path"] = str(path.relative_to(project_root()))
        rules.append(data)
    return rules


@app.get("/api/vulnerabilities/priorities")
def vulnerability_priorities(db: Session = Depends(get_db)):
    events = db.query(NormalizedEvent).filter(NormalizedEvent.source == "nmap_scan").all()
    results = []
    for event in events:
        try:
            raw = json.loads(event.raw_event or "{}")
        except Exception:
            raw = {}
        cve_match = raw.get("cve_match") or {}
        score = 0
        reasons = []
        if raw.get("risky_port"):
            score += 25
            reasons.append("Risky open port")
        if cve_match.get("cvss"):
            score += 20
            reasons.append(f"CVSS {cve_match.get('cvss')}")
        if cve_match.get("cisa_kev"):
            score += 60
            reasons.append("CISA KEV match")
        score = min(score, 100)
        if score == 0:
            continue
        severity = "Critical" if score >= 81 else "High" if score >= 61 else "Medium" if score >= 31 else "Low"
        results.append({
            "host": event.host,
            "service": raw.get("service"),
            "port": raw.get("port"),
            "protocol": raw.get("protocol"),
            "cve_id": cve_match.get("cve_id"),
            "cisa_kev": bool(cve_match.get("cisa_kev")),
            "cvss": cve_match.get("cvss"),
            "priority_score": score,
            "severity": severity,
            "reason": ", ".join(reasons),
            "recommended_action": ((cve_match.get("kev_record") or {}).get("required_action") or "Review exposure and patch or restrict access."),
        })
    return sorted(results, key=lambda item: item["priority_score"], reverse=True)


@app.get("/api/threat-intel/cisa-kev")
def get_cisa_kev_sample():
    return list(load_kev_catalog().values())
