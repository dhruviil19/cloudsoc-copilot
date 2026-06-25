from pathlib import Path
from typing import Dict, List
from ..config import REPORT_DIR


def generate_markdown_report(alert: Dict, evidence: List[Dict]) -> Path:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    path = REPORT_DIR / f"incident_{alert['id']:03d}.md"

    evidence_lines = []
    for item in evidence:
        event = item["event"]
        evidence_lines.append(
            f"| {event.get('timestamp')} | {event.get('source')} | {event.get('event_type')} | "
            f"{event.get('user') or ''} | {event.get('source_ip') or ''} | {event.get('action') or ''} | {event.get('status') or ''} |"
        )

    content = f"""# Incident Report: {alert['title']}

## Summary

{alert.get('ai_summary') or alert.get('description')}

## Alert Details

| Field | Value |
|---|---|
| Alert ID | {alert['id']} |
| Severity | {alert['severity']} |
| Risk Score | {alert['risk_score']}/100 |
| User | {alert.get('user') or 'Unknown'} |
| Source IP | {alert.get('source_ip') or 'Unknown'} |
| Host | {alert.get('host') or 'Unknown'} |
| Status | {alert.get('status') or 'Open'} |
| MITRE Tactic | {alert.get('mitre_tactic') or 'Not mapped'} |
| MITRE Technique | {alert.get('mitre_technique') or 'Not mapped'} |

## Evidence Timeline

| Time | Source | Event Type | User | Source IP | Action | Status |
|---|---|---|---|---|---|---|
{chr(10).join(evidence_lines)}

## Recommended Response

1. Validate whether the activity was expected.
2. Disable or rotate credentials for the affected account.
3. Revoke suspicious access keys or sessions.
4. Remove unauthorized privileges.
5. Review logs for related activity from the same source IP, user, and host.
6. Document findings and close the incident after confirmation.
"""
    path.write_text(content, encoding="utf-8")
    return path
