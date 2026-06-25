from typing import Any, Dict, List
from ..config import OPENAI_API_KEY


def _format_evidence(evidence: List[Dict[str, Any]]) -> str:
    lines = []
    for item in evidence:
        event = item["event"]
        lines.append(
            f"- {event.get('timestamp')} | {event.get('source')} | "
            f"{event.get('event_type')} | user={event.get('user')} | "
            f"ip={event.get('source_ip')} | action={event.get('action')} | status={event.get('status')}"
        )
    return "\n".join(lines)


def generate_local_summary(alert: Dict[str, Any], evidence: List[Dict[str, Any]]) -> str:
    evidence_text = _format_evidence(evidence)
    user = alert.get("user") or "unknown user"
    source_ip = alert.get("source_ip") or "unknown source IP"
    host = alert.get("host") or "unknown host"

    return f"""Incident Summary:
A {alert.get('severity', 'Unknown').lower()} security incident was detected for {user} from {source_ip} on {host}. The alert is classified as {alert.get('title')} with a risk score of {alert.get('risk_score')}/100.

Why this is suspicious:
The evidence shows a sequence of behavior that may indicate credential abuse, account compromise, or attacker persistence. The activity includes failed authentication attempts, a successful login after suspicious failures, or cloud account changes such as access key creation or privilege modification.

MITRE ATT&CK Mapping:
Tactic: {alert.get('mitre_tactic') or 'Not mapped'}
Technique: {alert.get('mitre_technique') or 'Not mapped'}

Evidence:
{evidence_text}

Recommended Response:
1. Confirm whether the login and account changes were expected.
2. Disable or rotate credentials for the affected account if activity is suspicious.
3. Revoke newly created access keys or suspicious sessions.
4. Remove unauthorized privilege changes.
5. Review related logs for additional activity from the same IP, user, or host.
6. Document the timeline and close the incident only after validation."""


def generate_summary(alert: Dict[str, Any], evidence: List[Dict[str, Any]]) -> str:
    if not OPENAI_API_KEY:
        return generate_local_summary(alert, evidence)

    try:
        from openai import OpenAI
        client = OpenAI(api_key=OPENAI_API_KEY)
        prompt = f"""
You are a SOC analyst. Write a concise incident investigation summary.

Alert:
{alert}

Evidence:
{evidence}

Return these sections:
Incident Summary, Why This Is Suspicious, MITRE ATT&CK Mapping, Evidence, Recommended Response.
"""
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You write clear SOC analyst investigation notes."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
        )
        return response.choices[0].message.content or generate_local_summary(alert, evidence)
    except Exception:
        return generate_local_summary(alert, evidence)
