# Demo Video Script

Target length: 3 to 5 minutes.

## Scene 1: Introduction

Say:

CloudSOC Copilot is an AI-assisted SOC investigation platform that analyzes cloud, Linux, IDS, web, and vulnerability logs. It normalizes events, detects suspicious activity, maps alerts to MITRE ATT&CK, prioritizes vulnerabilities using CISA KEV context, and generates incident reports.

## Scene 2: Load demo data

Show the dashboard.

Click:

```text
Load Advanced Demo Logs
Run Detection
```

Explain that the demo loads AWS CloudTrail, Linux SSH auth logs, Suricata IDS alerts, Nmap scan results, and web access logs.

## Scene 3: Alert queue

Open Alerts Queue.

Point out:

- AWS account compromise
- SSH brute force
- Suricata IDS alert
- Port scan
- Known exploited vulnerability match
- Suspicious web activity

## Scene 4: Incident detail

Open a Critical alert.

Show:

- Risk score
- Evidence timeline
- MITRE mapping
- AI investigation summary
- Raw logs

## Scene 5: MITRE and timeline

Open MITRE ATT&CK View and Attack Timeline.

Explain that the system groups alert behavior by tactics and techniques and shows the investigation timeline visually.

## Scene 6: Vulnerability prioritization

Open Vulnerability Prioritization.

Explain that Nmap services are enriched using a local CISA KEV sample catalog to prioritize patching.

## Scene 7: Report export

Return to Incident Detail and click Export Markdown Report.

Show the generated report link.

## Closing

Say:

This project demonstrates SOC analysis, cloud security, detection engineering, MITRE ATT&CK mapping, vulnerability prioritization, incident response reporting, and AI-assisted security workflows.
