# Architecture

```text
[Sample Logs or Uploaded Logs]
AWS CloudTrail / Linux Auth / Suricata eve.json / Nmap XML / Web Access Logs
        |
        v
[Parser Router]
Chooses the correct parser based on file type and content
        |
        v
[Normalization Layer]
Converts all logs into one event schema
        |
        v
[SQLite Event Database]
Stores events, alerts, and incident evidence
        |
        v
[Detection Engine]
Correlation rules, risk scoring, MITRE mapping, vulnerability prioritization
        |
        v
[AI Summary Generator]
Template-based by default, optional OpenAI API if configured
        |
        v
[Streamlit Dashboard]
Overview, alerts, incident detail, MITRE view, timeline, vulnerability priorities, rules
        |
        v
[Markdown Report Export]
Reports saved in /reports
```

## Key modules

| Module | Purpose |
|---|---|
| `parsers/` | Converts raw logs into normalized events |
| `detection_engine/` | Applies correlation and detection logic |
| `risk_engine/` | Converts detection factors into severity and risk score |
| `threat_intel/` | Loads local CISA KEV sample data |
| `ai_engine/` | Generates SOC-style incident summaries |
| `report_generator/` | Creates Markdown incident reports |
| `dashboard/` | Streamlit role-based dashboard |
