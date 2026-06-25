# Advanced Feature Summary

## Added features

- MITRE ATT&CK mapping for all major alert categories
- Sigma-style detection rules in `/detections`
- Suricata `eve.json` parser and IDS alert detections
- Nmap XML parser and vulnerability prioritization
- Local CISA KEV sample catalog matching
- Attack timeline graph in Streamlit
- Role-based dashboard views
- Docker Compose deployment
- Unit tests for advanced parsers and API flows
- Cloud deployment template and guide
- Demo video script and recording checklist

## New sample logs

```text
backend/sample_logs/suricata_eve.json
backend/sample_logs/nmap_scan.xml
backend/sample_logs/web_access.log
```

## New dashboard pages

- MITRE ATT&CK View
- Attack Timeline
- Vulnerability Prioritization
- Detection Rules
- Executive Summary

## Advanced detection examples

- Suricata high-severity IDS alert
- Possible command and control traffic
- Port scan activity
- Known exploited vulnerability match
- Risky exposed service
- Suspicious web activity
