# Detection Rules

CloudSOC Copilot uses Python detection logic plus Sigma-style YAML rules.

## Current rule families

| Rule | Source | Detection idea | MITRE mapping |
|---|---|---|---|
| Failed login burst | AWS, Linux SSH | Many failed logins from one source IP | Credential Access, T1110 Brute Force |
| Successful login after failures | AWS, Linux SSH | Successful login after many failures | Initial Access, T1078 Valid Accounts |
| AWS account compromise sequence | AWS CloudTrail | Failed logins, success, access key creation, privilege change | Persistence, T1098 Account Manipulation |
| Suricata high severity IDS alert | Suricata eve.json | High or critical IDS signature | Initial Access, T1190 Exploit Public-Facing Application |
| Port scan | Suricata eve.json | Scan-like IDS signature | Discovery, T1046 Network Service Discovery |
| Vulnerability priority | Nmap XML | Risky open port or CVE mapped to local KEV sample | Initial Access, T1190 Exploit Public-Facing Application |
| Suspicious web activity | Web access logs | Suspicious paths such as /.env, /wp-login.php, traversal, SQLi patterns | Reconnaissance, T1595 Active Scanning |

## Sigma-style YAML folder

```text
detections/
  aws/
  linux/
  suricata/
  vulnerability/
  web/
```

The dashboard includes a Detection Rules page that reads these YAML files and displays rule details.
