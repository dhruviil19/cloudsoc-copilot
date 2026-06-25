# Attack Scenarios

## Scenario 1: AWS Account Compromise

Evidence:

- Multiple failed AWS ConsoleLogin attempts
- Successful ConsoleLogin from same source IP
- CreateAccessKey event
- AdministratorAccess policy attached

Expected alerts:

- AWS brute force login attempt
- AWS successful login after brute force
- Possible AWS account compromise

## Scenario 2: Linux SSH Brute Force

Evidence:

- Multiple failed SSH login attempts
- Successful SSH login after failures

Expected alerts:

- SSH brute force login attempt
- SSH successful login after brute force

## Scenario 3: Suricata IDS Activity

Evidence:

- ET SCAN signature
- Possible C2 beacon signature

Expected alerts:

- Possible port scan detected
- Possible command and control traffic
- Suricata high-severity IDS alert

## Scenario 4: Vulnerable Public-Facing Service

Evidence:

- Nmap finds open Apache Struts service
- Service maps to sample CVE `CVE-2017-5638`
- CVE is present in local CISA KEV sample catalog

Expected alert:

- Known exploited vulnerability match

## Scenario 5: Suspicious Web Activity

Evidence:

- Requests for `/admin`
- Requests for `/.env`
- Requests for `/wp-login.php`
- Directory traversal attempt
- SQL injection-like query

Expected alert:

- Suspicious web activity detected
