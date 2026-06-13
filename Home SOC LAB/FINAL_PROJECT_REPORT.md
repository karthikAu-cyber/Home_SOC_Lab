# Final Project Report: Windows-Kali SOC Lab with Splunk, Sysmon, Phishing Detection, and Telegram Alerts

## 1. Project Title

Windows-Kali SOC Lab: Endpoint Monitoring, Attack Simulation, Phishing Detection, and Automated Alerting with Splunk

## 2. Objective

The objective of this project was to build a practical SOC monitoring lab that detects suspicious activity from Windows endpoint logs, Kali Linux attack simulations, and real email phishing indicators. The project also implements automated email and Telegram notifications and presents detections in a Splunk dashboard.

## 3. Environment

| Component | Description |
|---|---|
| Windows VM | Main monitored endpoint and Splunk server |
| Kali Linux VM | Attacker simulation system |
| Splunk Enterprise | SIEM platform |
| Sysmon | Endpoint telemetry |
| Gmail IMAP | Email source for phishing detection |
| Telegram Bot | Mobile notification channel |
| PowerShell | Windows configuration and alert scripts |

## 4. Architecture

```text
Kali Linux VM
    |
    | Attack simulation
    | - SMB failed logins
    | - Netcat listener
    v
Windows VM
    |
    | Log generation
    | - Windows Security logs
    | - Sysmon logs
    | - Gmail phishing collector log
    v
Splunk Enterprise
    |
    | Detection searches
    | Scheduled alerts
    | Dashboards
    v
Email + Telegram notifications
```

## 5. Log Sources

| Log Source | Splunk Index | Purpose |
|---|---|---|
| Windows Security Logs | `wineventlog` | Logon failures, user creation, group changes, log clearing |
| Sysmon Logs | `sysmon` | Process creation and network connection telemetry |
| Gmail Collector Log | `email` | Real email phishing monitoring |
| Splunk Internal Logs | `_internal` | Alert scheduler and triggered alert visibility |

## 6. Detections Built

### 6.1 Suspicious Encoded PowerShell

Detects suspicious PowerShell usage such as `EncodedCommand`, `IEX`, and `DownloadString`.

MITRE ATT&CK:

```text
T1059.001 - PowerShell
```

### 6.2 New Local User Created

Detects Windows Security Event ID 4720.

MITRE ATT&CK:

```text
T1136 - Create Account
```

### 6.3 User Added to Administrators Group

Detects Windows Security Event ID 4732.

MITRE ATT&CK:

```text
T1098 - Account Manipulation
```

### 6.4 Multiple Failed Logins / SMB Brute Force

Detects repeated Windows Security Event ID 4625 events from the same account/source IP.

Kali simulation used:

```bash
smbclient -L //WINDOWS_IP -U smbtest%WrongPassword
```

MITRE ATT&CK:

```text
T1110 - Brute Force
```

### 6.5 Real Email Phishing Detection

Uses a Python IMAP collector to ingest Gmail metadata and content indicators into Splunk. Splunk calculates a phishing score from sender, subject, URLs, and attachments.

MITRE ATT&CK:

```text
T1566 - Phishing
```

### 6.6 Suspicious Outbound Connection

Detects Sysmon Event ID 3 connections to suspicious port 4444.

MITRE ATT&CK:

```text
T1071 - Application Layer Protocol
```

### 6.7 Windows Security Log Cleared

Detects Windows Security Event ID 1102.

MITRE ATT&CK:

```text
T1070.001 - Clear Windows Event Logs
```

## 7. Alerting

Each detection was saved as a Splunk scheduled alert.

Testing settings:

```text
Run every: 1 minute
Time range: Last 15 minutes
Trigger: Number of Results > 0
Throttle: Off
Actions: Add to Triggered Alerts, Send Email, Run Script
```

Stable settings:

```text
Run every: 5 minutes
Time range: Last 15 minutes
Trigger: Number of Results > 0
Throttle: On, suppress for 30 minutes
Actions: Add to Triggered Alerts, Send Email, Run Script
```

## 8. Telegram Notification

Telegram alerts were implemented using:

```text
Splunk Run a Script action
    ↓
telegram_alert.cmd
    ↓
splunk_telegram_alert.ps1
    ↓
Telegram Bot API
    ↓
Telegram mobile notification
```

The script was stored in:

```text
C:\Program Files\Splunk\bin\scripts
```

Splunk script filename:

```text
telegram_alert.cmd
```

## 9. Dashboard

A final SOC dashboard was created to view all detections in one place.

Dashboard name:

```text
SOC Alert Overview Dashboard
```

Main panels:

```text
1. Total SOC Detections
2. SOC Detection Count by Type
3. SOC Alerts Over Time
4. Unified SOC Detection Timeline
5. All Triggered Splunk Alerts
6. Recent Failed Login Events
7. Real Email Phishing Detections
8. Suspicious PowerShell Events
```

## 10. Project Results

The lab successfully detected and alerted on:

```text
Suspicious Encoded PowerShell
New Local User Creation
Admin Group Modification
Kali SMB Failed Login / Brute Force Behavior
Real Email Phishing Indicators
Suspicious Outbound Connection
Windows Security Log Clearing
```

Notifications were successfully delivered through:

```text
Email
Telegram
Splunk Triggered Alerts
```

## 11. Challenges and Fixes

| Issue | Fix |
|---|---|
| RDP firewall rules not found | Used SMB failed-login simulation instead |
| Nmap port scan did not show Sysmon events | Skipped as optional because Sysmon does not reliably log inbound probes |
| Telegram `getUpdates` conflict | Deleted webhook using Telegram API |
| PowerShell path error with Program Files | Used quotes around paths |
| Email phishing triggered too often | Removed broad URL-only trigger and used phishing score logic |
| Splunk dashboard tables only | Built a new overview dashboard with charts and timeline panels |

## 12. Skills Demonstrated

```text
SIEM configuration
Windows log analysis
Sysmon telemetry analysis
SPL detection engineering
Kali attack simulation
Phishing detection logic
Alert tuning
Telegram API integration
SOC dashboard creation
Incident triage mapping
MITRE ATT&CK mapping
```

## 13. GitHub Repository Structure

Recommended structure:

```text
windows-kali-soc-lab/
│
├── README.md
├── FINAL_PROJECT_REPORT.md
├── COMMANDS_USED.md
├── HOW_PROJECT_WORKS.md
│
├── spl/
│   └── SPL_DETECTIONS.md
│
├── scripts/
│   ├── gmail_to_splunk.py
│   ├── splunk_telegram_alert.ps1
│   └── telegram_alert.cmd
│
├── docs/
│   └── INCIDENT_RESPONSE_PLAYBOOKS.md
│
└── screenshots/
    ├── dashboard_overview.png
    ├── triggered_alerts.png
    ├── telegram_notification.png
    ├── email_notification.png
    ├── failed_login_results.png
    └── phishing_alert.png
```

## 14. Conclusion

This project demonstrates a complete beginner-friendly SOC workflow: collecting endpoint logs, simulating attacker behavior, creating SPL detections, building alerts, sending mobile notifications, and presenting results in a dashboard. It is suitable for a fresher SOC analyst portfolio because it shows practical SIEM, Windows security monitoring, detection engineering, and incident triage skills.
