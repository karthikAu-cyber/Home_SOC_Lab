# Windows-Kali SOC Lab with Splunk, Sysmon, Email Phishing Detection, and Telegram Alerts

## Project Overview

This project is a hands-on home SOC lab built using a Windows VM, Kali Linux VM, Splunk Enterprise, Sysmon, Windows Event Logs, Gmail phishing log collection, email notifications, Telegram notifications, and Splunk dashboards.

The goal of this lab is to simulate common security events, detect them in Splunk, generate alerts, and present the activity in a centralized SOC dashboard.

## Lab Architecture

```text
Kali Linux VM
    |
    | SMB failed-login simulation
    | Netcat listener / attack simulation
    v
Windows VM
    |
    | Windows Security Logs
    | Sysmon Logs
    | PowerShell Logs
    | Gmail phishing collector log
    v
Splunk Enterprise
    |
    | SPL detections
    | Scheduled alerts
    | Dashboards
    v
Email Notification + Telegram Notification
```

## Tools Used

| Tool | Purpose |
|---|---|
| Windows VM | Victim/monitored endpoint |
| Kali Linux VM | Attack simulation machine |
| Splunk Enterprise | SIEM/log analysis platform |
| Sysmon | Endpoint telemetry collection |
| Windows Event Logs | Security, System, PowerShell, Defender events |
| Gmail IMAP + Python | Real email phishing log collection |
| Telegram Bot API | Mobile alert notification |
| PowerShell | Windows configuration and alert scripting |
| SMBClient | Kali-to-Windows failed-login simulation |
| Netcat | Suspicious outbound connection simulation |

## Key Detections Implemented

| Detection | Log Source | Event ID / Logic | Severity |
|---|---|---|---|
| Suspicious Encoded PowerShell | Sysmon | Event ID 1 + `EncodedCommand` | High |
| New Local User Created | Windows Security | 4720 | Medium |
| User Added to Administrators Group | Windows Security | 4732 | High |
| Multiple Failed Logins / SMB Brute Force | Windows Security | 4625 threshold | Medium |
| Real Email Phishing Detected | Gmail collector log | phishing score logic | High |
| Suspicious Outbound Connection | Sysmon | Event ID 3 + destination port 4444 | High |
| Windows Security Log Cleared | Windows Security | 1102 | Critical |
| Email + Telegram Alerting | Splunk alert actions | Script + SMTP | High Value |

## Dashboard

Final dashboard name:

```text
SOC Alert Overview Dashboard
```

Recommended dashboard panels:

1. Total SOC Detections
2. SOC Detection Count by Type
3. SOC Alerts Over Time
4. Unified SOC Detection Timeline
5. All Triggered Splunk Alerts
6. Recent Failed Login Events
7. Real Email Phishing Detections
8. Suspicious PowerShell Events

## Notification Flow

```text
Detection Search in Splunk
    ↓
Scheduled Alert Trigger
    ↓
Triggered Alert Entry
    ↓
Email Notification
    ↓
Telegram Notification
```

## Project Outcome

This project demonstrates:

- Windows endpoint monitoring with Sysmon and Windows Event Logs.
- Kali-to-Windows attack simulation using SMB failed logins.
- Suspicious PowerShell detection.
- Local account and administrator group change detection.
- Real email phishing detection using Gmail IMAP and Splunk.
- Automated alerting through email and Telegram.
- Centralized SOC dashboard creation in Splunk.
- MITRE ATT&CK mapping for detections.

## Screenshots to Add

Create a `screenshots/` folder in GitHub and add:

```text
1_dashboard_overview.png
2_triggered_alerts.png
3_failed_login_kali_smb.png
4_splunk_4625_results.png
5_phishing_alert.png
6_telegram_notification.png
7_email_notification.png
8_powershell_detection.png
9_security_log_cleared.png
```

## Important Security Notes

Do not upload real secrets to GitHub.

Never upload:

```text
Telegram bot token
Gmail app password
Personal email password
Splunk admin password
Real private IP details, if sensitive
```

Use placeholders instead:

```text
YOUR_BOT_TOKEN
YOUR_CHAT_ID
YOUR_GMAIL_ADDRESS
YOUR_APP_PASSWORD
```

If a Telegram bot token was exposed during testing, revoke it using BotFather and generate a new one before uploading this project.
