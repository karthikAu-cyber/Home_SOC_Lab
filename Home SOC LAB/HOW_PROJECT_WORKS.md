# How the Project Works

## 1. Log Collection

The Windows VM produces several types of security telemetry:

```text
Windows Security Events
Windows System Events
Sysmon Events
PowerShell Events
Gmail phishing collector logs
```

Splunk monitors these logs using separate indexes:

| Index | Purpose |
|---|---|
| `wineventlog` | Windows Security/System/Application events |
| `sysmon` | Sysmon endpoint telemetry |
| `powershell` | PowerShell activity |
| `defender` | Microsoft Defender logs |
| `email` | Gmail phishing collector logs |

## 2. Attack Simulation

Kali Linux is used to simulate attacker behavior against the Windows VM.

Main simulation:

```text
Kali smbclient → Windows SMB service → Failed authentication → Windows Event ID 4625
```

Other simulations:

```text
Encoded PowerShell command
New local user creation
Admin group modification
Outbound connection to Kali listener
Security log clearing
Phishing-like email ingestion
```

## 3. Detection Logic

Splunk searches identify suspicious activity from the collected logs.

Examples:

```text
EventCode=4625 repeated multiple times → Possible brute force
EventCode=4720 → New user created
EventCode=4732 → Admin group modification
Sysmon Event ID 1 + EncodedCommand → Suspicious PowerShell
Sysmon Event ID 3 + destination port 4444 → Suspicious outbound connection
EventCode=1102 → Security log cleared
Email phishing score >= threshold → Real email phishing detection
```

## 4. Alerting

Each detection was saved as a Splunk scheduled alert.

Testing alert settings:

```text
Alert type: Scheduled
Run every: 1 minute
Time range: Last 15 minutes
Trigger condition: Number of Results > 0
Throttle: OFF
Actions: Add to Triggered Alerts + Send Email + Run Script
```

Final stable alert settings:

```text
Alert type: Scheduled
Run every: 5 minutes
Time range: Last 15 minutes
Trigger condition: Number of Results > 0
Throttle: ON
Suppress for: 30 minutes
Actions: Add to Triggered Alerts + Send Email + Run Script
```

## 5. Telegram Notification Flow

```text
Splunk alert triggers
    ↓
Splunk runs telegram_alert.cmd
    ↓
CMD wrapper runs splunk_telegram_alert.ps1
    ↓
PowerShell sends HTTPS request to Telegram Bot API
    ↓
Telegram message appears on phone
```

## 6. Email Phishing Detection Flow

```text
Gmail inbox
    ↓
Python IMAP collector
    ↓
C:\SOC-Lab\gmail_mail.log
    ↓
Splunk monitors gmail_mail.log
    ↓
SPL extracts sender, subject, URLs, attachments, verdict
    ↓
Phishing score calculated
    ↓
Alert triggers if score threshold is reached
```

## 7. Dashboard Flow

The final dashboard combines data from:

```text
wineventlog
sysmon
email
_internal scheduler logs
```

The dashboard shows:

```text
Total detections
Detection count by type
Detections over time
Unified detection timeline
Triggered Splunk alerts
Failed logins
Phishing detections
Suspicious PowerShell events
```

## 8. MITRE ATT&CK Mapping

| Detection | MITRE Technique |
|---|---|
| Suspicious Encoded PowerShell | T1059.001 - PowerShell |
| Multiple Failed Logins / SMB Brute Force | T1110 - Brute Force |
| Real Email Phishing | T1566 - Phishing |
| Suspicious Outbound Connection | T1071 - Application Layer Protocol |
| Security Log Cleared | T1070.001 - Clear Windows Event Logs |
| New Local User Created | T1136 - Create Account |
| Admin Group Change | T1098 - Account Manipulation |
