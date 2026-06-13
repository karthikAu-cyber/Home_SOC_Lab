# Commands Used in the Windows-Kali SOC Lab

This file contains the main commands used during the SOC lab build, testing, alerting, and troubleshooting.

---

## 1. Splunk Start / Restart Commands

Run from PowerShell:

```powershell
cd "C:\Program Files\Splunk\bin"
.\splunk.exe start
.\splunk.exe restart
.\splunk.exe status
```

Splunk Web:

```text
http://localhost:8000
```

---

## 2. Sysmon Installation

Sysmon files were placed in:

```text
C:\Tools
```

Install Sysmon:

```powershell
cd C:\Tools
.\Sysmon64.exe -accepteula -i .\sysmonconfig-export.xml
```

Check Sysmon service:

```powershell
Get-Service Sysmon64
```

---

## 3. Suspicious Encoded PowerShell Test

Test command:

```powershell
powershell.exe -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAFMATwBDAEwAYQBiACAAVABlAHMAdAAiAA==
```

This generates Sysmon Event ID 1 process creation activity.

---

## 4. New Local User Created Test

Create user:

```powershell
net user alerttest P@ssw0rd123 /add
```

Delete user:

```powershell
net user alerttest /delete
```

Expected Windows Security Event ID:

```text
4720
```

---

## 5. Administrator Group Change Test

Create user:

```powershell
net user admintest P@ssw0rd123 /add
```

Add to Administrators group:

```powershell
net localgroup administrators admintest /add
```

Delete user:

```powershell
net user admintest /delete
```

Expected Windows Security Event ID:

```text
4732
```

---

## 6. SMB Failed Login / Brute Force Simulation from Kali

Create test user on Windows:

```powershell
net user smbtest CorrectP@ss123 /add
```

Allow SMB port if needed:

```powershell
New-NetFirewallRule -DisplayName "Allow SMB TCP 445" -Direction Inbound -Protocol TCP -LocalPort 445 -Action Allow
```

Check SMB listening:

```powershell
netstat -an | findstr 445
```

From Kali, check SMB port:

```bash
nmap -Pn -p 445 WINDOWS_IP
```

Run failed SMB login attempts from Kali:

```bash
smbclient -L //WINDOWS_IP -U smbtest%WrongPassword
```

Example used:

```bash
smbclient -L //10.150.218.127 -U smbtest%WrongPassword
```

Expected Kali output:

```text
session setup failed: NT_STATUS_LOGON_FAILURE
```

Run 3 to 5 times to simulate brute-force behavior.

Expected Windows Security Event ID:

```text
4625
```

Expected Logon Type:

```text
3
```

Cleanup:

```powershell
net user smbtest /delete
```

---

## 7. Suspicious Outbound Connection Test

On Kali, start listener:

```bash
nc -lvnp 4444
```

On Windows, connect to Kali:

```powershell
Test-NetConnection KALI_IP -Port 4444
```

Expected:

```text
TcpTestSucceeded : True
```

Expected Sysmon Event ID:

```text
3
```

---

## 8. Windows Security Log Cleared Test

Warning: This clears the Windows Security log. Use only in a lab VM.

```powershell
wevtutil cl Security
```

Expected Windows Security Event ID:

```text
1102
```

---

## 9. Gmail Phishing Collector

Python script path:

```text
C:\SOC-Lab\gmail_to_splunk.py
```

Log output path:

```text
C:\SOC-Lab\gmail_mail.log
```

Run collector:

```powershell
python C:\SOC-Lab\gmail_to_splunk.py
```

Manually add phishing test log line:

```powershell
Add-Content C:\SOC-Lab\gmail_mail.log 'time="2026-06-12T23:05:00Z" sender="security-alert@paypa1-login.com" recipient="karthik@example.com" subject="Urgent password reset required" urls="http://fake-login.example.com" attachments="invoice.html" verdict="suspicious"'
```

---

## 10. Telegram Bot Setup Commands

Delete webhook if `getUpdates` gives conflict:

```powershell
$BotToken = "YOUR_BOT_TOKEN"
Invoke-RestMethod "https://api.telegram.org/bot$BotToken/deleteWebhook"
```

Get updates after sending `hi` to the bot:

```powershell
$BotToken = "YOUR_BOT_TOKEN"
Invoke-RestMethod "https://api.telegram.org/bot$BotToken/getUpdates"
```

Get chat ID:

```powershell
$BotToken = "YOUR_BOT_TOKEN"
$updates = Invoke-RestMethod "https://api.telegram.org/bot$BotToken/getUpdates"
$updates.result[-1].message.chat.id
```

Test Telegram message:

```powershell
$BotToken = "YOUR_BOT_TOKEN"
$ChatId = "YOUR_CHAT_ID"

Invoke-RestMethod -Uri "https://api.telegram.org/bot$BotToken/sendMessage" -Method Post -Body @{
    chat_id = $ChatId
    text = "SOC Lab Telegram test alert"
}
```

Create Splunk script folder if missing:

```powershell
New-Item -ItemType Directory -Path "C:\Program Files\Splunk\bin\scripts" -Force
```

Copy Telegram script:

```powershell
Copy-Item "C:\SOC-Lab\splunk_telegram_alert.ps1" "C:\Program Files\Splunk\bin\scripts\splunk_telegram_alert.ps1" -Force
```

Create CMD wrapper:

```powershell
notepad "C:\Program Files\Splunk\bin\scripts\telegram_alert.cmd"
```

Wrapper content:

```cmd
@echo off
powershell.exe -ExecutionPolicy Bypass -File "C:\Program Files\Splunk\bin\scripts\splunk_telegram_alert.ps1"
```

Test wrapper:

```powershell
& "C:\Program Files\Splunk\bin\scripts\telegram_alert.cmd"
```

In Splunk alert action, use only:

```text
telegram_alert.cmd
```

Do not use the full path inside the Splunk script filename box.
