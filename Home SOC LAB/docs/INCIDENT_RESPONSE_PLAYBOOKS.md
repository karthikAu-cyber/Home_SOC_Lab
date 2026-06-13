# Incident Response Playbooks

## 1. Suspicious Encoded PowerShell

Severity: High

Triage steps:

```text
1. Review the PowerShell command line.
2. Decode Base64 if EncodedCommand is present.
3. Check parent process.
4. Check user account and host.
5. Look for network connections around the same time.
6. If malicious, isolate host and preserve logs.
```

## 2. Multiple Failed Logins / SMB Brute Force

Severity: Medium

Triage steps:

```text
1. Check source IP.
2. Check targeted account.
3. Count failed attempts.
4. Check if a successful login occurred after failures.
5. Check whether source IP is expected.
6. If unauthorized, block source IP and reset account password.
```

## 3. Real Email Phishing Detected

Severity: High

Triage steps:

```text
1. Review sender address and display name.
2. Review subject and urgency language.
3. Review URLs and attachments.
4. Confirm if user clicked link or opened attachment.
5. Remove email and block sender/domain if malicious.
```

## 4. Admin Group Change

Severity: High

Triage steps:

```text
1. Identify account that performed the change.
2. Identify user added to group.
3. Confirm whether change was authorized.
4. Check recent logons for both accounts.
5. Remove unauthorized admin membership.
```

## 5. Security Log Cleared

Severity: Critical

Triage steps:

```text
1. Identify account that cleared the logs.
2. Check recent admin activity.
3. Review Sysmon logs for activity before clearing.
4. Preserve remaining logs.
5. Treat as possible anti-forensics if unauthorized.
```

## 6. Suspicious Outbound Connection

Severity: High

Triage steps:

```text
1. Review destination IP and port.
2. Identify process responsible for the connection.
3. Check whether the destination is expected.
4. Review related process and PowerShell events.
5. If unauthorized, isolate host and block destination.
```
