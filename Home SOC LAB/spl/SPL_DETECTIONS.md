# Splunk SPL Detections

## 1. Suspicious Encoded PowerShell

```spl
index=sysmon earliest=-15m@m latest=now
| rex field=_raw "<EventID[^>]*>(?<EventID>\d+)</EventID>"
| search EventID=1
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]+)</Data>"
| search CommandLine="*-EncodedCommand*" OR CommandLine="*-enc*" OR CommandLine="*IEX*" OR CommandLine="*DownloadString*"
| table _time host Image ParentImage CommandLine
```

## 2. New Local User Created

```spl
index=wineventlog EventCode=4720 earliest=-15m@m latest=now
| table _time host Account_Name Target_Account_Name Message
```

## 3. User Added to Administrators Group

```spl
index=wineventlog EventCode=4732 earliest=-15m@m latest=now
| table _time host Account_Name Group_Name Member_Name Message
```

## 4. Multiple Failed Logins / Possible SMB Brute Force

```spl
index=wineventlog EventCode=4625 earliest=-15m@m latest=now
| fillnull value="unknown" Source_Network_Address
| stats count min(_time) as firstTime max(_time) as lastTime by Account_Name Source_Network_Address
| where count >= 3
| convert ctime(firstTime) ctime(lastTime)
```

## 5. Real Email Phishing Detection

```spl
index=email sourcetype=gmail_mail earliest=-15m@m latest=now
| rex "sender=\"(?<sender>[^\"]+)\""
| rex "recipient=\"(?<recipient>[^\"]+)\""
| rex "subject=\"(?<subject>[^\"]*)\""
| rex "urls=\"(?<urls>[^\"]*)\""
| rex "attachments=\"(?<attachments>[^\"]*)\""
| rex "verdict=\"(?<verdict>[^\"]+)\""
| eval sender_lower=lower(sender)
| eval subject_lower=lower(subject)
| eval urls_lower=lower(urls)
| eval attachments_lower=lower(attachments)
| eval phishing_score=0
| eval phishing_score=phishing_score + if(match(subject_lower,"urgent|verify|password reset|account suspended|action required|unusual sign.?in|confirm your account"),2,0)
| eval phishing_score=phishing_score + if(match(urls_lower,"bit\.ly|tinyurl|evil|fake|login|verify|security|account"),2,0)
| eval phishing_score=phishing_score + if(match(sender_lower,"micros0ft|paypa1|g00gle|faceb00k|security-alert|support"),2,0)
| eval phishing_score=phishing_score + if(match(attachments_lower,"\.html|\.htm|\.exe|\.scr|\.js|\.vbs|\.zip"),2,0)
| where phishing_score >= 2
| table _time sender recipient subject urls attachments verdict phishing_score
```

For stricter production-like testing, change:

```spl
| where phishing_score >= 2
```

to:

```spl
| where phishing_score >= 4
```

## 6. Suspicious Outbound Connection

```spl
index=sysmon earliest=-15m@m latest=now
| rex field=_raw "<EventID[^>]*>(?<EventID>\d+)</EventID>"
| search EventID=3
| rex field=_raw "<Data Name='SourceIp'>(?<SourceIp>[^<]+)</Data>"
| rex field=_raw "<Data Name='DestinationIp'>(?<DestinationIp>[^<]+)</Data>"
| rex field=_raw "<Data Name='DestinationPort'>(?<DestinationPort>[^<]+)</Data>"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| search DestinationPort="4444"
| table _time host SourceIp DestinationIp DestinationPort Image
```

## 7. Windows Security Log Cleared

```spl
index=wineventlog EventCode=1102 earliest=-15m@m latest=now
| table _time host Account_Name Message
| sort -_time
```

## 8. Unified SOC Detection Timeline Dashboard Panel

```spl
(
index=wineventlog earliest=-24h (EventCode=4625 OR EventCode=4720 OR EventCode=4732 OR EventCode=1102)
)
OR
(
index=sysmon earliest=-24h
)
OR
(
index=email sourcetype=gmail_mail earliest=-24h
)
| rex field=_raw "<EventID[^>]*>(?<SysmonEventID>\d+)</EventID>"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
| rex field=_raw "<Data Name='SourceIp'>(?<SourceIp>[^<]+)</Data>"
| rex field=_raw "<Data Name='DestinationIp'>(?<DestinationIp>[^<]+)</Data>"
| rex field=_raw "<Data Name='DestinationPort'>(?<DestinationPort>[^<]+)</Data>"
| rex "sender=\"(?<sender>[^\"]+)\""
| rex "recipient=\"(?<recipient>[^\"]+)\""
| rex "subject=\"(?<subject>[^\"]*)\""
| rex "urls=\"(?<urls>[^\"]*)\""
| rex "attachments=\"(?<attachments>[^\"]*)\""
| rex "verdict=\"(?<verdict>[^\"]+)\""
| eval Detection=case(
EventCode=4625, "Failed Login / Brute Force",
EventCode=4720, "New Local User Created",
EventCode=4732, "Admin Group Change",
EventCode=1102, "Security Log Cleared",
SysmonEventID=1 AND like(_raw,"%EncodedCommand%"), "Suspicious PowerShell",
SysmonEventID=3 AND DestinationPort="4444", "Suspicious Outbound Connection",
verdict="suspicious", "Phishing Email"
)
| where isnotnull(Detection)
| eval Severity=case(
Detection="Security Log Cleared", "Critical",
Detection="Phishing Email", "High",
Detection="Suspicious PowerShell", "High",
Detection="Suspicious Outbound Connection", "High",
Detection="Admin Group Change", "High",
Detection="Failed Login / Brute Force", "Medium",
Detection="New Local User Created", "Medium",
true(), "Low"
)
| eval Entity=coalesce(Account_Name, Target_Account_Name, sender, Image, SourceIp, host)
| eval Source=coalesce(Source_Network_Address, SourceIp, sender)
| eval Destination=coalesce(DestinationIp, recipient, host)
| eval Detail=coalesce(subject, CommandLine, Message)
| table _time Detection Severity host Entity Source Destination DestinationPort Detail
| sort -_time
```

## 9. SOC Detection Count by Type

```spl
(
index=wineventlog earliest=-24h (EventCode=4625 OR EventCode=4720 OR EventCode=4732 OR EventCode=1102)
)
OR
(
index=sysmon earliest=-24h
)
OR
(
index=email sourcetype=gmail_mail earliest=-24h
)
| rex field=_raw "<EventID[^>]*>(?<SysmonEventID>\d+)</EventID>"
| rex field=_raw "<Data Name='DestinationPort'>(?<DestinationPort>[^<]+)</Data>"
| rex "verdict=\"(?<verdict>[^\"]+)\""
| eval Detection=case(
EventCode=4625, "Failed Login / Brute Force",
EventCode=4720, "New Local User Created",
EventCode=4732, "Admin Group Change",
EventCode=1102, "Security Log Cleared",
SysmonEventID=1 AND like(_raw,"%EncodedCommand%"), "Suspicious PowerShell",
SysmonEventID=3 AND DestinationPort="4444", "Suspicious Outbound Connection",
verdict="suspicious", "Phishing Email"
)
| where isnotnull(Detection)
| stats count by Detection
| sort -count
```

## 10. All Triggered Splunk Alerts

```spl
index=_internal source="*scheduler.log*" savedsearch_name="SOC Alert*"
| table _time savedsearch_name status alert_actions result_count app user
| rename savedsearch_name as Alert_Name
| sort -_time
```
