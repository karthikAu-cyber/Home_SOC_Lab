$BotToken = "YOUR_BOT_TOKEN"
$ChatId = "YOUR_CHAT_ID"

$AlertName = $env:SPLUNK_ARG_4
$ResultCount = $env:SPLUNK_ARG_1
$ResultsFile = $env:SPLUNK_ARG_8

if ([string]::IsNullOrWhiteSpace($AlertName)) {
    $AlertName = "Splunk SOC Alert"
}

$Details = ""

if (-not [string]::IsNullOrWhiteSpace($ResultsFile) -and (Test-Path $ResultsFile)) {
    try {
        $csv = Import-Csv $ResultsFile
        if ($csv.Count -gt 0) {
            $first = $csv[0]

            $Details = @"

Host: $($first.host)
Account: $($first.Account_Name)
Source IP: $($first.Source_Network_Address)
Failed Count: $($first.count)
First Seen: $($first.firstTime)
Last Seen: $($first.lastTime)
Sender: $($first.sender)
Subject: $($first.subject)
Phishing Score: $($first.phishing_score)
"@
        }
    }
    catch {
        $Details = "`nDetails: Unable to parse Splunk result file."
    }
}

$Message = @"
🚨 Splunk SOC Alert Triggered

Alert: $AlertName
Result Count: $ResultCount
$Details

Open Splunk:
http://localhost:8000
"@

Invoke-RestMethod -Uri "https://api.telegram.org/bot$BotToken/sendMessage" -Method Post -Body @{
    chat_id = $ChatId
    text = $Message
}
