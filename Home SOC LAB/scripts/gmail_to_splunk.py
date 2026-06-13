"""
Gmail to Splunk Phishing Log Collector

Purpose:
- Connects to Gmail using IMAP.
- Reads latest unread emails.
- Extracts sender, recipient, subject, URLs, attachments, and suspicious keywords.
- Writes structured log lines to C:\SOC-Lab\gmail_mail.log.
- Splunk monitors the log file and triggers phishing alerts.

Before use:
- Enable IMAP in Gmail.
- Use a Google App Password.
- Do not upload real credentials to GitHub.
"""

import imaplib
import email
import re
from email.header import decode_header
from datetime import datetime, timezone
from pathlib import Path

GMAIL_USER = "YOUR_GMAIL_ADDRESS"
GMAIL_APP_PASSWORD = "YOUR_GMAIL_APP_PASSWORD"

LOG_FILE = Path(r"C:\SOC-Lab\gmail_mail.log")

SUSPICIOUS_KEYWORDS = [
    "urgent",
    "verify",
    "password",
    "account suspended",
    "login",
    "payment",
    "invoice",
    "security alert",
    "action required",
]

URL_REGEX = re.compile(r"https?://[^\s\"<>]+")


def decode_mime_words(value):
    if not value:
        return ""
    decoded_parts = decode_header(value)
    result = ""
    for part, encoding in decoded_parts:
        if isinstance(part, bytes):
            result += part.decode(encoding or "utf-8", errors="ignore")
        else:
            result += part
    return result


def clean(value):
    if value is None:
        return ""
    return str(value).replace('"', "'").replace("\r", " ").replace("\n", " ")


def get_body(msg):
    body = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition", ""))

            if content_type == "text/plain" and "attachment" not in disposition:
                payload = part.get_payload(decode=True)
                if payload:
                    body += payload.decode(errors="ignore")
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            body += payload.decode(errors="ignore")

    return body


def main():
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    print("[+] Connecting to Gmail IMAP...")
    mail = imaplib.IMAP4_SSL("imap.gmail.com")
    mail.login(GMAIL_USER, GMAIL_APP_PASSWORD)
    mail.select("inbox")

    print("[+] Searching unread emails...")
    status, data = mail.search(None, "UNSEEN")

    if status != "OK":
        print("[-] Failed to search mailbox")
        return

    email_ids = data[0].split()
    email_ids = email_ids[-5:]

    print(f"[+] Unread emails selected: {len(email_ids)}")

    for eid in email_ids:
        status, msg_data = mail.fetch(eid, "(RFC822)")
        if status != "OK":
            continue

        raw_msg = msg_data[0][1]
        msg = email.message_from_bytes(raw_msg)

        sender = decode_mime_words(msg.get("From", ""))
        recipient = decode_mime_words(msg.get("To", ""))
        subject = decode_mime_words(msg.get("Subject", ""))
        gmail_date = msg.get("Date", "")
        message_id = msg.get("Message-ID", "")

        body = get_body(msg)
        urls = URL_REGEX.findall(body)

        attachments = []
        if msg.is_multipart():
            for part in msg.walk():
                filename = part.get_filename()
                if filename:
                    attachments.append(decode_mime_words(filename))

        combined_text = f"{subject} {body}".lower()
        verdict = "suspicious" if any(keyword in combined_text for keyword in SUSPICIOUS_KEYWORDS) else "normal"

        log_line = (
            f'time="{datetime.now(timezone.utc).isoformat()}" '
            f'sender="{clean(sender)}" '
            f'recipient="{clean(recipient)}" '
            f'subject="{clean(subject)}" '
            f'urls="{clean(",".join(urls))}" '
            f'attachments="{clean(",".join(attachments))}" '
            f'gmail_date="{clean(gmail_date)}" '
            f'message_id="{clean(message_id)}" '
            f'verdict="{verdict}"'
        )

        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(log_line + "\n")

        print("[+] Logged:", subject)

    mail.logout()
    print("[+] Done")


if __name__ == "__main__":
    main()
