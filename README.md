# Phishing Email Analyser

A Blue Team triage tool that analyses suspicious emails and produces a structured threat report covering headers, links, attachments and social engineering indicators.

## What it analyses

**Email headers**
Extracts From, Reply-To, Return-Path and authentication results. Detects domain mismatches between the display address and actual sending domain, checks SPF and DKIM status, and counts mail hops for anomaly detection.

**Links**
Extracts every URL from the email body and flags domains with suspicious patterns — unusually long domains, excessive subdomains, IP addresses used as domains, and keywords like "verify" or "secure" in the path. Optionally checks each URL against VirusTotal.

**Attachments**
Lists all attachments and flags dangerous file types including .exe, .zip, .js, .ps1, .bat, .vbs and others commonly used to deliver malware.

**Social engineering keywords**
Scans the email body for phrases commonly used in phishing campaigns — urgency language, account suspension threats, prize notifications and credential requests.

**Threat scoring**
Combines all findings into a score from 0 to 100 and assigns a threat level of LOW, MEDIUM, HIGH or CRITICAL.

## Stack

- Python 3.11+ with Flask
- VirusTotal API for URL reputation checks
- Standard library email parser — no external parsing dependencies

## Getting started

```bash
git clone https://github.com/1ungaka/phishing-analyser
cd phishing-analyser
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

Create a `.env` file with your VirusTotal API key:

```
VIRUSTOTAL_API_KEY=your_key_here
```

Run the app:

```bash
python app.py
```

Open `http://127.0.0.1:5000` and upload any `.eml` file.

## Testing

A sample phishing email is included in the `samples/` folder to test the tool immediately after setup.

## Author

Lunga Ngaka — BSc Computer Science and Applied Mathematics, University of Fort Hare  
Blue Team | SOC Analyst | TryHackMe | Team DefendX
