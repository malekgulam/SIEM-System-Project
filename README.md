# SIEM System Project

A Python and Flask project that simulates a basic Security Operations Center (SOC) workflow.
The system reads log files, detects suspicious activity using rules, and shows alerts in a web dashboard.

## What This Project Does

Raw logs go through a pipeline:

Logs → Ingest → Parse → Normalize → Detect → Alert → Investigate

Two log sources are supported:
- Linux authentication logs (`auth.log`) — SSH logins, sudo commands, su activity
- Apache access logs (`access.log`) — web requests, status codes, endpoints

The detection engine reads rules from a JSON file and runs the matching detector automatically.
Each alert stores the raw log line that triggered it, so you can trace every alert back to its source.

## Detection Rules

| Rule ID | Name | MITRE Technique | Tactic | Trigger |
|---------|------|----------------|--------|---------|
| BF-001 | SSH Brute Force | T1110 | Credential Access | 5+ failed logins from same IP in 60 seconds |
| OHL-001 | Off-Hours Login | T1078 | Defense Evasion | Successful login between 00:00 and 05:00 |
| WS-001 | Web Scanning Activity | T1595 | Reconnaissance | 10+ 404 responses from same IP in 30 seconds |
| PFS-001 | Privilege Escalation via Sudo | T1548 | Privilege Escalation | Any sudo command execution detected |
| CSF-001 | Credential Stuffing | T1110.004 | Credential Access | 3+ different usernames failed from same IP in 60 seconds |

## Project Structure

SIEM-System-Project/
├── config.py                        # All paths in one place
├── requirements.txt
├── Data/Logs/
│   ├── auth.log
│   └── access.log
├── Generators/
│   ├── auth_log_generator.py        # Generates realistic auth log events
│   └── access_log_generator.py      # Generates realistic web access log events
├── Ingestion/
│   └── reader.py                    # Reads log files from disk
├── Parsing/
│   ├── parser.py                    # Extracts fields from raw log lines
│   └── normalization.py             # Converts parsed fields into unified event format
├── Detection/
│   ├── engine.py                    # Runs all rules against normalized events
│   └── rules.json                   # Detection rules with MITRE mappings
├── Storage/
│   └── store.py                     # SQLite database operations
└── Dashboard/
├── app.py                       # Flask routes
├── static/
│   ├── style.css
│   └── script.js
└── templates/
├── layout.html
├── index.html               # Main dashboard
├── alert_details.html       # Single alert view with raw event
├── metrics.html             # Per-rule detection metrics
├── coverage.html            # MITRE tactic coverage summary
└── search.html              # Search alerts by IP, rule, technique

## Setup

```bash
git clone <your-repo-url>
cd SIEM-System-Project

python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux / Mac
source .venv/bin/activate

pip install -r requirements.txt

Usage
Step 1 — Generate logs:
python Generators/auth_log_generator.py
python Generators/access_log_generator.py

Step 2 — Start the dashboard:
python Dashboard/app.py

Step 3 — Open in browser:
http://127.0.0.1:5000

The pipeline runs automatically when you open the dashboard.
Alerts are saved to SQLite and will not duplicate on refresh.

Dashboard Pages
Route
Description
/
Main dashboard — alert table, charts, filters
/alert/<id>
Alert detail — MITRE info, raw event, analyst actions
/metrics
Per-rule alert counts and status breakdown
/coverage
MITRE tactic and technique coverage summary
/search
Search alerts by IP, rule ID, rule name, or technique
Alert Lifecycle
Each alert moves through these statuses:
NEW → INVESTIGATING → ESCALATED → CLOSED
You can update the status and add analyst notes from the alert detail page.
Tech Stack
Python 3.10+
Flask
SQLite3
Jinja2
Chart.js

## Screenshots

### Dashboard


![Dashboard](screenshots/dashboard.png)



### Alert Details


![Alert Details](screenshots/alert_details.png)



### Metrics


![Metrics](screenshots/metrics.png)



### Coverage


![Coverage](screenshots/coverage.png)



### Search


![Search](Screenshots/search.png)


