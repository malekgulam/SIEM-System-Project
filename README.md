# SIEM System Project

A Python and Flask-based **Security Information and Event Management
(SIEM)** platform that simulates a Security Operations Center (SOC)
workflow. The platform ingests Linux authentication and Apache access
logs, normalizes events into a common event format, executes JSON-based
detection rules, stores alerts in SQLite, and provides a web dashboard
for alert investigation, analyst workflow, detection metrics, and MITRE
ATT&CK coverage.

## Table of Contents

-   [Features](#features)
-   [Architecture](#architecture)
-   [Screenshots](#screenshots)
-   [Supported Log Sources](#supported-log-sources)
-   [Detection Rules](#detection-rules)
-   [Project Structure](#project-structure)
-   [Installation](#installation)
-   [Usage](#usage)
-   [Dashboard Routes](#dashboard-routes)
-   [Alert Workflow](#alert-workflow)
-   [Technologies](#technologies)

------------------------------------------------------------------------

## Features

### Log Processing

-   Read Linux authentication logs (`auth.log`)
-   Read Apache access logs (`access.log`)
-   Parse and normalize logs into a common event format
-   Generate synthetic log data for repeatable testing

### Detection Engine

-   JSON-based detection rule repository
-   Five MITRE ATT&CK-mapped detection rules
-   Duplicate alert prevention
-   Alert-to-event relationship tracking
-   SQLite alert storage

### Investigation

-   Alert status management
-   Analyst investigation notes
-   Raw log evidence
-   Linked triggering events
-   Search alerts by IP address, Rule ID, Rule Name, or MITRE ATT&CK
    Technique

### Dashboard & Reporting

-   Alert overview dashboard
-   Detection metrics
-   MITRE ATT&CK coverage
-   Severity distribution
-   Top source IPs
-   MITRE tactic distribution
-   Alert filtering and search

------------------------------------------------------------------------

## Architecture

The platform processes logs through a simplified SOC pipeline.

``` text
Logs
   │
   ▼
Ingest
   │
   ▼
Parse
   │
   ▼
Normalize
   │
   ▼
Detect
   │
   ▼
Generate Alert
   │
   ▼
Investigate
```

Normalized events and generated alerts are stored separately. Each alert
preserves the original raw log and maintains links to every event that
contributed to the detection.

------------------------------------------------------------------------

## Screenshots

### Dashboard

![Dashboard](Screenshots/dashboard.png)

### Alert Details

![Alert Details](Screenshots/alert_details.png)

### Detection Metrics

![Metrics](Screenshots/metrics.png)

### MITRE ATT&CK Coverage

![Coverage](Screenshots/coverage.png)

### Search

![Search](Screenshots/search.png)

------------------------------------------------------------------------

## Supported Log Sources

### Linux Authentication Logs (`auth.log`)

-   SSH failed logins
-   SSH successful logins
-   `sudo` command execution
-   `su` activity

### Apache Access Logs (`access.log`)

-   HTTP requests
-   HTTP response status codes
-   Requested URLs
-   Source IP addresses

------------------------------------------------------------------------

## Detection Rules

| Rule ID | Rule Name | MITRE Technique | Tactic | Trigger |
|---------|-----------|-----------------|--------|---------|
| BF-001 | SSH Brute Force | T1110 | Credential Access | Five or more failed SSH logins from one IP within 60 seconds |
| OHL-001 | Off-Hours Login | T1078 | Defense Evasion | Successful login between 00:00 and 05:00 |
| WS-001 | Web Scanning Activity | T1595 | Reconnaissance | Ten or more HTTP 404 responses from one IP within 30 seconds |
| PFS-001 | Privilege Escalation via sudo | T1548 | Privilege Escalation | Any `sudo` command execution |
| CSF-001 | Credential Stuffing | T1110.004 | Credential Access | Failed logins against three or more different usernames from one IP within 60 seconds |

Detection rules are defined in `Detection/rules.json` and include Rule ID, Rule Type, Severity, MITRE ATT&CK Technique, and Tactic metadata.

------------------------------------------------------------------------

## Project Structure

``` text
SIEM-System-Project/
├── config.py
├── requirements.txt
├── Data/
│   └── Logs/
│       ├── auth.log
│       └── access.log
├── Generators/
│   ├── auth_log_generator.py
│   └── access_log_generator.py
├── Ingestion/
│   └── reader.py
├── Parsing/
│   ├── parser.py
│   └── normalization.py
├── Detection/
│   ├── engine.py
│   └── rules.json
├── Storage/
│   └── store.py
└── Dashboard/
    ├── app.py
    ├── static/
    │   ├── style.css
    │   └── script.js
    └── templates/
        ├── layout.html
        ├── index.html
        ├── alert_details.html
        ├── metrics.html
        ├── coverage.html
        ├── search.html
        └── 404.html
```

------------------------------------------------------------------------

## Installation

``` bash
git clone <your-repository-url>
cd SIEM-System-Project

python -m venv .venv
```

Activate the virtual environment.

**Windows**

``` bash
.venv\Scripts\activate
```

**Linux/macOS**

``` bash
source .venv/bin/activate
```

Install dependencies.

``` bash
pip install -r requirements.txt
```

------------------------------------------------------------------------

## Usage

### 1. Generate Sample Logs

``` bash
python Generators/auth_log_generator.py
python Generators/access_log_generator.py
```

### 2. Start the Dashboard

``` bash
python Dashboard/app.py
```

### 3. Open the Application

`http://127.0.0.1:5000`

When the dashboard starts, the application automatically:

-   Reads log files
-   Parses log events
-   Normalizes events
-   Executes all detection rules
-   Stores newly generated alerts
-   Links alerts to the events that triggered them

Duplicate alerts are automatically ignored.

------------------------------------------------------------------------

## Dashboard Routes

| Route | Description |
|-------|-------------|
| `/` | Dashboard with alerts, charts, filters, and statistics |
| `/alert/<id>` | Alert details, linked events, raw log, MITRE mapping, status updates, and analyst notes |
| `/metrics` | Detection statistics for each rule |
| `/coverage` | MITRE ATT&CK tactic and technique coverage |
| `/search` | Search alerts by IP address, Rule ID, Rule Name, or MITRE Technique |

------------------------------------------------------------------------

## Alert Workflow

``` text
NEW
 │
 ▼
INVESTIGATING
 │
 ▼
ESCALATED
 │
 ▼
CLOSED
```

Analysts can update the alert status and investigation notes from the
Alert Details page.

------------------------------------------------------------------------

## Technologies

-   Python 3.10+
-   Flask
-   SQLite3
-   Jinja2
-   Chart.js
