# SIEM System Project

A Python and Flask-based **Security Information and Event Management (SIEM)** platform that simulates a Security Operations Center (SOC) workflow. The platform ingests Linux authentication and Apache access logs, normalizes them into a unified event model, executes MITRE ATT&CK-mapped detection rules, prioritizes alerts using risk scoring, and provides a web interface for event investigation, alert triage, case management, detection validation, and SOC reporting.

The project is designed to demonstrate the core responsibilities of a SOC analyst and detection engineer, from log ingestion and detection development to investigation, analyst workflow, and reporting.

---

# Table of Contents

- [Highlights](#highlights)
- [Architecture](#architecture)
- [Screenshots](#screenshots)
- [Features](#features)
- [Supported Log Sources](#supported-log-sources)
- [Detection Rules](#detection-rules)
- [Risk Scoring](#risk-scoring)
- [Project Structure](#project-structure)
- [Database Schema](#database-schema)
- [Installation](#installation)
- [Usage](#usage)
- [Dashboard Routes](#dashboard-routes)
- [Alert Workflow](#alert-workflow)
- [Case Workflow](#case-workflow)
- [Technology Stack](#technology-stack)

---

# Highlights

- End-to-end SOC workflow from log ingestion to investigation
- Linux authentication and Apache access log ingestion
- Event normalization into a unified event model
- Five MITRE ATT&CK-mapped detection rules
- Alert risk scoring based on multiple investigation factors
- Event Browser for investigating normalized events independently of alerts
- Alert-to-event relationship tracking
- Analyst investigation workflow with status management and verdicts
- Case management with investigation notes
- Detection Rule Simulator using the same production detection pipeline
- MITRE ATT&CK Navigator layer export
- Detection metrics including True Positive, False Positive, and rule precision
- AI-assisted investigation summaries
- Flask dashboard with interactive charts and search
- SQLite storage with duplicate prevention

---

# Architecture

The platform processes security telemetry through a multi-stage SOC pipeline.

![Architecture](architecture/siem-architecture.png)

---

Every normalized event is stored independently before detection runs. Detection rules generate alerts which maintain references to all contributing events while preserving the original raw log entry as investigation evidence.

---

## Screenshots

### Dashboard

The main SOC dashboard showing alert overview, risk scoring, charts, and recent alerts after processing a fresh dataset.

![Dashboard](Screenshots/dashboard.png)

---

### Investigation Workflow

| Events Browser | Alert Investigation |
|----------------|---------------------|
| ![Events](Screenshots/events.png) | ![Alert Details](Screenshots/alert_details.png) |

| Cases | Case Details |
|--------|--------------|
| ![Cases](Screenshots/cases.png) | ![Case Details](Screenshots/case_details.png) |

---

### Detection & Reporting

| Detection Metrics | MITRE ATT&CK Coverage |
|-------------------|-----------------------|
| ![Metrics](Screenshots/metrics.png) | ![Coverage](Screenshots/coverage.png) |

---

### Search

Search results for MITRE ATT&CK Technique **T1110**.

![Search](Screenshots/search.png)

---

# Features

## Log Processing

- Read Linux authentication logs (`auth.log`)
- Read Apache access logs (`access.log`)
- Parse raw logs into structured events
- Normalize different log sources into a unified event model
- Store normalized events independently of detections
- Generate synthetic log data for repeatable testing

## Detection Engine

- JSON-based rule repository
- Centralized rule dispatcher
- Five MITRE ATT&CK-mapped detection rules
- Duplicate alert prevention
- Alert-to-event relationship tracking
- Raw log preservation for every alert
- Detection metadata including Rule ID, Severity, Technique, and Tactic

## Risk Scoring

Each generated alert receives a risk score between **0 and 100**.

Risk scoring considers multiple factors including:

- Detection severity
- Off-hours activity
- Privileged account involvement
- Historical alert activity from the same source IP

The calculated score is used throughout the dashboard to help prioritize investigations.

## Event Investigation

- Dedicated Event Browser
- Event detail pages
- Raw event inspection
- Event type filtering
- Search normalized events
- Pivot directly from an event to related alerts using IP address or username

## Alert Investigation

- Alert status workflow
- Analyst investigation notes
- Verdict assignment
- Raw log evidence
- Linked triggering events
- Visual risk scoring
- MITRE ATT&CK mapping
- AI-assisted investigation summaries

## Case Management

- Create investigation cases directly from alerts
- One case per alert
- Timestamped investigation notes
- Independent case status tracking
- Investigation verdicts
- Automatic case closure timestamps
- Linked alert context

## Detection Validation

- Detection Rule Simulator
- Executes the same parsing, normalization, and detection pipeline used by the application
- Rule-specific testing
- Match and no-match validation
- Example log lines for every rule
- Risk score preview

## Reporting & Analytics

- Alert overview dashboard
- Rule performance dashboard
- Detection metrics
- True Positive tracking
- False Positive tracking
- Rule precision calculations
- MITRE ATT&CK coverage dashboard
- ATT&CK Navigator layer export

## Search

Search alerts by:

- Source IP
- Username
- Rule ID
- Rule Name
- MITRE ATT&CK Technique

## AI Investigation Assistant

Generate investigation guidance directly from an alert.

The assistant uses alert context, detection metadata, and supporting evidence to generate investigation summaries and recommended analyst actions without modifying alert data.

---

# Supported Log Sources

## Linux Authentication Logs (`auth.log`)

Supported event types include:

- Failed SSH logins
- Successful SSH logins
- Invalid user attempts
- sudo command execution
- su activity

## Apache Access Logs (`access.log`)

Supported event types include:

- HTTP requests
- Status codes
- Requested URLs
- Source IP addresses
- Web scanning activity

---

# Detection Rules

| Rule ID | Rule Name | MITRE Technique | ATT&CK Tactic | Trigger |
|---------|-----------|-----------------|---------------|---------|
| BF-001 | SSH Brute Force | T1110 | Credential Access | Five or more failed SSH logins from one IP within 60 seconds |
| OHL-001 | Off-Hours Login | T1078 | Defense Evasion | Successful login between 00:00 and 05:00 |
| WS-001 | Web Scanning Activity | T1595 | Reconnaissance | Ten or more HTTP 404 responses from one IP within 30 seconds |
| PFS-001 | Privilege Escalation via sudo | T1548 | Privilege Escalation | sudo command execution |
| CSF-001 | Credential Stuffing | T1110.004 | Credential Access | Failed logins against three or more different usernames from one IP within 60 seconds |

Detection rules are stored in `Detection/rules.json` and include metadata such as severity, rule type, MITRE ATT&CK technique, and ATT&CK tactic.

---

# Risk Scoring

Every generated alert receives a calculated **Risk Score (0–100)**.

The score is derived from multiple investigation factors rather than a fixed severity level, including:

- Alert severity
- Off-hours activity
- Privileged account involvement
- Historical alert frequency from the same source IP

Risk scores are displayed throughout the dashboard using both numeric values and visual indicators to assist alert prioritization.

---

# Project Structure

```text
SIEM-System-Project/
├── architecture/
├── Dashboard/
├── Data/
├── Detection/
├── Generators/
├── Ingestion/
├── Parsing/
├── screenshots/
├── Storage/
├── config.py
├── requirements.txt
├── README.md
└── .gitignore
```
# Database Schema

The platform stores normalized events, alerts, investigations, and supporting evidence in SQLite.

| Table | Description |
|------|-------------|
| `events` | Stores every normalized event generated during log processing |
| `alerts` | Detection results including severity, risk score, status, verdict, and MITRE ATT&CK mapping |
| `alert_events` | Maps alerts to the events that triggered them |
| `cases` | Investigation cases created from alerts |
| `notes` | Timestamped analyst investigation notes |

This schema separates telemetry from detections, allowing analysts to investigate raw events even when no alert is generated.

---

# Installation

Clone the repository.

```bash
git clone <your-repository-url>
cd SIEM-System-Project
```

Create a virtual environment.

```bash
python -m venv .venv
```

Activate the environment.

**Windows**

```bash
.venv\Scripts\activate
```

**Linux / macOS**

```bash
source .venv/bin/activate
```

Install dependencies.

```bash
pip install -r requirements.txt
```

---

# Usage

## 1. Generate Sample Logs

```bash
python Generators/auth_log_generator.py
python Generators/access_log_generator.py
```

The generators create realistic authentication and web activity containing both normal and suspicious events for repeatable testing.

---

## 2. Start the Dashboard

```bash
python Dashboard/app.py
```

---

## 3. Open the Application

```
http://127.0.0.1:5000
```

When the application starts it automatically:

- Reads configured log files
- Parses raw log entries
- Normalizes events
- Stores normalized events
- Executes all enabled detection rules
- Calculates alert risk scores
- Stores alerts and alert-to-event relationships
- Prevents duplicate alerts

---

## Detection Rule Simulator

The Detection Rule Simulator allows individual log lines to be tested without generating a full dataset.

The simulator executes the same:

- Ingestion
- Parsing
- Normalization
- Detection

pipeline used by the application, making it useful for validating detection rules and demonstrating rule behaviour.

---

## Event Investigation

The Event Browser allows analysts to investigate normalized events independently of generated alerts.

From an event page analysts can:

- Inspect normalized fields
- View the original raw log
- Filter by event type
- Pivot directly to related alerts using source IP or username

---

## Alert Investigation

Each alert includes:

- Severity
- Risk score
- Status
- Verdict
- MITRE ATT&CK mapping
- Raw log evidence
- Linked triggering events
- Analyst notes
- AI investigation assistance

Alerts may also be converted into investigation cases.

---

## Case Management

Cases provide a dedicated investigation workflow.

Each case includes:

- Linked alert context
- Investigation status
- Verdict
- Timestamped investigation notes
- Automatic closure timestamp
- Original evidence from the triggering alert

Only one case can exist for each alert.

---

## ATT&CK Navigator Export

The Coverage page can export the project's MITRE ATT&CK coverage as a valid **ATT&CK Navigator Layer**.

The exported JSON can be imported directly into MITRE ATT&CK Navigator to visualize implemented detection coverage.

---

# Dashboard Routes

| Route | Description |
|------|-------------|
| `/` | Security dashboard showing alert overview, risk metrics, charts, and recent alerts |
| `/alert/<id>` | Alert investigation including evidence, linked events, risk score, verdict, and analyst actions |
| `/events` | Browse normalized events |
| `/events/<id>` | View a single normalized event with pivot links |
| `/cases` | Investigation case overview |
| `/cases/<id>` | Case details, investigation notes, verdict, and linked alert |
| `/metrics` | Detection performance dashboard including TP, FP, and precision metrics |
| `/coverage` | MITRE ATT&CK coverage dashboard and Navigator export |
| `/search` | Search alerts by IP, username, rule ID, rule name, or ATT&CK technique |
| `/simulator` | Detection Rule Simulator |
| `/navigator/export` | Export ATT&CK Navigator layer |
| `/reset` | Reset the investigation database |

---

# Alert Workflow

Every generated alert follows the investigation lifecycle below.

```text
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

During investigation analysts can:

- Review supporting evidence
- Inspect linked events
- Record investigation notes
- Assign a verdict
- Open an investigation case
- Request AI investigation guidance

---

# Case Workflow

Cases extend the alert investigation process by tracking the overall investigation.

```text
Alert
   │
   ▼
Open Case
   │
   ▼
Investigation Notes
   │
   ▼
Verdict
   │
   ▼
Case Closed
```

Each case maintains its own status while remaining linked to the originating alert.

---

# Technology Stack

## Backend

- Python 3.10+
- Flask
- SQLite3

## Frontend

- HTML5
- CSS3
- JavaScript
- Chart.js
- Jinja2

## Security Frameworks

- MITRE ATT&CK
- MITRE ATT&CK Navigator

## Project Components

- JSON Rule Repository
- Detection Engine
- Event Normalization
- Risk Scoring
- Case Management
- Detection Rule Simulator
- AI Investigation Assistant

---