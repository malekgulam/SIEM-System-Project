SIEM System Project

A Python and Flask-based Security Information and Event Management (SIEM) project that simulates a Security Operations Center (SOC) workflow. The platform ingests Linux authentication and Apache web logs, normalizes events into a common schema, executes JSON-configurable detection rules, stores alerts and supporting evidence, and provides a web dashboard for alert investigation, analyst workflow, and detection reporting.

Features

- Multi-source log ingestion
  - Linux authentication logs ("auth.log")
  - Apache access logs ("access.log")
- Event parsing and normalization into a common event model
- JSON-based detection rule repository
- Five MITRE ATT&CK mapped detection rules
- SQLite alert storage with duplicate alert prevention
- Alert-to-event relationship tracking
- Analyst workflow with alert status updates and investigation notes
- Search alerts by IP address, rule ID, rule name, or MITRE technique
- Detection metrics dashboard
- MITRE ATT&CK coverage dashboard
- Synthetic log generators for repeatable testing

---

SOC Workflow

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

The platform stores normalized events and generated alerts separately. Every alert retains its original raw log and maintains links to all events that contributed to the detection, allowing analysts to review supporting evidence during investigations.

---

Supported Log Sources

Linux Authentication Logs ("auth.log")

Supported event types include:

- SSH failed logins
- SSH successful logins
- sudo command execution
- su activity

Apache Access Logs ("access.log")

Supported event types include:

- HTTP requests
- HTTP response status codes
- Requested URLs
- Source IP addresses

---

Detection Rules

Rule ID| Rule Name| MITRE Technique| Tactic| Trigger
BF-001| SSH Brute Force| T1110| Credential Access| Five or more failed SSH logins from one IP within 60 seconds
OHL-001| Off-Hours Login| T1078| Defense Evasion| Successful login between 00:00 and 05:00
WS-001| Web Scanning Activity| T1595| Reconnaissance| Ten or more HTTP 404 responses from one IP within 30 seconds
PFS-001| Privilege Escalation via sudo| T1548| Privilege Escalation| sudo command execution
CSF-001| Credential Stuffing| T1110.004| Credential Access| Failed logins against three or more different usernames from one IP within 60 seconds

Detection rules are defined in "rules.json" and include metadata such as rule ID, rule type, severity, MITRE ATT&CK technique, and tactic. The detection engine dispatches rules based on their configured rule type.

---

Alert Investigation

Each alert contains:

- Rule information
- Severity
- MITRE ATT&CK technique and tactic
- Source IP
- Username (when applicable)
- Original raw log
- Linked normalized events
- Analyst notes
- Investigation status

Alert lifecycle:

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

---

Dashboard

The Flask dashboard provides:

Dashboard

- Alert overview
- Severity distribution
- Top source IPs
- MITRE tactic breakdown
- Alert filtering by:
  - Severity
  - Status
  - Tactic
  - Search query

Alert Details

- Alert metadata
- MITRE ATT&CK information
- Raw log
- Linked triggering events
- Status management
- Analyst notes

Metrics

Per-rule statistics including:

- Total alerts generated
- High-severity alerts
- Unreviewed alerts
- Closed alerts

MITRE Coverage

Displays implemented detections grouped by ATT&CK tactic together with alert volume.

Search

Search alerts by:

- Source IP
- Rule ID
- Rule name
- MITRE technique ID

---

Project Structure

SIEM-System-Project/
│
├── config.py
├── requirements.txt
│
├── Data/
│   └── Logs/
│       ├── auth.log
│       └── access.log
│
├── Generators/
│   ├── auth_log_generator.py
│   └── access_log_generator.py
│
├── Ingestion/
│   └── reader.py
│
├── Parsing/
│   ├── parser.py
│   └── normalization.py
│
├── Detection/
│   ├── engine.py
│   └── rules.json
│
├── Storage/
│   └── store.py
│
└── Dashboard/
    ├── app.py
    ├── static/
    └── templates/

---

Installation

git clone <your-repository-url>
cd SIEM-System-Project

python -m venv .venv

Activate the virtual environment.

Windows:

.venv\Scripts\activate

Linux/macOS:

source .venv/bin/activate

Install dependencies:

pip install -r requirements.txt

---

Usage

Generate sample logs:

python Generators/auth_log_generator.py
python Generators/access_log_generator.py

Start the dashboard:

python Dashboard/app.py

Open:

http://127.0.0.1:5000

On startup, the application:

- Reads log files
- Parses log events
- Normalizes events
- Executes detection rules
- Stores newly generated alerts
- Links alerts to contributing events

Duplicate alerts are automatically ignored.

---

Dashboard Routes

Route| Description
"/"| Dashboard with alerts, charts, and filters
"/alert/<id>"| Alert details, linked events, raw log, MITRE mapping, analyst notes
"/metrics"| Detection statistics by rule
"/coverage"| MITRE ATT&CK coverage
"/search"| Search alerts by IP, rule, or MITRE technique

---

Technologies

- Python 3.10+
- Flask
- SQLite
- Jinja2
- Chart.js

---

Screenshots

Dashboard

"Dashboard" (Screenshots/dashboard.png)

Alert Details

"Alert Details" (Screenshots/alert_details.png)

Metrics

"Metrics" (Screenshots/metrics.png)

MITRE Coverage

"Coverage" (Screenshots/coverage.png)

Search

"Search" (Screenshots/search.png)
