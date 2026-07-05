SIEM System Project

A Python-based Security Information and Event Management (SIEM) platform built with Python and Flask that simulates a Security Operations Center (SOC) workflow. The platform ingests Linux authentication and Apache access logs, normalizes events into a common schema, executes MITRE ATT&CK–mapped detection rules, stores alerts and supporting evidence, and provides a web dashboard for alert investigation, metrics, and analyst workflows.

Table of Contents

- Overview
- Screenshots
- Features
- Architecture
- Supported Log Sources
- Detection Rules
- Dashboard
- Project Structure
- Installation
- Usage
- Dashboard Routes
- Technologies

Overview

The platform simulates a simplified SOC pipeline:

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

Alerts are linked to the normalized events that triggered them, allowing analysts to investigate detections using both parsed event data and the original raw log entries.

Screenshots

Place screenshots near the top so visitors immediately understand what the project looks like.

Dashboard

![Dashboard](Screenshots/dashboard.png)

Alert Details

![Alert Details](Screenshots/alert_details.png)

Detection Metrics

![Metrics](Screenshots/metrics.png)

MITRE Coverage

![Coverage](Screenshots/coverage.png)

Search

![Search](Screenshots/search.png)

Features

Log Processing

- Linux authentication log ingestion
- Apache access log ingestion
- Event parsing
- Event normalization
- Synthetic log generation

Detection Engine

- JSON-based rule repository
- MITRE ATT&CK mapped detections
- Configurable detection engine
- Duplicate alert prevention
- Alert-to-event relationship tracking

Investigation

- Alert lifecycle management
- Analyst notes
- Linked triggering events
- Raw log evidence
- Search by IP, rule, or MITRE technique

Reporting

- Detection metrics
- MITRE ATT&CK coverage
- Severity statistics
- Tactic distribution
- Dashboard visualizations

Architecture

The application consists of independent modules for ingestion, parsing, detection, storage, and visualization.

Generators
      │
      ▼
Ingestion
      │
      ▼
Parsing
      │
      ▼
Normalization
      │
      ▼
Detection Engine
      │
      ▼
SQLite
      │
      ▼
Flask Dashboard

Supported Log Sources

Linux Authentication Logs

- SSH failed logins
- SSH successful logins
- sudo execution
- su activity

Apache Access Logs

- HTTP requests
- Status codes
- Requested URLs
- Source IP addresses

Detection Rules

(Keep your existing detection table here.)

Dashboard

Main Dashboard

- Alert overview
- Severity distribution
- Top source IPs
- MITRE tactic distribution
- Alert filtering

Alert Investigation

- Alert metadata
- Linked events
- Raw log
- MITRE ATT&CK information
- Analyst notes
- Status updates

Detection Metrics

- Total alerts per rule
- High-severity alerts
- Closed alerts
- Unreviewed alerts

MITRE Coverage

Displays implemented detections grouped by ATT&CK tactic.

Search

Search alerts using:

- IP address
- Rule ID
- Rule name
- MITRE technique

Project Structure

(Keep your existing folder tree.)

Installation

(Keep your existing installation instructions.)

Usage

(Keep your existing usage instructions.)

Dashboard Routes

(Keep your existing route table.)

Technologies

- Python 3.10+
- Flask
- SQLite
- Jinja2
- Chart.js