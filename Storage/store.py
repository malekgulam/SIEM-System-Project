import sqlite3
import sys
from pathlib import Path
from datetime import datetime

sys.path.append(str(Path(__file__).parent.parent))

from config import DB_PATH

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events(
            id INTEGER PRIMARY KEY,
            timestamp TEXT,
            source_ip TEXT,
            event_type TEXT,
            user TEXT,
            process TEXT,
            status TEXT,
            raw TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts(
            id INTEGER PRIMARY KEY,
            rule_id TEXT,
            rule_name TEXT,
            event_type TEXT,
            source_ip TEXT,
            user TEXT,
            severity TEXT,
            timestamp TEXT,
            status TEXT,
            notes TEXT,
            raw_event TEXT,
            technique_id TEXT,
            tactic TEXT,
            risk_score INTEGER,
            verdict TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alert_events(
            id INTEGER PRIMARY KEY,
            alert_id INTEGER,
            raw_event TEXT,
            timestamp TEXT,
            source_ip TEXT,
            FOREIGN KEY (alert_id) REFERENCES alerts(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cases(
            id INTEGER PRIMARY KEY,
            alert_id INTEGER,
            title TEXT,
            status TEXT,
            verdict TEXT,
            created_at TEXT,
            closed_at TEXT,
            FOREIGN KEY (alert_id) REFERENCES alerts(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS notes(
            id INTEGER PRIMARY KEY,
            case_id INTEGER,
            content TEXT,
            created_at TEXT,
            FOREIGN KEY (case_id) REFERENCES cases(id)
        )
    """)

    conn.commit()
    conn.close()

def save_events(events):
    conn = get_connection()
    cursor = conn.cursor()
    for event in events:
        if event.get("source_ip") is None:
            cursor.execute("""
                SELECT id FROM events
                WHERE timestamp = ? AND source_ip IS NULL AND event_type = ? AND raw = ?
            """, (
                event.get("timestamp"),
                event.get("event_type"),
                event.get("raw")
            ))
        else:
            cursor.execute("""
                SELECT id FROM events
                WHERE timestamp = ? AND source_ip = ? AND event_type = ? AND raw = ?
            """, (
                event.get("timestamp"),
                event.get("source_ip"),
                event.get("event_type"),
                event.get("raw")
            ))
        if not cursor.fetchone():
            cursor.execute("""
                INSERT INTO events (timestamp, source_ip, event_type, user, process, status, raw)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                event.get("timestamp"),
                event.get("source_ip"),
                event.get("event_type"),
                event.get("user"),
                event.get("process"),
                event.get("status"),
                event.get("raw")
            ))
    conn.commit()
    conn.close()

def load_events(limit=200):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    events = []
    for row in rows:
        events.append({
            "id": row[0],
            "timestamp": row[1],
            "source_ip": row[2],
            "event_type": row[3],
            "user": row[4],
            "process": row[5],
            "status": row[6],
            "raw": row[7]
        })
    return events

def load_event_by_id(event_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM events WHERE id = ?", (event_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return {
        "id": row[0],
        "timestamp": row[1],
        "source_ip": row[2],
        "event_type": row[3],
        "user": row[4],
        "process": row[5],
        "status": row[6],
        "raw": row[7]
    }

def save_alert(alert):
    conn = get_connection()
    cursor = conn.cursor()

    if alert["source_ip"] is None:
        cursor.execute("""
            SELECT id FROM alerts
            WHERE rule_id = ? AND source_ip IS NULL AND timestamp = ?
        """, (alert["rule_id"], alert["timestamp"]))
    else:
        cursor.execute("""
            SELECT id FROM alerts
            WHERE rule_id = ? AND source_ip = ? AND timestamp = ?
        """, (alert["rule_id"], alert["source_ip"], alert["timestamp"]))

    existing = cursor.fetchone()
    if existing:
        conn.close()
        return None

    cursor.execute("""
        INSERT INTO alerts (
            rule_id, rule_name, event_type, source_ip, user,
            severity, timestamp, status, notes,
            raw_event, technique_id, tactic, risk_score, verdict
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        alert["rule_id"],
        alert["rule_name"],
        alert["event_type"],
        alert["source_ip"],
        alert.get("user"),
        alert["severity"],
        alert["timestamp"],
        alert["status"],
        "",
        alert.get("raw_event"),
        alert.get("technique_id"),
        alert.get("tactic"),
        alert.get("risk_score", 0),
        None
    ))
    alert_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return alert_id

def save_alert_events(alert_id, events):
    conn = get_connection()
    cursor = conn.cursor()
    for event in events:
        cursor.execute("""
            INSERT INTO alert_events (alert_id, raw_event, timestamp, source_ip)
            VALUES (?, ?, ?, ?)
        """, (
            alert_id,
            event.get("raw"),
            event.get("timestamp"),
            event.get("source_ip")
        ))
    conn.commit()
    conn.close()

def load_events_by_alert_id(alert_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT raw_event, timestamp, source_ip
        FROM alert_events WHERE alert_id = ?
        ORDER BY id ASC
    """, (alert_id,))
    rows = cursor.fetchall()
    conn.close()
    events = []
    for row in rows:
        events.append({
            "raw_event": row[0],
            "timestamp": row[1],
            "source_ip": row[2]
        })
    return events

def load_all_events():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM events ORDER BY id ASC")
    rows = cursor.fetchall()
    conn.close()
    events = []
    for row in rows:
        events.append({
            "id": row[0],
            "timestamp": row[1],
            "source_ip": row[2],
            "event_type": row[3],
            "user": row[4],
            "process": row[5],
            "status": row[6],
            "raw": row[7]
        })
    return events

def load_alerts():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    alerts = []
    for row in rows:
        alerts.append({
            "id": row[0],
            "rule_id": row[1],
            "rule_name": row[2],
            "event_type": row[3],
            "source_ip": row[4],
            "user": row[5],
            "severity": row[6],
            "timestamp": row[7],
            "status": row[8],
            "notes": row[9],
            "raw_event": row[10],
            "technique_id": row[11],
            "tactic": row[12],
            "risk_score": row[13],
            "verdict": row[14]
        })
    return alerts

def load_alert_by_id(alert_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return {
        "id": row[0],
        "rule_id": row[1],
        "rule_name": row[2],
        "event_type": row[3],
        "source_ip": row[4],
        "user": row[5],
        "severity": row[6],
        "timestamp": row[7],
        "status": row[8],
        "notes": row[9],
        "raw_event": row[10],
        "technique_id": row[11],
        "tactic": row[12],
        "risk_score": row[13],
        "verdict": row[14]
    }

def update_alert(alert_id, new_status, new_notes):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE alerts SET status = ?, notes = ? WHERE id = ?
    """, (new_status, new_notes, alert_id))
    conn.commit()
    conn.close()

def update_verdict(alert_id, verdict):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE alerts SET verdict = ? WHERE id = ?
    """, (verdict, alert_id))
    conn.commit()
    conn.close()

def load_ip_alert_count(source_ip):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT COUNT(*) FROM alerts WHERE source_ip = ?
    """, (source_ip,))
    count = cursor.fetchone()[0]
    conn.close()
    return count

def open_case(alert_id, title):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id FROM cases WHERE alert_id = ?
    """, (alert_id,))
    if cursor.fetchone():
        conn.close()
        return None
    cursor.execute("""
        INSERT INTO cases (alert_id, title, status, verdict, created_at, closed_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        alert_id,
        title,
        "OPEN",
        None,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        None
    ))
    case_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return case_id

def load_cases():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM cases ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    cases = []
    for row in rows:
        cases.append({
            "id": row[0],
            "alert_id": row[1],
            "title": row[2],
            "status": row[3],
            "verdict": row[4],
            "created_at": row[5],
            "closed_at": row[6]
        })
    return cases

def load_case_by_id(case_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM cases WHERE id = ?", (case_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return {
        "id": row[0],
        "alert_id": row[1],
        "title": row[2],
        "status": row[3],
        "verdict": row[4],
        "created_at": row[5],
        "closed_at": row[6]
    }

def update_case(case_id, status, verdict):
    conn = get_connection()
    cursor = conn.cursor()
    closed_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S") if status == "CLOSED" else None
    cursor.execute("""
        UPDATE cases SET status = ?, verdict = ?, closed_at = ? WHERE id = ?
    """, (status, verdict, closed_at, case_id))
    conn.commit()
    conn.close()

def add_note(case_id, content):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO notes (case_id, content, created_at)
        VALUES (?, ?, ?)
    """, (
        case_id,
        content,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))
    conn.commit()
    conn.close()

def load_notes(case_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, content, created_at FROM notes
        WHERE case_id = ? ORDER BY id ASC
    """, (case_id,))
    rows = cursor.fetchall()
    conn.close()
    notes = []
    for row in rows:
        notes.append({
            "id": row[0],
            "content": row[1],
            "created_at": row[2]
        })
    return notes

def load_metrics():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT
            rule_id, rule_name, technique_id, tactic,
            COUNT(*) as total,
            SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) as high_count,
            SUM(CASE WHEN status = 'NEW' THEN 1 ELSE 0 END) as new_count,
            SUM(CASE WHEN status = 'CLOSED' THEN 1 ELSE 0 END) as closed_count,
            SUM(CASE WHEN verdict = 'TRUE POSITIVE' THEN 1 ELSE 0 END) as tp_count,
            SUM(CASE WHEN verdict = 'FALSE POSITIVE' THEN 1 ELSE 0 END) as fp_count,
            SUM(CASE WHEN verdict = 'BENIGN' THEN 1 ELSE 0 END) as benign_count
        FROM alerts
        GROUP BY rule_id
    """)
    rows = cursor.fetchall()
    conn.close()
    metrics = []
    for row in rows:
        total = row[4]
        tp = row[8]
        fp = row[9]
        verdicted = tp + fp + row[10]
        precision = round((tp / verdicted * 100), 1) if verdicted > 0 else None
        metrics.append({
            "rule_id": row[0],
            "rule_name": row[1],
            "technique_id": row[2],
            "tactic": row[3],
            "total": total,
            "high_count": row[5],
            "new_count": row[6],
            "closed_count": row[7],
            "tp_count": tp,
            "fp_count": fp,
            "benign_count": row[10],
            "precision": precision
        })
    return metrics

def reset_db():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM notes")
    cursor.execute("DELETE FROM cases")
    cursor.execute("DELETE FROM alert_events")
    cursor.execute("DELETE FROM alerts")
    cursor.execute("DELETE FROM events")
    conn.commit()
    conn.close()