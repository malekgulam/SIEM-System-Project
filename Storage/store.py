import sqlite3
import sys
from pathlib import Path

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
            tactic TEXT
        )
    """)
    conn.commit()
    conn.close()

def save_alert(alert):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id FROM alerts
        WHERE rule_id = ? AND source_ip = ? AND timestamp = ?
    """, (alert["rule_id"], alert["source_ip"], alert["timestamp"]))

    if not cursor.fetchone():
        cursor.execute("""
            INSERT INTO alerts (
                rule_id, rule_name, event_type, source_ip, user,
                severity, timestamp, status, notes,
                raw_event, technique_id, tactic
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            alert.get("tactic")
        ))
        conn.commit()
    conn.close()

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
            "tactic": row[12]
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
        "tactic": row[12]
    }

def update_alert(alert_id, new_status, new_notes):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE alerts SET status = ?, notes = ? WHERE id = ?
    """, (new_status, new_notes, alert_id))
    conn.commit()
    conn.close()

def load_metrics():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT rule_id, rule_name, technique_id, tactic, COUNT(*) as total,
        SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) as high_count,
        SUM(CASE WHEN status = 'NEW' THEN 1 ELSE 0 END) as new_count,
        SUM(CASE WHEN status = 'CLOSED' THEN 1 ELSE 0 END) as closed_count
        FROM alerts
        GROUP BY rule_id
    """)
    rows = cursor.fetchall()
    conn.close()

    metrics = []
    for row in rows:
        metrics.append({
            "rule_id": row[0],
            "rule_name": row[1],
            "technique_id": row[2],
            "tactic": row[3],
            "total": row[4],
            "high_count": row[5],
            "new_count": row[6],
            "closed_count": row[7]
        })
    return metrics