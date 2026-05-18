import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "alerts.db"

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
               event_type TEXT,
               source_ip TEXT,
               severity TEXT,
               timestamp TEXT,
               status TEXT,
               notes TEXT
               )
            """)
    conn.commit()
    conn.close()

def save_alert(alert):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
                SELECT * FROM alerts WHERE timestamp = ?
            """, (alert["timestamp"],))
    existing_alerts = cursor.fetchall()
    if not existing_alerts:
        cursor.execute("""
                INSERT INTO alerts (rule_id, event_type, source_ip, severity, timestamp, status, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (alert["rule_id"], alert["event_type"], alert["source_ip"], alert["severity"], alert["timestamp"], alert["status"], ""))
        conn.commit()

    else:
        pass
    conn.close()
def load_alerts():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
                SELECT * FROM alerts 
            """)
    rows = cursor.fetchall()
    alerts = []
    for row in rows:
        row_dict = {
            "id" : row[0],
            "rule_id" : row[1],
            "event_type" : row[2],
            "source_ip" : row[3],
            "severity" : row[4],
            "timestamp" : row[5],
            "status" : row[6],
            "notes" : row[7]
        }
        alerts.append(row_dict)
    conn.close()
    conn.close()
    return alerts

def update_alert(alert_id,new_status,new_notes):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
                UPDATE alerts SET status = ?, notes = ? WHERE id = ?
            """,(new_status,new_notes,alert_id))
    conn.commit()
    conn.close()

