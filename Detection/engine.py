import sys
from pathlib import Path
import json
from datetime import datetime

project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from Parsing.normalization import normalize_events

RULES_PATH = Path("C:/Users/msi-ninja/Documents/Projects/SIEM_System_Project/Detection/rules.json")

MONTHS = {"Jan":1, "Feb":2, "Mar":3, "Apr":4, "May":5, "Jun":6,
          "Jul":7, "Aug":8, "Sep":9, "Oct":10, "Nov":11, "Dec":12}

def parse_timestamp_auth(ts):
    parts = ts.split()
    month = MONTHS[parts[0]]
    day = int(parts[1])
    h, m, s = map(int, parts[2].split(":"))
    return datetime(2000, month, day, h, m, s)

def parse_timestamp_access(ts):
    parts = ts.split("/")
    month = MONTHS[parts[1]]
    day = int(parts[0])
    time_parts = parts[2].split(":")
    year = int(time_parts[0])
    time_values = time_parts[1],time_parts[2],time_parts[3]
    h,m,s = map(int,time_values)
    return datetime(year,month,day,h,m,s)


def detect_bruteforce(events, rule):
    threshold = rule["threshold"]
    window_sec = rule["time_window_seconds"]
    cooldown_sec = 300
    alerts = []

    failed_events = [e for e in events if e["event_type"] == rule["event_type"] and e["source_ip"]]
    if not failed_events:
        return alerts

    failed_events.sort(key=lambda e: (e["source_ip"], parse_timestamp_auth(e["timestamp"])))

    ip_events = {}
    for e in failed_events:
        ip_events.setdefault(e["source_ip"], []).append(e)

    ip_last_alert = {}

    for ip, ev_list in ip_events.items():
        times = [parse_timestamp_auth(e["timestamp"]) for e in ev_list]
        for i, start_time in enumerate(times):
            if ip in ip_last_alert:
                if (start_time - ip_last_alert[ip]).total_seconds() < cooldown_sec:
                    continue
            count = 1
            for j in range(i+1, len(times)):
                if (times[j] - start_time).total_seconds() <= window_sec:
                    count += 1
                else:
                    break
            if count >= threshold:
                alerts.append({
                    "rule_id": rule["rule_id"],
                    "event_type": "failed_login",
                    "source_ip": ip,
                    "severity": rule["severity"],
                    "timestamp": ev_list[i]["timestamp"],
                    "status": "NEW"
                })
                ip_last_alert[ip] = start_time
    return alerts

def detect_offhour(events,rule):
    time_condition = rule["time_condition"]
    alerts = []
    rule_parts = time_condition.split("-")
    rule_start = datetime.strptime(rule_parts[0],"%H:%M")
    rule_end = datetime.strptime(rule_parts[1], "%H:%M")

    start_minute = rule_start.hour * 60 + rule_start.minute
    end_minute = rule_end.hour * 60 + rule_end.minute
    successful_logins = [e for e in events if e["event_type"] == rule["event_type"]]

    if not successful_logins:
        return alerts
    for event in successful_logins:
        dt = parse_timestamp_auth(event["timestamp"])
        event_minute = dt.hour * 60 + dt.minute
        if start_minute <= event_minute <= end_minute:
            alerts.append({
                    "rule_id": rule["rule_id"],
                    "event_type": "successful_login",
                    "source_ip": event["source_ip"],
                    "severity": rule["severity"],
                    "timestamp": event["timestamp"],
                    "status": "NEW"
                })
    return alerts
        
def detect_webscan(events,rule):
    threshold = rule["threshold"]
    window_sec = rule["time_window_seconds"]
    cooldown_sec = 300
    alerts = []

    web_events = [e for e in events if e["event_type"] == rule["event_type"] and e["status"] == rule["status"]]
    if not web_events:
        return alerts
    
    ip_events = {}
    for e in web_events:
        ip_events.setdefault(e["source_ip"], []).append(e)
    
    ip_last_alert = {}

    for ip, ev_list in ip_events.items():
        times = [parse_timestamp_access(e["timestamp"]) for e in ev_list]

        for i, start_time in enumerate(times):
            if ip in ip_last_alert:
                if (start_time - ip_last_alert[ip]).total_seconds() < cooldown_sec:
                    continue
            count = 1
            for j in range(i+1, len(times)):
                if (times[j] - start_time).total_seconds() <= window_sec:
                    count += 1
                else:
                    break
            if count >= threshold:
                alerts.append({
                    "rule_id": rule["rule_id"],
                    "event_type": "web_request",
                    "source_ip": ip,
                    "severity": rule["severity"],
                    "timestamp": ev_list[i]["timestamp"],
                    "status": "NEW"
                })
                ip_last_alert[ip] = start_time
    
    return alerts
def detection_engine():
    try:
       rules = json.loads(RULES_PATH.read_text())
       events = normalize_events()
       alerts = []
       bruteforce_rule = next((r for r in rules if r["rule_id"] == "BF-001"), None)
       offhour_rule = next((r for r in rules if r["rule_id"] == "OHL-001"), None)
       webscan_rule = next((r for r in rules if r["rule_id"] == "WS-001"), None)
       alerts.extend(detect_bruteforce(events, bruteforce_rule) if bruteforce_rule else [])
       alerts.extend(detect_offhour(events, offhour_rule) if offhour_rule else [])
       alerts.extend(detect_webscan(events, webscan_rule) if webscan_rule else [])
       return alerts
    except Exception as e:
        print(f"Error : {e}")
