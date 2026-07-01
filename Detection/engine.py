import sys
from pathlib import Path
import json
from datetime import datetime

sys.path.append(str(Path(__file__).parent.parent))

from config import RULES_PATH
from Parsing.normalization import normalize_events

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}

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
    h, m, s = map(int, time_parts[1:4])
    return datetime(year, month, day, h, m, s)

def detect_bruteforce(events, rule):
    threshold = rule["threshold"]
    window_sec = rule["time_window_seconds"]
    cooldown_sec = 300
    alerts = []

    failed_events = [e for e in events if e["event_type"] == rule["event_type"] and e["source_ip"]]
    if not failed_events:
        return alerts

    ip_events = {}
    for e in failed_events:
        ip_events.setdefault(e["source_ip"], []).append(e)

    for ip, ev_list in ip_events.items():
        ev_list.sort(key=lambda e: parse_timestamp_auth(e["timestamp"]))
        times = [parse_timestamp_auth(e["timestamp"]) for e in ev_list]
        ip_last_alert = None

        for i, start_time in enumerate(times):
            if ip_last_alert and (start_time - ip_last_alert).total_seconds() < cooldown_sec:
                continue
            count = sum(
                1 for j in range(i + 1, len(times))
                if (times[j] - start_time).total_seconds() <= window_sec
            ) + 1

            if count >= threshold:
                alerts.append({
                    "rule_id": rule["rule_id"],
                    "rule_name": rule["name"],
                    "event_type": rule["event_type"],
                    "source_ip": ip,
                    "user": ev_list[i].get("user"),
                    "severity": rule["severity"],
                    "timestamp": ev_list[i]["timestamp"],
                    "status": "NEW",
                    "raw_event": ev_list[i]["raw"],
                    "technique_id": rule["technique_id"],
                    "tactic": rule["tactic"]
                })
                ip_last_alert = start_time
    return alerts

def detect_offhours(events, rule):
    time_condition = rule["time_condition"]
    alerts = []

    rule_parts = time_condition.split("-")
    rule_start = datetime.strptime(rule_parts[0], "%H:%M")
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
                "rule_name": rule["name"],
                "event_type": rule["event_type"],
                "source_ip": event["source_ip"],
                "user": event.get("user"),
                "severity": rule["severity"],
                "timestamp": event["timestamp"],
                "status": "NEW",
                "raw_event": event["raw"],
                "technique_id": rule["technique_id"],
                "tactic": rule["tactic"]
            })
    return alerts

def detect_webscan(events, rule):
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

    for ip, ev_list in ip_events.items():
        times = [parse_timestamp_access(e["timestamp"]) for e in ev_list]
        ip_last_alert = None

        for i, start_time in enumerate(times):
            if ip_last_alert and (start_time - ip_last_alert).total_seconds() < cooldown_sec:
                continue
            count = sum(
                1 for j in range(i + 1, len(times))
                if (times[j] - start_time).total_seconds() <= window_sec
            ) + 1

            if count >= threshold:
                alerts.append({
                    "rule_id": rule["rule_id"],
                    "rule_name": rule["name"],
                    "event_type": rule["event_type"],
                    "source_ip": ip,
                    "user": ev_list[i].get("user"),
                    "severity": rule["severity"],
                    "timestamp": ev_list[i]["timestamp"],
                    "status": "NEW",
                    "raw_event": ev_list[i]["raw"],
                    "technique_id": rule["technique_id"],
                    "tactic": rule["tactic"]
                })
                ip_last_alert = start_time
    return alerts

def detect_privesc(events, rule):
    alerts = []

    sudo_events = [e for e in events if e["event_type"] == rule["event_type"]]
    if not sudo_events:
        return alerts

    for event in sudo_events:
        alerts.append({
            "rule_id": rule["rule_id"],
            "rule_name": rule["name"],
            "event_type": rule["event_type"],
            "source_ip": event["source_ip"],
            "user": event.get("user"),
            "severity": rule["severity"],
            "timestamp": event["timestamp"],
            "status": "NEW",
            "raw_event": event["raw"],
            "technique_id": rule["technique_id"],
            "tactic": rule["tactic"]
        })
    return alerts

def detect_credstuffing(events, rule):
    threshold = rule["threshold"]
    window_sec = rule["time_window_seconds"]
    cooldown_sec = 300
    alerts = []

    failed_events = [
        e for e in events
        if e["event_type"] == rule["event_type"] and e["source_ip"] and e.get("user")
    ]
    if not failed_events:
        return alerts

    ip_events = {}
    for e in failed_events:
        ip_events.setdefault(e["source_ip"], []).append(e)

    for ip, ev_list in ip_events.items():
        ev_list.sort(key=lambda e: parse_timestamp_auth(e["timestamp"]))
        times = [parse_timestamp_auth(e["timestamp"]) for e in ev_list]
        ip_last_alert = None

        for i, start_time in enumerate(times):
            if ip_last_alert and (start_time - ip_last_alert).total_seconds() < cooldown_sec:
                continue

            window_events = [
                ev_list[j] for j in range(i, len(times))
                if (times[j] - start_time).total_seconds() <= window_sec
            ]
            unique_users = set(e["user"] for e in window_events if e.get("user"))

            if len(unique_users) >= threshold:
                alerts.append({
                    "rule_id": rule["rule_id"],
                    "rule_name": rule["name"],
                    "event_type": rule["event_type"],
                    "source_ip": ip,
                    "user": ", ".join(unique_users),
                    "severity": rule["severity"],
                    "timestamp": ev_list[i]["timestamp"],
                    "status": "NEW",
                    "raw_event": ev_list[i]["raw"],
                    "technique_id": rule["technique_id"],
                    "tactic": rule["tactic"]
                })
                ip_last_alert = start_time
    return alerts

RULE_DISPATCHER = {
    "bruteforce": detect_bruteforce,
    "offhours": detect_offhours,
    "webscan": detect_webscan,
    "privesc": detect_privesc,
    "credstuffing": detect_credstuffing
}

def detection_engine():
    try:
        rules = json.loads(RULES_PATH.read_text())
        events = normalize_events()
        alerts = []

        for rule in rules:
            rule_type = rule.get("rule_type")
            detector = RULE_DISPATCHER.get(rule_type)
            if detector:
                alerts.extend(detector(events, rule))
            else:
                print(f"No detector found for rule_type: {rule_type}")

        return alerts
    except Exception as e:
        print(f"Detection engine error: {e}")
        return []