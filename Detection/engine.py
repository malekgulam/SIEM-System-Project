import sys
from pathlib import Path
import json
from datetime import datetime

sys.path.append(str(Path(__file__).parent.parent))

from config import RULES_PATH
from Parsing.normalization import normalize_events
from Storage.store import load_ip_alert_count

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

def compute_risk_score(alert, events):
    severity_base = {"HIGH": 70, "MEDIUM": 40, "LOW": 15}
    score = severity_base.get(alert["severity"], 15)

    try:
        dt = parse_timestamp_auth(alert["timestamp"])
        event_minute = dt.hour * 60 + dt.minute
        if 0 <= event_minute <= 300:
            score += 15
    except Exception:
        pass

    user = alert.get("user") or ""
    if any(u in user.lower() for u in ["root", "admin", "administrator"]):
        score += 10

    try:
        prior_alerts = load_ip_alert_count(alert["source_ip"])
        if prior_alerts >= 3:
            score += 10
    except Exception:
        pass

    return min(score, 100)

def build_alert(rule, event, extra_fields=None):
    alert = {
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
        "tactic": rule["tactic"],
        "risk_score": 0
    }
    if extra_fields:
        alert.update(extra_fields)
    return alert

def detect_bruteforce(events, rule):
    threshold = rule["threshold"]
    window_sec = rule["time_window_seconds"]
    cooldown_sec = 300
    results = []

    failed_events = [
        e for e in events
        if e["event_type"] == rule["event_type"] and e["source_ip"]
    ]
    if not failed_events:
        return results

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

            if len(window_events) >= threshold:
                alert = build_alert(rule, ev_list[i])
                alert["risk_score"] = compute_risk_score(alert, window_events)
                results.append((alert, window_events))
                ip_last_alert = start_time

    return results

def detect_offhours(events, rule):
    time_condition = rule["time_condition"]
    results = []

    rule_parts = time_condition.split("-")
    rule_start = datetime.strptime(rule_parts[0], "%H:%M")
    rule_end = datetime.strptime(rule_parts[1], "%H:%M")
    start_minute = rule_start.hour * 60 + rule_start.minute
    end_minute = rule_end.hour * 60 + rule_end.minute

    successful_logins = [
        e for e in events
        if e["event_type"] == rule["event_type"]
    ]
    if not successful_logins:
        return results

    for event in successful_logins:
        dt = parse_timestamp_auth(event["timestamp"])
        event_minute = dt.hour * 60 + dt.minute
        if start_minute <= event_minute <= end_minute:
            alert = build_alert(rule, event)
            alert["risk_score"] = compute_risk_score(alert, [event])
            results.append((alert, [event]))

    return results

def detect_webscan(events, rule):
    threshold = rule["threshold"]
    window_sec = rule["time_window_seconds"]
    cooldown_sec = 300
    results = []

    web_events = [
        e for e in events
        if e["event_type"] == rule["event_type"] and e["status"] == rule["status"]
    ]
    if not web_events:
        return results

    ip_events = {}
    for e in web_events:
        ip_events.setdefault(e["source_ip"], []).append(e)

    for ip, ev_list in ip_events.items():
        times = [parse_timestamp_access(e["timestamp"]) for e in ev_list]
        ip_last_alert = None

        for i, start_time in enumerate(times):
            if ip_last_alert and (start_time - ip_last_alert).total_seconds() < cooldown_sec:
                continue

            window_events = [
                ev_list[j] for j in range(i, len(times))
                if (times[j] - start_time).total_seconds() <= window_sec
            ]

            if len(window_events) >= threshold:
                alert = build_alert(rule, ev_list[i])
                alert["risk_score"] = compute_risk_score(alert, window_events)
                results.append((alert, window_events))
                ip_last_alert = start_time

    return results

def detect_privesc(events, rule):
    results = []

    sudo_events = [
        e for e in events
        if e["event_type"] == rule["event_type"]
    ]
    if not sudo_events:
        return results

    for event in sudo_events:
        alert = build_alert(rule, event)
        alert["risk_score"] = compute_risk_score(alert, [event])
        results.append((alert, [event]))

    return results

def detect_credstuffing(events, rule):
    threshold = rule["threshold"]
    window_sec = rule["time_window_seconds"]
    cooldown_sec = 300
    results = []

    failed_events = [
        e for e in events
        if e["event_type"] == rule["event_type"]
        and e["source_ip"]
        and e.get("user")
    ]
    if not failed_events:
        return results

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
                alert = build_alert(rule, ev_list[i], {
                    "user": ", ".join(unique_users)
                })
                alert["risk_score"] = compute_risk_score(alert, window_events)
                results.append((alert, window_events))
                ip_last_alert = start_time

    return results

RULE_DISPATCHER = {
    "bruteforce": detect_bruteforce,
    "offhours": detect_offhours,
    "webscan": detect_webscan,
    "privesc": detect_privesc,
    "credstuffing": detect_credstuffing
}

def run_simulator(rule_id, log_line):
    try:
        rules = json.loads(RULES_PATH.read_text())
        rule = next((r for r in rules if r["rule_id"] == rule_id), None)
        if not rule:
            return {"matched": False, "reason": "Rule not found"}

        from Parsing.parser import auth_parser, access_parser
        from Parsing.normalization import normalize_events

        auth_timestamps, auth_hostnames, auth_processes, auth_pid, auth_messages, auth_ips, auth_usernames, auth_raw = auth_parser()
        acc_ips, acc_users, acc_timestamps, acc_methods, acc_endpoints, acc_status, acc_sizes, acc_raw = access_parser()

        from Parsing.normalization import normalize_events
        events = normalize_events()

        test_events = [e for e in events if e.get("raw") == log_line.strip()]

        if not test_events:
            return {
                "matched": False,
                "reason": "Log line not found in parsed events. Make sure it exists in your log files."
            }

        detector = RULE_DISPATCHER.get(rule.get("rule_type"))
        if not detector:
            return {"matched": False, "reason": f"No detector for rule_type: {rule.get('rule_type')}"}

        results = detector(events, rule)

        for alert, triggered_events in results:
            for te in triggered_events:
                if te.get("raw") == log_line.strip():
                    return {
                        "matched": True,
                        "rule_id": rule["rule_id"],
                        "rule_name": rule["name"],
                        "technique_id": rule["technique_id"],
                        "tactic": rule["tactic"],
                        "severity": rule["severity"],
                        "source_ip": alert["source_ip"],
                        "timestamp": alert["timestamp"],
                        "risk_score": alert.get("risk_score", 0),
                        "reason": f"Log line matched rule {rule['rule_id']} — {rule['name']}"
                    }

        return {
            "matched": False,
            "reason": f"Log line was parsed but did not meet rule threshold or conditions for {rule['rule_id']}"
        }

    except Exception as e:
        return {"matched": False, "reason": f"Simulator error: {str(e)}"}

def detection_engine():
    try:
        rules = json.loads(RULES_PATH.read_text())
        from Storage.store import load_all_events
        events = load_all_events()
        results = []

        for rule in rules:
            rule_type = rule.get("rule_type")
            detector = RULE_DISPATCHER.get(rule_type)
            if detector:
                results.extend(detector(events, rule))
            else:
                print(f"No detector found for rule_type: {rule_type}")

        return results, events

    except Exception as e:
        print(f"Detection engine error: {e}")
        return [], []