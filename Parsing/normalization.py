import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent))

from Parsing.parser import auth_parser, access_parser

def normalize_events():
    auth_timestamps, auth_hostnames, auth_processes, auth_pid, auth_messages, auth_ips, auth_usernames, auth_raw_logs = auth_parser()
    acc_ips, acc_users, acc_timestamps, acc_methods, acc_endpoints, acc_status, acc_sizes, acc_raw = access_parser()

    keyword_map = {
        "Failed password": "failed_login",
        "Accepted password": "successful_login",
        "TTY=": "sudo_command",
        "Connection closed": "connection_closed",
        "Received disconnect": "disconnect",
        "not allowed to execute": "sudo_denied",
        "session closed": "session_closed",
        "session opened": "session_opened",
        "CMD": "cron_job",
        "Authentication failure": "auth_failure",
        "Successful su": "su_success",
        "Failed su": "su_failure",
        "Reached target": "systemd_target",
        "Stopped": "systemd_stopped",
        "Starting": "systemd_starting",
        "Started": "systemd_started"
    }

    normalized_events = []

    for i in range(len(auth_ips)):
        message = auth_messages[i]
        event_type = None

        for keyword, mapped_type in keyword_map.items():
            if keyword.lower() in message.lower():
                event_type = mapped_type
                break

        event = {
            "timestamp": auth_timestamps[i],
            "source_ip": auth_ips[i],
            "event_type": event_type,
            "user": auth_usernames[i],
            "process": auth_processes[i],
            "status": None,
            "severity": None,
            "raw": auth_raw_logs[i]
        }
        normalized_events.append(event)

    for i in range(len(acc_ips)):
        event = {
            "timestamp": acc_timestamps[i],
            "source_ip": acc_ips[i],
            "event_type": "web_request",
            "user": acc_users[i],
            "process": None,
            "status": acc_status[i],
            "severity": None,
            "raw": acc_raw[i]
        }
        normalized_events.append(event)

    return normalized_events