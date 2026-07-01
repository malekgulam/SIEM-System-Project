import sys
from pathlib import Path
import re

sys.path.append(str(Path(__file__).parent.parent))

from Ingestion.reader import read_logs

def auth_parser():
    auth_lines, _ = read_logs()

    auth_timestamps = []
    auth_hostnames = []
    auth_processes = []
    auth_pid = []
    auth_messages = []
    auth_ips = []
    auth_usernames = []
    auth_raw_logs = []

    username_pattern = re.compile(
        r'\bas\s+([a-zA-Z0-9_.-]+)|'
        r'\bfor\s+invalid\s+user\s+([a-zA-Z0-9_.-]+)(?=\s+from)|'
        r'\bfor\s+user\s+([a-zA-Z0-9_.-]+)(?=\s+from|\s*$)|'
        r'\bfor\s+([a-zA-Z0-9_.-]+)(?=\s+from|\s+by\s+user)|'
        r'^\(([a-zA-Z0-9_.-]+)\)|'
        r'\b([a-zA-Z0-9_.-]+)\s*:(?=.*TTY)|'
        r'\bby\s+([a-zA-Z0-9_.-]+)(?=\s*\(uid)|'
        r'\bSuccessful\s+su\s+for\s+([a-zA-Z0-9_.-]+)'
    )

    line_pattern = re.compile(
        r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+'
        r'([a-zA-Z0-9]+|[a-zA-Z0-9]+(?:-[a-zA-Z0-9]+)+)\s+'
        r'(\w+)\[(\d+)\]:\s+(.*)'
    )

    for line in auth_lines:
        line_match = line_pattern.search(line)
        if line_match:
            auth_raw_logs.append(line_match.group())
            auth_timestamps.append(line_match.group(1))
            auth_hostnames.append(line_match.group(2))
            auth_processes.append(line_match.group(3))
            auth_pid.append(line_match.group(4))
            auth_messages.append(line_match.group(5))

            ip_match = re.search(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', line_match.group(5))
            user_match = username_pattern.search(line_match.group(5))

            auth_ips.append(ip_match.group() if ip_match else None)
            auth_usernames.append(
                next((g for g in user_match.groups() if g is not None), None)
                if user_match else None
            )

    return auth_timestamps, auth_hostnames, auth_processes, auth_pid, auth_messages, auth_ips, auth_usernames, auth_raw_logs


def access_parser():
    _, access_lines = read_logs()

    acc_ips = []
    acc_timestamps = []
    acc_methods = []
    acc_endpoints = []
    acc_status = []
    acc_sizes = []
    acc_users = []
    access_raw_logs = []

    line_pattern = re.compile(
        r'(\b\d{1,3}(?:\.\d{1,3}){3})\s+-\s+([a-zA-Z0-9]+|-)\s+'
        r'\[(\d{2}/[a-zA-Z]{3}/\d{4}:\d{2}:\d{2}:\d{2})\+\d+\]\s+'
        r'\"(\w+)\s+(/[^\s\"]*)\s+\w+/\d+\.\d+\"\s+(\d{1,3})\s+(\d+)'
    )

    for line in access_lines:
        line_match = line_pattern.search(line)
        if line_match:
            access_raw_logs.append(line_match.group())
            acc_ips.append(line_match.group(1))
            acc_users.append(line_match.group(2))
            acc_timestamps.append(line_match.group(3))
            acc_methods.append(line_match.group(4))
            acc_endpoints.append(line_match.group(5))
            acc_status.append(line_match.group(6))
            acc_sizes.append(line_match.group(7))

    return acc_ips, acc_users, acc_timestamps, acc_methods, acc_endpoints, acc_status, acc_sizes, access_raw_logs