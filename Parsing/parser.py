import sys
from pathlib import Path
import re

project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from Ingestion.reader import read_logs

log_data = read_logs()

auth_lines , access_lines = log_data

def auth_parser():

    auth_timestamps = []
    auth_hostnames = []
    auth_processes = []
    auth_pid = []
    auth_messages = []
    auth_ips = []
    auth_usernames = []
    auth_raw_logs = []

    pattern = re.compile(
        r'\bas\s+([a-zA-Z0-9_.-]+)|'
        r'\bfor\s+invalid\s+user\s+([a-zA-Z0-9_.-]+)(?=\s+from)|'
        r'\bfor\s+user\s+([a-zA-Z0-9_.-]+)(?=\s+from|\s*$)|'
        r'\bfor\s+([a-zA-Z0-9_.-]+)(?=\s+from|\s+by\s+user)|'
        r'^\(([a-zA-Z0-9_.-]+)\)|'
        r'\b([a-zA-Z0-9_.-]+)\s*:(?=.*TTY)|'
        r'\bby\s+([a-zA-Z0-9_.-]+)(?=\s*\(uid)|'
        r'\bSuccessful\s+su\s+for\s+([a-zA-Z0-9_.-]+)'
    )

    for line in auth_lines:
        line_match = re.search(r"(\w+\s+\d+\s+\d+:\d+:\d+)\s+([a-zA-Z0-9]+|[a-zA-Z0-9]+(?:-[a-zA-Z0-9]+)+)\s+(\w+)\[(\d+)\]:\s+(.*)", line)
        if line_match:

            auth_raw_logs.append(line_match.group())
            auth_timestamps.append(line_match.group(1))
            auth_hostnames.append(line_match.group(2))
            auth_processes.append(line_match.group(3))
            auth_pid.append(line_match.group(4))
            auth_messages.append(line_match.group(5))
        
            ip_match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", line_match.group(5))
            user_matches = pattern.search(line_match.group(5))

            if user_matches:
                username = next((g for g in user_matches.groups() if g is not None), None)
                if username:
                    auth_usernames.append(username)
                if username is None:
                    auth_usernames.append(None)
            if user_matches is None:
                auth_usernames.append(None)
            if ip_match:
                auth_ips.append(ip_match.group())
            if ip_match is None:
                auth_ips.append(None)
            
    return auth_timestamps,auth_hostnames,auth_processes,auth_pid,auth_messages,auth_ips,auth_usernames,auth_raw_logs

def access_parser():

    acc_ips = []
    acc_timestamps = []
    acc_methods = []
    acc_endpoints = []
    acc_status = []
    acc_sizes = []
    acc_users = []
    access_raw_logs = []


    for line in access_lines:
        line_match = re.search(r'(\b\d{1,3}(?:\.\d{1,3}){3})\s+-\s+([a-zA-Z0-9]+|-)\s+\[(\d{2}/[a-zA-Z]{3}/\d{4}:\d{2}:\d{2}:\d{2})\+\d+\]\s+\"(\w+)\s+(/[a-zA-Z0-9]+|/[a-zA-Z0-9]+(?:\.[a-zA-Z0-9]+)+|/[a-zA-Z0-9]+(?:-[a-zA-Z0-9]+)+|/[a-zA-Z0-9]+(?:/[a-zA-Z0-9]+)+|/[a-zA-Z0-9]+(?:/[a-zA-Z0-9]+\.[a-zA-Z0-9]+)+)\s+\w+/\d+\.\d+\"\s+(\d{1,3})\s+(\d+)',line)

        if line_match:
            access_raw_logs.append(line_match.group())
            acc_ips.append(line_match.group(1))
            acc_timestamps.append(line_match.group(3))
            acc_methods.append(line_match.group(4))
            acc_endpoints.append(line_match.group(5))
            acc_status.append(line_match.group(6))
            acc_sizes.append(line_match.group(7))
            acc_users.append(line_match.group(2))

    return acc_ips,acc_users,acc_timestamps,acc_methods,acc_endpoints,acc_status,acc_sizes,access_raw_logs
