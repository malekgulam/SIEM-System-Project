import random
from datetime import datetime, timedelta
from pathlib import Path
import sys

sys.path.append(str(Path(__file__).parent.parent))

from config import AUTH_LOG

process_messages = {
    "sshd": [
        "Accepted password for user from 192.168.1.10 port 54321 ssh2",
        "Failed password for invalid user admin from 192.168.1.20 port 44444 ssh2",
        "Failed password for user root from 10.0.0.5 port 2222 ssh2",
        "Connection closed by authenticating user",
        "Received disconnect from 192.168.1.15 port 50234"
    ],
    "sudo": [
        "user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/bin/ls",
        "user : TTY=pts/1 ; PWD=/home/user ; USER=root ; COMMAND=/usr/bin/apt update",
        "pam_unix(sudo:session): session opened for user root by user(uid=0)",
        "pam_unix(sudo:session): session closed for user root",
        "user not allowed to execute command as root"
    ],
    "su": [
        "pam_unix(su:session): session opened for user root by user(uid=0)",
        "pam_unix(su:session): session closed for user root",
        "Authentication failure for user root",
        "Failed su for root by user",
        "Successful su for root by user"
    ],
    "crond": [
        "(root) CMD (/usr/bin/backup.sh)",
        "(user) CMD (/usr/bin/python3 script.py)",
        "(root) CMD (run-parts /etc/cron.hourly)",
        "(user) CMD (/bin/bash cleanup.sh)",
        "(root) CMD (/usr/bin/apt update)"
    ],
    "systemd": [
        "Started User Manager for UID 1000",
        "Starting Daily Cleanup of Temporary Directories",
        "Stopped User Manager for UID 1000",
        "Starting Session for user root",
        "Reached target Multi-User System"
    ]
}

processes = ["sshd", "sudo", "su", "crond", "systemd"]
hostnames = ["kali", "ubuntu", "server01", "web-prod", "my-laptop"]
delay_seconds = [30, 10, 15, 45, 60]
timestamp_format = "%b %d %H:%M:%S"

log_number = 100
current_time = datetime.now()

burst_ips = ["10.0.0.5", "172.16.1.24", "192.168.1.20"]
stuffing_ips = ["45.33.32.156", "93.184.216.34"]
stuffing_usernames = ["admin", "root", "administrator", "guest", "test", "oracle", "postgres"]

midnight_start = current_time.replace(hour=0, minute=0, second=0, microsecond=0)
midnight_end = current_time.replace(hour=5, minute=0, second=0, microsecond=0)

burst_mode = True
burst_count = 0
burst_ip = random.choice(burst_ips)

midnight_mode = True
midnight_count = 0
midnight_ip = random.choice(["10.0.0.5", "172.16.1.24"])

stuffing_mode = True
stuffing_count = 0
stuffing_ip = random.choice(stuffing_ips)
stuffing_index = 0

privesc_mode = True

with AUTH_LOG.open("a") as f:
    for i in range(log_number):
        timestamps = current_time.strftime(timestamp_format)

        if burst_mode and burst_count > 0:
            process = "sshd"
            port = random.randint(10000, 65535)
            msg = f"Failed password for invalid user admin from {burst_ip} port {port} ssh2"
            hostname = "ubuntu"
            delay_second = random.choice([2, 3, 4, 5])
            burst_count -= 1

        elif stuffing_mode and stuffing_count > 0:
            process = "sshd"
            port = random.randint(10000, 65535)
            username = stuffing_usernames[stuffing_index % len(stuffing_usernames)]
            msg = f"Failed password for invalid user {username} from {stuffing_ip} port {port} ssh2"
            hostname = random.choice(hostnames)
            delay_second = random.choice([3, 5, 7])
            stuffing_count -= 1
            stuffing_index += 1

        elif midnight_mode and midnight_count > 0:
            process = "sshd"
            port = random.randint(10000, 65535)
            msg = f"Accepted password for user from {midnight_ip} port {port} ssh2"
            hostname = random.choice(hostnames)
            delta_seconds = int((midnight_end - midnight_start).total_seconds())
            random_seconds = random.randint(0, delta_seconds)
            result = midnight_start + timedelta(seconds=random_seconds)
            timestamps = result.strftime(timestamp_format)
            delay_second = random.choice([5, 10, 15, 20])
            midnight_count -= 1

        else:
            process = random.choice(processes)
            msg = random.choice(process_messages[process])
            hostname = random.choice(hostnames)
            delay_second = random.choice(delay_seconds)

            if burst_mode and random.random() < 0.10:
                burst_count = random.randint(5, 7)
                burst_ip = random.choice(burst_ips)
                process = "sshd"
                port = random.randint(10000, 65535)
                msg = f"Failed password for invalid user admin from {burst_ip} port {port} ssh2"
                hostname = "ubuntu"
                delay_second = random.choice([2, 3, 4, 5])
                burst_count -= 1

            elif stuffing_mode and random.random() < 0.06:
                stuffing_count = random.randint(4, 6)
                stuffing_ip = random.choice(stuffing_ips)
                stuffing_index = 0
                process = "sshd"
                port = random.randint(10000, 65535)
                username = stuffing_usernames[stuffing_index % len(stuffing_usernames)]
                msg = f"Failed password for invalid user {username} from {stuffing_ip} port {port} ssh2"
                hostname = random.choice(hostnames)
                delay_second = random.choice([3, 5, 7])
                stuffing_count -= 1
                stuffing_index += 1

            elif midnight_mode and random.random() < 0.04:
                midnight_count = random.randint(1, 2)
                process = "sshd"
                port = random.randint(10000, 65535)
                msg = f"Accepted password for user from {midnight_ip} port {port} ssh2"
                hostname = random.choice(hostnames)
                delta_seconds = int((midnight_end - midnight_start).total_seconds())
                random_seconds = random.randint(0, delta_seconds)
                result = midnight_start + timedelta(seconds=random_seconds)
                timestamps = result.strftime(timestamp_format)
                delay_second = random.choice([5, 10, 15, 20])
                midnight_count -= 1

            elif privesc_mode and random.random() < 0.08:
                process = "sudo"
                msg = random.choice(process_messages["sudo"])
                hostname = random.choice(hostnames)
                delay_second = random.choice(delay_seconds)

        print(timestamps, f"{hostname} {process}[{random.randint(1000, 1399)}]: {msg}", file=f)
        current_time += timedelta(seconds=delay_second)