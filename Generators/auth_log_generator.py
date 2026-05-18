import random
import time
from datetime import datetime, timedelta
from pathlib import Path

process_messages = {
    "sshd" : ["Accepted password for user from 192.168.1.10 port 54321 ssh2","Failed password for invalid user admin from 192.168.1.20 port 44444 ssh2","Failed password for user root from 10.0.0.5 port 2222 ssh2","Connection closed by authenticating user","Received disconnect from 192.168.1.15 port 50234"],
    "sudo" : ["user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/bin/ls","user : TTY=pts/1 ; PWD=/home/user ; USER=root ; COMMAND=/usr/bin/apt update","pam_unix(sudo:session): session opened for user root by user(uid=0)","pam_unix(sudo:session): session closed for user root","user not allowed to execute command as root"],
    "su" : ["pam_unix(su:session): session opened for user root by user(uid=0)","pam_unix(su:session): session closed for user root","Authentication failure for user root","Failed su for root by user","Successful su for root by user"],
    "crond" : ["(root) CMD (/usr/bin/backup.sh)","(user) CMD (/usr/bin/python3 script.py)","(root) CMD (run-parts /etc/cron.hourly)","(user) CMD (/bin/bash cleanup.sh)","(root) CMD (/usr/bin/apt update)"],
    "systemd" : ["Started User Manager for UID 1000","Starting Daily Cleanup of Temporary Directories","Stopped User Manager for UID 1000","Starting Session for user root","Reached target Multi-User System"]
}

processes = ["sshd","sudo","su","crond","systemd"]
hostnames = ["kali", "ubuntu", "server01","web-prod","my-laptop"]
log_number = 100
log_path = Path("C:/") / "Users" / "msi-ninja" / "Documents" / "Projects" / "SIEM_System_Project" / "Data" / "Logs" / "auth.log"
delay_seconds = [30,10,15,45,60]
current_time = datetime.now()


burst_mode = True
burst_count = 0          
burst_ip = "10.0.0.5"    
midnight_mode = True
midnight_count = 0
midnight_ip = random.choice(["10.0.0.5","172.16.1.24"])
timestamp_format = "%b %d %H:%M:%S"
start_time = current_time.replace(hour=0, minute=0,second=0,microsecond=0)
end_time = current_time.replace(hour=5,minute=0,second=0,microsecond=0)

with log_path.open("a") as f:
    for i in range(log_number):
        timestamps = current_time.strftime("%b %d %H:%M:%S")
        
        if burst_mode and burst_count > 0:
            process = "sshd"
            
            port = random.randint(10000, 65535)
            msg = f"Failed password for invalid user admin from {burst_ip} port {port} ssh2"
            hostname = "ubuntu"
            delay_second = random.choice([2,3,4,5])   
            burst_count -= 1

        elif midnight_mode and midnight_count > 0:
            process = "sshd"

            port = random.randint(10000,65535)
            msg = f"Accepted password for user from {midnight_ip} port {port} ssh2"
            hostname = random.choice(hostnames)
            delta_seconds = int((end_time - start_time).total_seconds())
            random_seconds = random.randint(0, delta_seconds)
            result = start_time + timedelta(seconds=random_seconds)
            timestamps = result.strftime(timestamp_format)
            delay_second = random.choice([5,10,15,20])
            midnight_count -= 1
        
        else:
            
            process = random.choice(processes)
            msg = random.choice(process_messages[process])
            hostname = random.choice(hostnames)
            delay_second = random.choice(delay_seconds)
            
            
            if burst_mode and random.random() < 0.10:
                burst_count = random.randint(5, 7)   
                
                process = "sshd"
                port = random.randint(10000, 65535)
                msg = f"Failed password for invalid user admin from {burst_ip} port {port} ssh2"
                hostname = "ubuntu"
                delay_second = random.choice([2,3,4,5])
                burst_count -= 1

            if midnight_mode and random.random() < 0.04:
                midnight_count = random.randint(1,2)

                process = "sshd"
                port = random.randint(10000,65535)
                msg = f"Accepted password for user from {midnight_ip} port {port} ssh2"
                hostname = random.choice(hostnames)
                delta_seconds = int((end_time - start_time).total_seconds())
                random_seconds = random.randint(0, delta_seconds)
                result = start_time + timedelta(seconds=random_seconds)
                timestamps = result.strftime(timestamp_format)
                delay_second = random.choice([5,10,15,20])
                midnight_count -= 1



        
        print(timestamps, f"{hostname} {process}[{random.randint(1000,1399)}]: {msg}", file=f)
        current_time += timedelta(seconds=delay_second)

time.sleep(0.5)