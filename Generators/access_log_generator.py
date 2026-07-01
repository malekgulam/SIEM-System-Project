import random
from datetime import datetime, timedelta
from pathlib import Path
import sys

sys.path.append(str(Path(__file__).parent.parent))

from config import ACCESS_LOG

ips = [
    "192.168.1.10", "10.0.0.5", "172.16.0.12", "10.0.0.8",
    "192.168.1.15", "8.8.8.8", "1.1.1.1", "142.250.183.14",
    "104.26.10.78", "93.184.216.34", "198.51.100.23", "45.33.32.156"
]

methods = ["GET", "POST"]

endpoints = {
    "GET": [
        "/index.html", "/home", "/dashboard", "/admin",
        "/images/logo.png", "/css/style.css", "/profile",
        "/.env", "/wp-admin", "/phpmyadmin", "/config.php",
        "/backup.zip", "/.git/config", "/etc/passwd"
    ],
    "POST": [
        "/login", "/submit", "/api/login", "/logout",
        "/upload", "/register", "/reset-password"
    ]
}

status_codes = [200, 301, 302, 400, 401, 403, 404, 500, 502]
users = ["-", "admin", "user", "guest", "root", "john"]
request_types = ["HTTP/1.1", "HTTP/1.0", "HTTP/2.0"]
sizes = [0, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768]

scan_endpoints = [
    "/.env", "/wp-admin", "/phpmyadmin", "/config.php",
    "/backup.zip", "/.git/config", "/etc/passwd",
    "/admin", "/login", "/dashboard"
]

log_number = 100
current_time = datetime.now()
delay_seconds = [30, 10, 15, 45, 60]

burst_mode = True
burst_count = 0
burst_ip = "10.0.0.5"
burst_endpoint_index = 0

with ACCESS_LOG.open("a") as f:
    for i in range(log_number):

        if burst_mode and burst_count > 0:
            ip = burst_ip
            user = "-"
            method = "GET"
            endpoint = scan_endpoints[burst_endpoint_index % len(scan_endpoints)]
            request_type = random.choices(request_types, weights=[80, 5, 15])[0]
            status_code = 404
            size = random.choices(sizes, weights=[10, 10, 10, 50, 20, 0, 0, 0, 0, 0])[0]
            delay_second = random.choice([1, 2, 3])
            burst_count -= 1
            burst_endpoint_index += 1

        else:
            method = random.choices(methods, weights=[70, 40])[0]
            endpoint = random.choice(endpoints[method])

            if endpoint == "/login":
                status_code = random.choices(status_codes, weights=[55, 0, 0, 2, 35, 3, 5, 0, 0])[0]
            elif endpoint == "/admin":
                status_code = random.choices(status_codes, weights=[30, 0, 0, 0, 0, 60, 10, 0, 0])[0]
            else:
                status_code = random.choices(status_codes, weights=[10, 0, 0, 10, 10, 45, 20, 5, 0])[0]

            ip = random.choice(ips)
            user = random.choices(users, weights=[40, 15, 15, 10, 15, 5])[0]
            request_type = random.choices(request_types, weights=[80, 5, 15])[0]

            if status_code == 200:
                size = random.choices(sizes, weights=[0, 0, 0, 0, 0, 0, 5, 25, 50, 30])[0]
            else:
                size = random.choices(sizes, weights=[12, 14, 13, 12, 14, 13, 14, 5, 0, 0])[0]

            delay_second = random.choice(delay_seconds)

            if burst_mode and random.random() < 0.05:
                burst_count = random.randint(10, 12)
                burst_ip = random.choice(["10.0.0.5", "45.33.32.156", "93.184.216.34"])
                burst_endpoint_index = 0
                ip = burst_ip
                user = "-"
                method = "GET"
                endpoint = scan_endpoints[burst_endpoint_index % len(scan_endpoints)]
                request_type = random.choices(request_types, weights=[80, 5, 15])[0]
                status_code = 404
                size = random.choices(sizes, weights=[10, 10, 10, 50, 20, 0, 0, 0, 0, 0])[0]
                delay_second = random.choice([1, 2, 3])
                burst_count -= 1
                burst_endpoint_index += 1

        print(
            f'{ip} - {user} [{current_time.strftime("%d/%b/%Y:%H:%M:%S+0000")}]'
            f' "{method} {endpoint} {request_type}" {status_code} {size}',
            file=f
        )

        current_time += timedelta(seconds=delay_second)