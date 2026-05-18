import random
import time
from datetime import datetime, timedelta
from pathlib import Path

ips = ["192.168.1.10","10.0.0.5","172.16.0.12","10.0.0.8","192.168.1.15","8.8.8.8","1.1.1.1","142.250.183.14","104.26.10.78","93.184.216.34","198.51.100.23","45.33.32.156"]

methods = ["GET","POST"]

endpoints = {
    "GET" : ["/index.html","/home","/dashboard","/admin","/images/logo.png","/css/style.css","/profile"],
    "POST" : ["/login","/submit","/api/login","/logout","/upload","/register","/reset-password"]
}

status_codes = [200,301,302,400,401,403,404,500,502]

users = ["-","admin","user","guest","root","john"]

request_types = ["HTTP/1.1","HTTP/1.0","HTTP/2.0"]

sizes = [0,128,256,512,1024,2048,4096,8192,16384,32768]

log_number = 100

log_path = Path("C:/") / "Users" / "msi-ninja" / "Documents" / "Projects" / "SIEM_System_Project" / "Data" / "Logs" / "access.log"

delay_seconds = [30,10,15,45,60]
current_time = datetime.now()

burst_mode = True
burst_count = 0          

with log_path.open("a") as f:

    for i in range(log_number):
        
        if burst_mode and burst_count > 0:

            ip = "10.0.0.5"
            user = "-"
            method = "GET"
            endpoint = random.choice(endpoints[method])
            request_type, = random.choices(request_types,weights=[80,5,15])
            status_code = 404
            size, = random.choices(sizes,weights=[10,10,10,50,20,0,0,0,0,0])
            delay_second = random.choice([1,2,3])   
            burst_count -= 1
        
        else:

            method, = random.choices(methods,weights=[70,40])

            endpoint = random.choice(endpoints[method])
            if endpoint == "/login":
                status_code, = random.choices(status_codes,weights=[55,0,0,2,35,3,5,0,0])
            elif endpoint == "/admin":
                status_code, = random.choices(status_codes,weights=[30,0,0,0,0,60,10,0,0])
            else :
                status_code, = random.choices(status_codes,weights=[10,0,0,10,10,45,20,5,0])

            ip = random.choice(ips)

            user, = random.choices(users,weights=[40,15,15,10,15,5])

            request_type, = random.choices(request_types,weights=[80,5,15])
            if status_code == 200:
                size, = random.choices(sizes,weights=[0,0,0,0,0,0,5,25,50,30])
            else :
                  size, = random.choices(sizes,weights=[12,14,13,12,14,13,14,5,0,0])

            delay_second = random.choice(delay_seconds)

            if burst_mode and random.random() < 0.05:
                burst_count = random.randint(10,12)

                ip = "10.0.0.5"
                user, = random.choices(users,weights=[60,10,10,5,10,5])
                method = "GET"
                endpoint = random.choice(endpoints[method])
                request_type, = random.choices(request_types,weights=[80,5,15])
                status_code = 404
                size, = random.choices(sizes,weights=[10,10,10,50,20,0,0,0,0,0])
                delay_second = random.choice([1,2,3])   
                burst_count -= 1

        print(f'{ip} - {user} [{current_time.strftime("%d/%b/%Y:%H:%M:%S+0000")}] "{method} {endpoint} {request_type}" {status_code} {size}',file=f)

        current_time += timedelta(seconds=delay_second)
        
time.sleep(0.5)





