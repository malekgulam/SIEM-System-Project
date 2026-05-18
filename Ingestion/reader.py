from pathlib import Path

def read_logs():
    auth_path = Path("C:/") / "Users" / "msi-ninja" / "Documents" / "Projects" / "SIEM_System_Project" / "Data" / "Logs" / "auth.log"
    apache_path = Path("C:/") / "Users" / "msi-ninja" / "Documents" / "Projects" / "SIEM_System_Project" / "Data" / "Logs" / "access.log"

    auth_lines = []
    access_lines = []

    try:
        with auth_path.open("r") as auth_file:

            for line in auth_file:
                auth_lines.append(line.strip())
            

        with apache_path.open("r") as apache_file:

            for line in apache_file:
                access_lines.append(line.strip())
        
        return auth_lines,access_lines                

    except FileNotFoundError:
        print("file not found")

