from pathlib import Path
import sys

sys.path.append(str(Path(__file__).parent.parent))

from config import AUTH_LOG, ACCESS_LOG

def read_logs():
    auth_lines = []
    access_lines = []

    try:
        with AUTH_LOG.open("r") as auth_file:
            for line in auth_file:
                auth_lines.append(line.strip())

        with ACCESS_LOG.open("r") as access_file:
            for line in access_file:
                access_lines.append(line.strip())

        return auth_lines, access_lines

    except FileNotFoundError as e:
        print(f"Log file not found: {e}")
        return [], []