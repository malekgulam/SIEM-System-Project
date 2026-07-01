from pathlib import Path

BASE_DIR = Path(__file__).parent

LOG_DIR = BASE_DIR / "Data" / "Logs"
AUTH_LOG = LOG_DIR / "auth.log"
ACCESS_LOG = LOG_DIR / "access.log"

RULES_PATH = BASE_DIR / "Detection" / "rules.json"

DB_PATH = BASE_DIR / "Storage" / "alerts.db"