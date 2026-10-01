import atexit
import os
from pathlib import Path
import tempfile
from uuid import uuid4


os.environ["CYBERGUARD_ENV"] = "test"
os.environ["CYBERGUARD_HEAD_ADMIN_USERNAME"] = "test-head-admin"
os.environ["CYBERGUARD_HEAD_ADMIN_PASSWORD"] = "test-only-admin-password-123"
os.environ["CYBERGUARD_JWT_SECRET"] = "test-only-jwt-secret-not-for-deployment"
os.environ["CYBERGUARD_DEMO_ANALYST_PASSWORD"] = "analyst123"
os.environ["CYBERGUARD_DEMO_LEAD_PASSWORD"] = "lead123"
os.environ["CYBERGUARD_DEMO_ADMIN_PASSWORD"] = "admin123"
os.environ["CYBERGUARD_IDP_ADMIN_PASSWORD"] = "admin123"
os.environ.pop("CYBERGUARD_DATABASE_URL", None)
os.environ.pop("CYBERGUARD_REDIS_URL", None)

_test_database = Path(tempfile.gettempdir()) / f"cyberguard-tests-{uuid4().hex}.sqlite"
os.environ["CYBERGUARD_DB_PATH"] = str(_test_database)


def _remove_test_database():
    for suffix in ("", "-shm", "-wal"):
        Path(f"{_test_database}{suffix}").unlink(missing_ok=True)


atexit.register(_remove_test_database)
