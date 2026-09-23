from __future__ import annotations

import os

if not os.getenv("CYBERGUARD_DATABASE_URL", "").strip().startswith(("postgresql://", "postgres://")):
    raise SystemExit("Set CYBERGUARD_DATABASE_URL to a PostgreSQL connection string before migration")

from main import initialize_database

initialize_database()
print("CyberGuard PostgreSQL schema initialized")
