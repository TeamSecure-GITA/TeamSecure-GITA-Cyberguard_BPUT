from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def database_path() -> Path:
    return Path(os.getenv("CYBERGUARD_DB_PATH", str(Path(__file__).with_name("cyberguard.db"))))


def backup_database(destination: str | None = None) -> dict[str, Any]:
    if os.getenv("CYBERGUARD_DATABASE_URL", "").strip().startswith(("postgresql://", "postgres://")):
        raise RuntimeError("SQLite backup utility cannot back up PostgreSQL; use pg_dump for PostgreSQL deployments")
    source = database_path()
    if not source.exists():
        raise FileNotFoundError(f"Database does not exist: {source}")
    target = Path(destination or os.getenv("CYBERGUARD_BACKUP_PATH", str(source.with_suffix(".backup.db"))))
    target.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(source) as source_db, sqlite3.connect(target) as target_db:
        source_db.backup(target_db)
    return {"status": "completed", "source": str(source), "destination": str(target), "created_at": datetime.now(timezone.utc).isoformat()}


def restore_database(source: str, destination: str | None = None) -> dict[str, Any]:
    if os.getenv("CYBERGUARD_DATABASE_URL", "").strip().startswith(("postgresql://", "postgres://")):
        raise RuntimeError("SQLite restore utility cannot restore PostgreSQL; use pg_restore for PostgreSQL deployments")
    backup = Path(source)
    target = Path(destination or database_path())
    if not backup.exists():
        raise FileNotFoundError(f"Backup does not exist: {backup}")
    target.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(backup) as source_db, sqlite3.connect(target) as target_db:
        source_db.backup(target_db)
    return {"status": "restored", "source": str(backup), "destination": str(target), "restored_at": datetime.now(timezone.utc).isoformat()}


def prometheus_metrics(request_count: int, error_count: int, active_incidents: int, provider_count: int) -> str:
    values = {
        "cyberguard_http_requests_total": request_count,
        "cyberguard_http_errors_total": error_count,
        "cyberguard_active_incidents": active_incidents,
        "cyberguard_configured_providers": provider_count,
    }
    return "\n".join(f"{name} {value}" for name, value in values.items()) + "\n"
