from __future__ import annotations

import os
import hashlib
import shutil
import sqlite3
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit


def database_path() -> Path:
    return Path(os.getenv("CYBERGUARD_DB_PATH", str(Path(__file__).with_name("cyberguard.db"))))


def _postgres_client_environment(database_url: str) -> tuple[str, dict[str, str]]:
    parsed = urlsplit(database_url)
    if parsed.scheme not in {"postgres", "postgresql"} or not parsed.hostname or not parsed.path.strip("/"):
        raise ValueError("A valid PostgreSQL URL with host and database name is required")

    environment = os.environ.copy()
    environment.update({
        "PGHOST": parsed.hostname,
        "PGPORT": str(parsed.port or 5432),
        "PGDATABASE": unquote(parsed.path.lstrip("/")),
    })
    if parsed.username:
        environment["PGUSER"] = unquote(parsed.username)
    if parsed.password:
        environment["PGPASSWORD"] = unquote(parsed.password)
    else:
        environment.pop("PGPASSWORD", None)
    sslmode = parse_qs(parsed.query).get("sslmode", [])
    if sslmode:
        environment["PGSSLMODE"] = sslmode[-1]
    return environment["PGDATABASE"], environment


def _require_postgres_tool(name: str) -> str:
    executable = shutil.which(name)
    if not executable:
        raise RuntimeError(f"{name} is required for PostgreSQL backup and restore operations")
    return executable


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def backup_database(destination: str | None = None) -> dict[str, Any]:
    database_url = os.getenv("CYBERGUARD_DATABASE_URL", "").strip()
    if database_url.startswith(("postgresql://", "postgres://")):
        database_name, environment = _postgres_client_environment(database_url)
        pg_dump = _require_postgres_tool("pg_dump")
        pg_restore = _require_postgres_tool("pg_restore")
        target = Path(destination or os.getenv("CYBERGUARD_BACKUP_PATH", "cyberguard-postgres.backup"))
        target.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".partial", dir=target.parent)
        os.close(descriptor)
        temporary_target = Path(temporary_name)
        try:
            subprocess.run(
                [pg_dump, "--format=custom", "--no-owner", "--no-privileges", "--file", str(temporary_target), "--dbname", database_name],
                env=environment,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            subprocess.run(
                [pg_restore, "--list", str(temporary_target)],
                env=environment,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            temporary_target.replace(target)
        except (OSError, subprocess.CalledProcessError) as error:
            temporary_target.unlink(missing_ok=True)
            raise RuntimeError("PostgreSQL backup failed; the destination was not replaced") from error
        return {"status": "completed", "database": database_name, "destination": str(target), "sha256": _sha256_file(target), "created_at": datetime.now(timezone.utc).isoformat(), "format": "postgresql_custom_archive"}

    source = database_path()
    if not source.exists():
        raise FileNotFoundError(f"Database does not exist: {source}")
    target = Path(destination or os.getenv("CYBERGUARD_BACKUP_PATH", str(source.with_suffix(".backup.db"))))
    target.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(source) as source_db, sqlite3.connect(target) as target_db:
        source_db.backup(target_db)
    return {"status": "completed", "source": str(source), "destination": str(target), "sha256": _sha256_file(target), "created_at": datetime.now(timezone.utc).isoformat(), "format": "sqlite"}


def restore_database(source: str, destination: str | None = None) -> dict[str, Any]:
    backup = Path(source)
    if not backup.is_file():
        raise FileNotFoundError(f"Backup does not exist: {backup}")
    with backup.open("rb") as handle:
        archive_signature = handle.read(16)
    explicit_destination = (destination or "").strip()
    restore_url = explicit_destination if explicit_destination.startswith(("postgresql://", "postgres://")) else os.getenv("CYBERGUARD_RESTORE_DATABASE_URL", "").strip()
    if restore_url.startswith(("postgresql://", "postgres://")):
        if not archive_signature.startswith(b"PGDMP"):
            raise ValueError("The selected backup is not a PostgreSQL custom-format archive")
        active_database_url = os.getenv("CYBERGUARD_DATABASE_URL", "").strip()
        if active_database_url.startswith(("postgresql://", "postgres://")):
            active = urlsplit(active_database_url)
            restore = urlsplit(restore_url)
            active_database = (active.hostname, active.port or 5432, unquote(active.path.lstrip("/")))
            restore_database = (restore.hostname, restore.port or 5432, unquote(restore.path.lstrip("/")))
            if active_database == restore_database:
                raise ValueError("PostgreSQL restore target must be a separate database from the active application database")
        database_name, environment = _postgres_client_environment(restore_url)
        pg_restore = _require_postgres_tool("pg_restore")
        try:
            subprocess.run(
                [pg_restore, "--list", str(backup)],
                env=environment,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            subprocess.run(
                [pg_restore, "--exit-on-error", "--no-owner", "--no-privileges", "--dbname", database_name, str(backup)],
                env=environment,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except (OSError, subprocess.CalledProcessError) as error:
            raise RuntimeError("PostgreSQL restore failed; inspect the target database before retrying") from error
        return {"status": "restored", "source": str(backup), "database": database_name, "restored_at": datetime.now(timezone.utc).isoformat(), "format": "postgresql_custom_archive"}
    if restore_url:
        raise ValueError("PostgreSQL restore destination must be a postgresql:// or postgres:// URL")
    if archive_signature.startswith(b"PGDMP"):
        raise ValueError("PostgreSQL restore requires an explicit, separate CYBERGUARD_RESTORE_DATABASE_URL target")
    if not archive_signature.startswith(b"SQLite format 3\x00"):
        raise ValueError("The backup is not a supported SQLite database or PostgreSQL custom archive")

    target = Path(explicit_destination or database_path())
    if not backup.exists():
        raise FileNotFoundError(f"Backup does not exist: {backup}")
    target.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(backup) as source_db, sqlite3.connect(target) as target_db:
        source_db.backup(target_db)
    return {"status": "restored", "source": str(backup), "destination": str(target), "sha256": _sha256_file(backup), "restored_at": datetime.now(timezone.utc).isoformat(), "format": "sqlite"}


def prometheus_metrics(request_count: int, error_count: int, active_incidents: int, provider_count: int) -> str:
    values = {
        "cyberguard_http_requests_total": request_count,
        "cyberguard_http_errors_total": error_count,
        "cyberguard_active_incidents": active_incidents,
        "cyberguard_configured_providers": provider_count,
    }
    return "\n".join(f"{name} {value}" for name, value in values.items()) + "\n"
