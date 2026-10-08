import sqlite3
import hashlib

import pytest

import operations


def test_sqlite_backup_and_restore_round_trip(tmp_path, monkeypatch):
    source = tmp_path / "source.sqlite"
    backup = tmp_path / "backup.sqlite"
    restored = tmp_path / "restored.sqlite"
    monkeypatch.setenv("CYBERGUARD_DB_PATH", str(source))
    monkeypatch.delenv("CYBERGUARD_DATABASE_URL", raising=False)

    with sqlite3.connect(source) as database:
        database.execute("CREATE TABLE evidence (value TEXT NOT NULL)")
        database.execute("INSERT INTO evidence VALUES ('retained')")

    backup_result = operations.backup_database(str(backup))
    restore_result = operations.restore_database(str(backup), str(restored))
    assert backup_result["status"] == "completed"
    assert backup_result["sha256"] == hashlib.sha256(backup.read_bytes()).hexdigest()
    assert restore_result["status"] == "restored"
    assert restore_result["sha256"] == backup_result["sha256"]
    with sqlite3.connect(restored) as database:
        assert database.execute("SELECT value FROM evidence").fetchone()[0] == "retained"


def test_postgres_backup_uses_checked_custom_archive_without_exposing_password(tmp_path, monkeypatch):
    backup = tmp_path / "postgres.backup"
    monkeypatch.setenv("CYBERGUARD_DATABASE_URL", "postgresql://backup-user:secret%40pw@db.example:5432/soc?sslmode=require")
    monkeypatch.setattr(operations.shutil, "which", lambda name: f"/usr/bin/{name}")
    captured = []

    def fake_run(command, **kwargs):
        captured.append((command, kwargs))
        if "--file" in command:
            archive = command[command.index("--file") + 1]
            with open(archive, "wb") as handle:
                handle.write(b"test archive")

    monkeypatch.setattr(operations.subprocess, "run", fake_run)

    result = operations.backup_database(str(backup))

    assert result["format"] == "postgresql_custom_archive"
    assert result["sha256"] == hashlib.sha256(backup.read_bytes()).hexdigest()
    assert backup.read_bytes() == b"test archive"
    dump_command, dump_options = captured[0]
    assert "--format=custom" in dump_command
    assert "soc" in dump_command
    assert "secret@pw" not in " ".join(dump_command)
    assert dump_options["env"]["PGPASSWORD"] == "secret@pw"
    assert dump_options["env"]["PGSSLMODE"] == "require"
    assert captured[1][0][1] == "--list"


def test_postgres_restore_requires_explicit_separate_target_and_never_drops_objects(tmp_path, monkeypatch):
    archive = tmp_path / "backup.dump"
    archive.write_bytes(b"PGDMP test archive")
    monkeypatch.delenv("CYBERGUARD_RESTORE_DATABASE_URL", raising=False)
    monkeypatch.setattr(operations.shutil, "which", lambda name: f"/usr/bin/{name}")
    captured = []
    monkeypatch.setattr(operations.subprocess, "run", lambda command, **kwargs: captured.append((command, kwargs)))

    result = operations.restore_database(str(archive), "postgresql://restore:target%21@db.example/restored")

    assert result["database"] == "restored"
    restore_command = captured[-1][0]
    assert "--exit-on-error" in restore_command
    assert "--clean" not in restore_command
    assert "--create" not in restore_command
    assert "target!" not in " ".join(restore_command)
    assert captured[-1][1]["env"]["PGPASSWORD"] == "target!"


def test_postgres_restore_rejects_missing_target_url(tmp_path, monkeypatch):
    archive = tmp_path / "backup.dump"
    archive.write_bytes(b"PGDMP test archive")
    monkeypatch.delenv("CYBERGUARD_RESTORE_DATABASE_URL", raising=False)
    monkeypatch.setenv("CYBERGUARD_DATABASE_URL", "postgresql://live:secret@db.example/live")

    with pytest.raises(ValueError, match="explicit, separate"):
        operations.restore_database(str(archive))


def test_postgres_restore_refuses_active_application_database(tmp_path, monkeypatch):
    archive = tmp_path / "backup.dump"
    archive.write_bytes(b"PGDMP test archive")
    monkeypatch.setenv("CYBERGUARD_DATABASE_URL", "postgresql://app:password@db.example:5432/soc")
    monkeypatch.setattr(operations, "_require_postgres_tool", lambda _name: "/usr/bin/pg_restore")

    with pytest.raises(ValueError, match="separate database"):
        operations.restore_database(str(archive), "postgresql://restore:password@db.example:5432/soc")
