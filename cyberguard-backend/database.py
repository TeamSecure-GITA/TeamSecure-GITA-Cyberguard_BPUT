from __future__ import annotations

import os
import re
import sqlite3
from pathlib import Path
from typing import Any


class PostgresCursor:
    def __init__(self, cursor):
        self._cursor = cursor
        self._prefetched = None
        self.lastrowid = None

    def fetchone(self):
        if self._prefetched is not None:
            row, self._prefetched = self._prefetched, None
            return row
        return self._cursor.fetchone()

    def fetchall(self):
        if self._prefetched is not None:
            rows = [self._prefetched, *self._cursor.fetchall()]
            self._prefetched = None
            return rows
        return self._cursor.fetchall()

    def __getattr__(self, name):
        return getattr(self._cursor, name)


class PostgresConnection:
    def __init__(self, url: str):
        try:
            import psycopg
            from psycopg.rows import dict_row
        except ImportError as error:
            raise RuntimeError("PostgreSQL requires psycopg[binary]; install backend requirements before setting CYBERGUARD_DATABASE_URL") from error
        self._connection = psycopg.connect(url, row_factory=dict_row)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type:
            self._connection.rollback()
        else:
            self._connection.commit()
        self._connection.close()

    def execute(self, statement: str, parameters: tuple[Any, ...] = ()) -> PostgresCursor:
        pragma = re.fullmatch(r"PRAGMA table_info\((\w+)\)", statement.strip(), re.IGNORECASE)
        if pragma:
            statement = "SELECT column_name AS name FROM information_schema.columns WHERE table_name = %s ORDER BY ordinal_position"
            parameters = (pragma.group(1),)
        normalized = _postgresql_statement(statement)
        cursor = PostgresCursor(self._connection.cursor())
        if normalized.lstrip().upper().startswith("INSERT INTO ") and "RETURNING" not in normalized.upper() and re.search(r"INSERT INTO (incidents|access_requests)\b", normalized, re.IGNORECASE):
            normalized += " RETURNING id"
        cursor._cursor.execute(normalized, parameters)
        if normalized.upper().endswith("RETURNING ID"):
            row = cursor._cursor.fetchone()
            cursor.lastrowid = row["id"] if row else None
        return cursor

    def executemany(self, statement: str, parameters):
        self._connection.cursor().executemany(_postgresql_statement(statement), parameters)

    def executescript(self, script: str):
        for statement in script.split(";"):
            if statement.strip():
                self.execute(statement)


def _postgresql_statement(statement: str) -> str:
    converted = statement.replace("?", "%s")
    converted = re.sub(r"INTEGER PRIMARY KEY AUTOINCREMENT", "BIGSERIAL PRIMARY KEY", converted, flags=re.IGNORECASE)
    converted = re.sub(r"INSERT\s+OR\s+IGNORE\s+INTO", "INSERT INTO", converted, flags=re.IGNORECASE)
    if re.match(r"^\s*INSERT INTO", converted, re.IGNORECASE) and "ON CONFLICT" not in converted.upper():
        converted = converted.rstrip() + " ON CONFLICT DO NOTHING"
    return converted


def connect_database(path: Path):
    database_url = os.getenv("CYBERGUARD_DATABASE_URL", "").strip()
    if database_url.startswith(("postgresql://", "postgres://")):
        return PostgresConnection(database_url)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    return connection


def database_backend() -> str:
    return "postgresql" if os.getenv("CYBERGUARD_DATABASE_URL", "").strip().startswith(("postgresql://", "postgres://")) else "sqlite"
