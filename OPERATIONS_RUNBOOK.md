# CyberGuard Operations Runbook

## Production services

Use `docker-compose.prod.yml` for the backend, frontend, and scheduled worker. The worker runs CVE synchronization and creates an online SQLite backup when `CYBERGUARD_BACKUP_PATH` is set.

## Health and monitoring

- `GET /` is the container health check.
- `GET /metrics` is a Prometheus-compatible public scrape endpoint.
- `GET /api/v1/system/production-readiness` reports configured integrations for a head administrator.
- `GET /api/v1/integrations/status` reports provider configuration without returning secrets.

## Backup and restore

```powershell
python backup_db.py backup C:\backups\cyberguard.backup.db
python backup_db.py restore C:\backups\cyberguard.backup.db
```

Backups must be copied to storage outside the application host and periodically restored in a separate environment.

## PostgreSQL

Set `CYBERGUARD_DATABASE_URL` to a PostgreSQL connection string and install the backend requirements. Initialize the schema with:

```powershell
python migrate_postgres.py
```

The application uses PostgreSQL automatically when the URL starts with `postgresql://` or `postgres://`; otherwise it preserves the local SQLite mode. Use `pg_dump` and `pg_restore` for PostgreSQL backups. The SQLite backup utility intentionally refuses to operate against PostgreSQL.

## HTTPS and secrets

Terminate TLS at the reverse proxy or managed platform. Set `CYBERGUARD_ENV=production`, provide a unique `CYBERGUARD_JWT_SECRET` of at least 32 characters, disable anonymous evaluation, and inject provider secrets through the platform secret manager. Never commit `.env` or provider tokens.

## Incident response

High-impact prevention actions require a head administrator or SOC lead. Every provider action and database backup is written to the audit log. Provider integrations fail closed with HTTP 503 when required credentials are absent.
