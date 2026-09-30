# CyberGuard Operations Runbook

## Production services

Use `docker-compose.prod.yml` for the backend, PostgreSQL, Redis, frontend, and scheduled worker. Set `CYBERGUARD_POSTGRES_PASSWORD`, `CYBERGUARD_JWT_SECRET`, and `CYBERGUARD_FRONTEND_ORIGINS` before startup. Use a URL-safe PostgreSQL password (letters, digits, `_`, or `-`) because Compose embeds it in the connection URL. The worker runs CVE synchronization; production backups must use PostgreSQL-native `pg_dump`/`pg_restore`, not the SQLite-only backup worker.

## Health and monitoring

- `GET /` is the container health check.
- `GET /metrics` is a Prometheus-compatible public scrape endpoint.
- `GET /api/v1/system/production-readiness` reports configured integrations for a head administrator.
- `GET /api/v1/integrations/status` reports provider configuration without returning secrets.

## Backup and restore

```powershell
docker compose -f docker-compose.prod.yml exec postgres pg_dump -U cyberguard -d cyberguard -Fc -f /tmp/cyberguard.dump
docker compose -f docker-compose.prod.yml cp postgres:/tmp/cyberguard.dump C:\backups\cyberguard.dump
```

Backups must be copied to storage outside the application host and periodically restored in a separate environment.

## PostgreSQL

Production Compose configures `CYBERGUARD_DATABASE_URL` for its PostgreSQL service automatically. For an external PostgreSQL deployment, set the URL directly and install the backend requirements. Initialize the schema with:

```powershell
python migrate_postgres.py
```

The application uses PostgreSQL automatically when the URL starts with `postgresql://` or `postgres://`; otherwise it preserves the local SQLite mode. Use `pg_dump` and `pg_restore` for PostgreSQL backups. The SQLite backup utility intentionally refuses to operate against PostgreSQL.

## HTTPS and secrets

Terminate TLS at the reverse proxy or managed platform. Set `CYBERGUARD_ENV=production`, provide a unique `CYBERGUARD_JWT_SECRET` of at least 32 characters, set `CYBERGUARD_HEAD_ADMIN_USERNAME` and a unique `CYBERGUARD_HEAD_ADMIN_PASSWORD` of at least 16 characters, configure `CYBERGUARD_SESSION_TTL_MINUTES`, disable anonymous evaluation, and inject provider secrets through the platform secret manager. Login locks an account for five minutes after ten failed attempts by default; tune this with `CYBERGUARD_LOGIN_FAILURE_LIMIT` and `CYBERGUARD_LOGIN_FAILURE_WINDOW_SECONDS`. Production startup rejects missing authentication settings and does not seed demo analyst/admin accounts. Never commit `.env` or provider tokens.

## Vercel + Render login deployment

- Vercel production builds use `cyberguard-frontend/.env.production`, which points `VITE_API_URL` at `https://cyberguard-backend.onrender.com`. If the Render service has a different public hostname, set that exact URL as Vercel's `VITE_API_URL` and redeploy the frontend.
- Render must deploy the `cyberguard-backend` web service successfully. The API root must return HTTP 200 before frontend login can work; a Render 503 means the service is unavailable/asleep or its latest build/start failed, not that the username/password was rejected.
- Set Render `CYBERGUARD_FRONTEND_ORIGINS=https://teamsecure-gita-cyberguard.vercel.app` and `CYBERGUARD_PUBLIC_APP_URL` to the same URL.
- Set `CYBERGUARD_HEAD_ADMIN_USERNAME` and `CYBERGUARD_HEAD_ADMIN_PASSWORD` in Render to the credentials the operator will use. Keep both private; the password must be at least 16 characters. On backend startup the configured head-admin password is hashed and applied to that account.
- After updating Render or Vercel settings, redeploy both services. Verify the Render root and `/api/v1/auth/login` before testing the Vercel login form.

## Incident response

High-impact prevention actions require a head administrator or SOC lead. Every provider action and database backup is written to the audit log. Provider integrations fail closed with HTTP 503 when required credentials are absent.
