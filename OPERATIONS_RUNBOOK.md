# CyberGuard Operations Runbook

## Production services

Use `docker-compose.prod.yml` for the backend, PostgreSQL, Redis, frontend, and scheduled worker. Set `CYBERGUARD_POSTGRES_PASSWORD`, `CYBERGUARD_JWT_SECRET`, and `CYBERGUARD_FRONTEND_ORIGINS` before startup. Use a URL-safe PostgreSQL password (letters, digits, `_`, or `-`) because Compose embeds it in the connection URL. The worker runs CVE synchronization; production backups must use PostgreSQL-native `pg_dump`/`pg_restore`, not the SQLite-only backup worker.

## AI and enrichment runtime

Render and Docker install `requirements-models.txt` for local pretrained image/audio inference and install Tesseract for image OCR. The model weights occupy about 0.72 GB on disk and need additional runtime memory; select a host sized for CPU inference. Keep `CYBERGUARD_ENABLE_PRETRAINED_MEDIA=true` only where both models are available, and verify the actual weights with `python check_models.py` or `GET /api/v1/models/status`. `CYBERGUARD_ENABLE_RDAP` and `CYBERGUARD_ENABLE_CT` control website-registration and Certificate Transparency lookups; these enrichments require outbound HTTPS access and report unavailable status when providers cannot be reached.

Run `verify_all.ps1` from the project root for backend tests, frontend lint/build, deployment configuration, dependency consistency, and model inference. Set `API_URL` and `CYBERGUARD_FRONTEND_URL` to include deployed API health and Playwright smoke checks. The default run labels unavailable deployment checks as `SKIP`; use `.\verify_all.ps1 -RequireDeploymentChecks` for a release gate that fails unless both deployed API health and the authenticated browser smoke test are configured and pass.

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

- Configure the Vercel project root directory as `cyberguard-frontend`. Use `npm ci`, `npm run build`, and `dist` for install, build, and output. The production build requires a public HTTPS `VITE_API_URL`; `cyberguard-frontend/.env.production` supplies the default Render URL. If Render assigned a different hostname, set the exact public API origin in Vercel and redeploy.
- Deploy the Render Blueprint from this repository so the `cyberguard-backend` service uses `rootDir: cyberguard-backend`, its backend requirements, and the `uvicorn main:app` start command. Set `CYBERGUARD_FRONTEND_ORIGINS` to the exact Vercel origin and `CYBERGUARD_PUBLIC_APP_URL` to that same origin.
- Verify `https://<render-host>/health` returns HTTP 200 with `{"status":"Active","system":"CYBERGUARD AI Engine v2.0"}`. A 404 indicates the hostname is not serving this backend/revision; a 5xx means the service is unhealthy and its Render deploy/runtime logs must be checked. Do not consider the frontend deployed successfully until its browser smoke test can reach this backend.
- The Vercel build intentionally fails when `VITE_API_URL` is missing, non-HTTPS, or points at loopback. Confirm the Vercel deployment is built from the latest repository revision; an old bundle can still contain hard-coded localhost API URLs.
- If the deployed bundle still contains `http://127.0.0.1:8000`, the Vercel project is serving an older deployment. Set the project Production `VITE_API_URL` to the current Render origin, deploy the latest `main` revision with the project root set to `cyberguard-frontend`, and verify the deployment's build log reports `vite build` from that revision. Do not edit the generated `dist` files or add a localhost fallback for production.
- After deployment, inspect the frontend HTML to find its current JavaScript asset and confirm that asset does not contain `127.0.0.1`, `localhost`, or a stale backend hostname. Then open the browser network panel and verify API requests target the configured Render origin. A frontend HTTP 200 alone is not sufficient.
- Set `CYBERGUARD_HEAD_ADMIN_USERNAME` and `CYBERGUARD_HEAD_ADMIN_PASSWORD` in Render to the credentials the operator will use. Keep both private; the password must be at least 16 characters. On backend startup the configured head-admin password is hashed and applied to that account.
- After updating Render or Vercel settings, redeploy both services. Run `verify_all.ps1` with `API_URL`, `CYBERGUARD_FRONTEND_URL`, `CYBERGUARD_HEAD_ADMIN_USERNAME`, and `CYBERGUARD_HEAD_ADMIN_PASSWORD` set in the local process environment. Never put administrator credentials in Vercel's `VITE_*` variables or share them in logs/chat.

## Incident response

High-impact prevention actions require a head administrator or SOC lead. Every provider action and database backup is written to the audit log. Provider integrations fail closed with HTTP 503 when required credentials are absent.
