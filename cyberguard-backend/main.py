import ast
import hashlib
import html
import json
import os
import re
import secrets
import sqlite3
import sys
import smtplib
import time
import base64
from email.message import EmailMessage

try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
except ImportError:
    pass

# Auto-detect and switch to local .venv if run with system python lacking fastapi/uvicorn
try:
    import fastapi  # noqa: F401
    import uvicorn  # noqa: F401
except ImportError:
    backend_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(backend_dir, ".venv", "bin", "python3"),
        os.path.join(backend_dir, ".venv", "Scripts", "python.exe"),
        os.path.join(backend_dir, "venv", "bin", "python3"),
        os.path.join(backend_dir, "venv", "Scripts", "python.exe"),
        os.path.join(os.path.dirname(backend_dir), ".venv", "bin", "python3"),
        os.path.join(os.path.dirname(backend_dir), ".venv", "Scripts", "python.exe"),
    ]
    venv_python = next((p for p in candidates if os.path.exists(p)), None)
    if venv_python and sys.executable != venv_python:
        os.execv(venv_python, [venv_python] + sys.argv)

from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import requests
import jwt
from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Query, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from webauthn import generate_authentication_options, generate_registration_options, options_to_json, verify_authentication_response, verify_registration_response
from webauthn.helpers.structs import PublicKeyCredentialDescriptor, UserVerificationRequirement

from detection_engine import TEXT_MODEL, adversarial_self_test, evaluate_threat_payload
from battle_simulator import run_battle
from campaign_engine import correlate_incident
from digital_twin import build_twin
from forecast_engine import forecast_risk
from media_engine import analyze_media
from psychology_detector import analyze_psychology
from response_simulator import simulate_response
from self_healing import recommend_healing
from threat_intel import enrich_iocs, extract_iocs
from threat_fusion import (
    alert_quality_report,
    build_genome,
    compute_drift_snapshot,
    detect_memory_hits,
    generate_attacker_intent,
    record_alert_outcome as fusion_record_alert_outcome,
    score_explainability,
    serialize_genome,
)
from timeline_engine import build_timeline
from extended_intel import analyze_trust_media, build_global_threat_map, build_identity_heatmap, inspect_indicator, scan_payload
from frontier_engine import agent_consensus, assess_analyst_load, assess_neuromorphic_telemetry, assess_q_state, assess_satellite_link, build_cognitive_echo, cognitive_deception_session, frontier_overview, morph_topology, predict_threat_physics, static_artifact_analysis
from advanced_defense_engine import acoustic_channel, counter_agent_proxy, dark_mesh_schedule, hallucinated_infrastructure, heartbeat_keying, polymorphism_plan, quantum_decoy, space_weather_correlation, temporal_healing, vaccine_recommendations
from speculative_defense_engine import chrono_causal_trap, cognitive_poisoning, holographic_memory, hyperbolic_network, phase_change_zeroization, photonic_bus, plasma_channel, singularity_sinkhole, software_apoptosis, speculative_overview, vacuum_keying
from cloudflare_waf import block_ip as cloudflare_block_ip, configuration as cloudflare_configuration
from roadmap_features import analyst_bias_report, attention_heatmap, attacker_resource_cost, breach_economics, compliance_diff, counterfactual_replay, cross_modal_consistency, jurisdiction_route, seed_honeytokens, shared_immunity
from provider_integrations import deploy_honeytokens, integration_status as provider_integration_status, publish_tenant_signatures, sync_cve_feed
from prevention_engine import (
    campaign_aware_prevention,
    containment_action_plan,
    cross_channel_prevention_score,
    deception_trigger_check,
    identity_trust_evaluation,
    insider_threat_risk,
    policy_aware_prevention,
    risk_aware_prevention_decision,
)
from production_integrations import IntegrationNotConfigured, create_ticket, disable_identity, isolate_endpoint, provider_status
from operations import backup_database, prometheus_metrics
from database import connect_database, database_backend
from account_rescue_engine import blast_radius, consent_record, contact_warning_draft, evidence_snapshot, fleet_summary, guardian_contact, guardian_watch, lockdown_plan, locked_out_recovery, offline_rescue_card, provider_capabilities, rescue_plan, rescue_report, rescue_simulation, rollback_record, scan_account, execute_step
from models import AccessRequestCreate, AdvancedTelemetryRequest, AgentConsensusRequest, AlertRequest, AnalystLoadRequest, BattleRequest, CognitiveEchoRequest, DarkMeshRequest, DeceptionRequest, ForecastRequest, IncidentComment, IncidentUpdate, InfrastructureEchoRequest, LoginRequest, NeuromorphicRequest, NotificationUpdate, OtpVerificationRequest, PasskeyCredentialRequest, PermissionRequest, PolymorphismRequest, PsychologyRequest, QStateRequest, QuantumDecoyRequest, ResponseExecutionRequest, SatelliteRequest, ScannerRequest, SimulationRequest, SpeculativeTelemetryRequest, TemporalHealingRequest, ThreatAnalysisRequest, ThreatIntelLookup, TopologyMorphRequest, ThreatPhysicsRequest, UserCreate, VaccineRequest

DB_PATH = Path(os.getenv("CYBERGUARD_DB_PATH", str(Path(__file__).with_name("cyberguard.db"))))
CYBERGUARD_ENV = os.getenv("CYBERGUARD_ENV", "development").lower()
JWT_SECRET = os.getenv("CYBERGUARD_JWT_SECRET", "development-only-change-me-use-a-long-secret-key")
if CYBERGUARD_ENV in {"production", "prod"} and (len(JWT_SECRET) < 32 or JWT_SECRET.startswith("development-only")):
    raise RuntimeError("CYBERGUARD_JWT_SECRET must be a unique secret of at least 32 characters in production")
JWT_ALGORITHM = "HS256"
JWT_TTL_MINUTES = max(5, int(os.getenv("CYBERGUARD_JWT_TTL_MINUTES", "30")))
SECURITY_OWNER_EMAIL = os.getenv("CYBERGUARD_SECURITY_OWNER_EMAIL", "teamsecure.project@gmail.com")
PUBLIC_APP_URL = os.getenv("CYBERGUARD_PUBLIC_APP_URL", "http://127.0.0.1:5173")
ACCESS_REQUEST_TTL_HOURS = max(1, int(os.getenv("CYBERGUARD_ACCESS_REQUEST_TTL_HOURS", "24")))
HEAD_ADMIN_USERNAME = os.getenv("CYBERGUARD_HEAD_ADMIN_USERNAME", "teamsecure.project@gmail.com")
HEAD_ADMIN_PASSWORD = os.getenv("CYBERGUARD_HEAD_ADMIN_PASSWORD", "Secure@9040")
STARTED_AT = datetime.now(timezone.utc)
SECURITY_EVENT_WINDOW: dict[str, list[float]] = {}
OTP_CHALLENGES: dict[str, dict[str, Any]] = {}
OTP_TTL_SECONDS = max(60, int(os.getenv("CYBERGUARD_OTP_TTL_SECONDS", "300")))
OTP_MAX_ATTEMPTS = max(3, int(os.getenv("CYBERGUARD_OTP_MAX_ATTEMPTS", "5")))
PASSKEY_RP_ID = os.getenv("CYBERGUARD_PASSKEY_RP_ID", "127.0.0.1")
PASSKEY_ORIGIN = os.getenv("CYBERGUARD_PASSKEY_ORIGIN", "http://127.0.0.1:5173")
PASSKEY_CHALLENGES: dict[str, dict[str, Any]] = {}
DEMO_SCENARIOS = [
    {
        "id": "deepfake-authority",
        "name": "Deepfake Authority Message",
        "category": "deepfake",
        "payload": "Voice clone of the finance director uses synthetic speech to request an urgent transfer.",
    },
    {
        "id": "behavioral-ato",
        "name": "Behavioural Account Takeover",
        "category": "ato",
        "payload": json.dumps({"failed_attempts": 12, "total_attempts": 15, "distinct_accounts": 8, "distinct_countries": 2, "impossible_travel": True, "new_device": True, "mfa_denials": 4}),
    },
    {
        "id": "url-impersonation",
        "name": "Look-alike URL and Contact Mismatch",
        "category": "url",
        "payload": "From: registrar@gmail.com urgently verify at https://micros0ft-login.xyz/auth?redirect=https://evil.example/login",
    },
]

DHCP_LEASES = {
    "192.168.1.10": {"mac": "00:1A:2B:3C:4D:5E", "hostname": "Admin-Workstation", "device_type": "corporate-laptop"},
    "192.168.1.25": {"mac": "A1:B2:C3:D4:E5:F6", "hostname": "Finance-Server", "device_type": "server"},
    "192.168.1.42": {"mac": "88:77:66:55:44:33", "hostname": "Faculty-Laptop", "device_type": "corporate-laptop"},
    "192.168.1.99": {"mac": "74:E1:B2:8F:44:9A", "hostname": "Unknown-Kali-Linux", "device_type": "untrusted-host"},
    "0.0.0.0": {"mac": "UNKNOWN", "hostname": "Untracked-Device", "device_type": "unknown"},
}

IDP_USER_REGISTRY = {
    "user_admin": {"name": "Amit Sharma", "role": "Network Administrator", "status": "ACTIVE", "password": "admin123"},
    "user_faculty": {"name": "Dr. Mishra", "role": "Professor", "status": "ACTIVE", "password": "faculty123"},
    "user_student": {"name": "Rohan Das", "role": "Student", "status": "SUSPENDED", "password": "student123"},
}

SIEM_EVENT_STORE: list[dict] = []
RATE_LIMIT_WINDOW_SECONDS = max(10, int(os.getenv("CYBERGUARD_RATE_LIMIT_WINDOW_SECONDS", "60")))
RATE_LIMIT_MAX_REQUESTS = max(30, int(os.getenv("CYBERGUARD_RATE_LIMIT_MAX_REQUESTS", "120")))
RATE_LIMIT_STORE: dict[str, list[float]] = {}
HTTP_REQUEST_COUNT = 0
HTTP_ERROR_COUNT = 0


def get_db():
    return connect_database(DB_PATH)


def correlate_dhcp_ip(source_ip: str) -> dict:
    normalized_ip = str(source_ip or "0.0.0.0").strip()
    lease = DHCP_LEASES.get(normalized_ip)
    if lease:
        return lease
    return {"mac": "UNKNOWN", "hostname": "Untracked-Device", "device_type": "unknown"}


def normalize_severity(severity: str) -> str:
    value = (severity or "LOW").upper()
    return value if value in {"LOW", "MEDIUM", "HIGH", "CRITICAL"} else "MEDIUM"


def siem_ingest_event(payload: dict | None, user: dict[str, str] | None = None):
    if user is None:
        user = {"username": "system", "role": "lead"}
    data = payload or {}
    source_ip = str(data.get("source_ip") or "0.0.0.0")
    event_type = str(data.get("event_type") or "System Access")
    severity = normalize_severity(str(data.get("severity") or "LOW"))
    details = str(data.get("details") or "SIEM event ingested")
    timestamp = datetime.now(timezone.utc).isoformat()
    device_info = correlate_dhcp_ip(source_ip)
    hostname = str(data.get("source_host") or device_info.get("hostname") or "Untracked-Device")
    log_entry = {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "source_host": hostname,
        "mac_address": device_info.get("mac", "UNKNOWN"),
        "hostname": hostname,
        "event": event_type,
        "severity": severity,
        "details": details,
    }
    with get_db() as db:
        db.execute(
            "INSERT INTO siem_events (timestamp, source_ip, source_host, mac_address, hostname, event, severity, details) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (log_entry["timestamp"], source_ip, log_entry["source_host"], log_entry["mac_address"], hostname, event_type, severity, details),
        )

    if severity == "CRITICAL" or "kali" in hostname.lower() or "unknown" in hostname.lower():
        action_taken = f"ALERT: SIEM triggered DHCP isolation protocol. Cutting network lease for {hostname}."
        threat_status = "CRITICAL"
    elif severity in {"HIGH", "MEDIUM"}:
        action_taken = "Log ingested and indexed. Device is under monitoring."
        threat_status = "HIGH" if severity == "HIGH" else "MEDIUM"
    else:
        action_taken = "Log ingested and indexed cleanly."
        threat_status = "LOW"

    return {
        "message": "SIEM processing complete",
        "correlated_log": log_entry,
        "system_response": action_taken,
        "threat_level": threat_status,
        "user": user.get("username", "unknown"),
    }


def read_siem_events(user: dict[str, str] | None = None):
    if user is None:
        user = {"username": "system", "role": "lead"}
    with get_db() as db:
        events = [dict(row) for row in db.execute("SELECT timestamp, source_ip, source_host, mac_address, hostname, event, severity, details FROM siem_events ORDER BY id DESC LIMIT 20").fetchall()]
    high_risk = [event for event in events if event["severity"] in {"HIGH", "CRITICAL"}]
    return {"events": events, "count": len(events), "high_risk_count": len(high_risk), "user": user.get("username", "unknown")}


def idp_authenticate_user(payload: dict | None, user: dict[str, str] | None = None):
    if user is None:
        user = {"username": "system", "role": "lead"}
    data = payload or {}
    username = str(data.get("username") or "")
    password = str(data.get("password") or "")
    source_ip = str(data.get("source_ip") or "0.0.0.0")
    requested_app = str(data.get("service_provider_app") or "Main Dashboard")

    profile = IDP_USER_REGISTRY.get(username)
    if not profile:
        return {"auth_status": "DENIED", "reason": "User identity record not found in IdP database."}

    if profile["status"] == "SUSPENDED":
        return {"auth_status": "DENIED", "user": profile["name"], "reason": "Account quarantined automatically due to active security event alerts."}

    if profile["password"] != password:
        return {"auth_status": "DENIED", "user": profile["name"], "reason": "Invalid credentials for IdP authentication."}

    hardware_context = correlate_dhcp_ip(source_ip)
    suspicious_ip = source_ip in DHCP_LEASES and DHCP_LEASES[source_ip].get("hostname") == "Unknown-Kali-Linux"
    suspicious_event = any(
        event["source_ip"] == source_ip or event["hostname"] == hardware_context.get("hostname")
        for event in SIEM_EVENT_STORE
    )

    if suspicious_ip or suspicious_event:
        return {
            "auth_status": "BLOCKED",
            "user": profile["name"],
            "reason": "Risk engine flagged this asset or IP as compromised. IdP policy blocked the session.",
            "alert": "CRITICAL RISK: authentication attempt blocked from untrusted hardware asset or malicious SIEM event.",
        }

    if profile["role"] == "Network Administrator" and hardware_context.get("hostname") != "Admin-Workstation":
        return {
            "auth_status": "BLOCKED",
            "user": profile["name"],
            "reason": "Hardware mismatch detected against IdP governance rules.",
            "alert": "CRITICAL RISK: Admin login attempted from unauthorized hardware asset. Triggering threat notification.",
        }

    return {
        "auth_status": "SUCCESS",
        "identity_verified": {
            "name": profile["name"],
            "role": profile["role"],
            "hardware_bound": hardware_context.get("hostname", "Untracked-Device"),
            "mac_address": hardware_context.get("mac", "UNKNOWN"),
            "requested_app": requested_app,
        },
        "message": f"Single Sign-On (SSO) token issued cleanly for {requested_app}.",
    }


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def initialize_database():
    with get_db() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                email TEXT NOT NULL DEFAULT '',
                parent_username TEXT,
                status TEXT NOT NULL DEFAULT 'active'
            );
            CREATE TABLE IF NOT EXISTS passkeys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                credential_id TEXT NOT NULL UNIQUE,
                public_key TEXT NOT NULL,
                sign_count INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                category TEXT NOT NULL,
                payload TEXT NOT NULL,
                filename TEXT,
                file_hash TEXT,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                assessment TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT NOT NULL,
                action_id TEXT NOT NULL,
                target TEXT NOT NULL,
                username TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                severity TEXT NOT NULL,
                read INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                action TEXT NOT NULL,
                resource TEXT NOT NULL,
                details TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS threat_fingerprints (
                incident_id INTEGER PRIMARY KEY,
                fingerprint TEXT NOT NULL,
                genome_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS campaigns (
                campaign_id TEXT PRIMARY KEY,
                confidence INTEGER NOT NULL,
                stage TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS campaign_incidents (
                campaign_id TEXT NOT NULL,
                incident_id INTEGER NOT NULL,
                score INTEGER NOT NULL,
                PRIMARY KEY (campaign_id, incident_id)
            );
            CREATE TABLE IF NOT EXISTS incident_timelines (
                incident_id INTEGER NOT NULL,
                event_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS threat_forecasts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER,
                forecast_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS response_simulations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER,
                simulation_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS network_nodes (
                node_id TEXT PRIMARY KEY,
                label TEXT NOT NULL,
                kind TEXT NOT NULL,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS network_edges (
                source TEXT NOT NULL,
                target TEXT NOT NULL,
                relationship TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (source, target)
            );
            CREATE TABLE IF NOT EXISTS battle_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                defender_actions_json TEXT NOT NULL,
                result_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS permission_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                permission TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                requested_at TEXT NOT NULL,
                decided_by TEXT,
                decided_at TEXT
            );
            CREATE TABLE IF NOT EXISTS access_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                name TEXT NOT NULL DEFAULT '',
                purpose TEXT NOT NULL DEFAULT '',
                request_token_hash TEXT NOT NULL UNIQUE,
                approval_token_hash TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL DEFAULT 'pending',
                requested_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                decided_at TEXT,
                decided_by TEXT
            );
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                path TEXT NOT NULL,
                details TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS siem_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                source_host TEXT NOT NULL,
                mac_address TEXT NOT NULL,
                hostname TEXT NOT NULL,
                event TEXT NOT NULL,
                severity TEXT NOT NULL,
                details TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS blocked_ips (
                ip_address TEXT PRIMARY KEY,
                reason TEXT NOT NULL,
                blocked_at TEXT NOT NULL,
                expires_at TEXT
            );
            """
        )
        user_columns = {row["name"] for row in db.execute("PRAGMA table_info(users)").fetchall()}
        if "email" not in user_columns:
            db.execute("ALTER TABLE users ADD COLUMN email TEXT NOT NULL DEFAULT ''")
        if "parent_username" not in user_columns:
            db.execute("ALTER TABLE users ADD COLUMN parent_username TEXT")
        if "status" not in user_columns:
            db.execute("ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'active'")
        columns = {row["name"] for row in db.execute("PRAGMA table_info(incidents)").fetchall()}
        if "status" not in columns:
            db.execute("ALTER TABLE incidents ADD COLUMN status TEXT NOT NULL DEFAULT 'New'")
        if "assigned_to" not in columns:
            db.execute("ALTER TABLE incidents ADD COLUMN assigned_to TEXT")
        if "notes" not in columns:
            db.execute("ALTER TABLE incidents ADD COLUMN notes TEXT NOT NULL DEFAULT ''")
        users = [
            ("analyst", hash_password("analyst123"), "analyst", "", None, "active"),
            ("lead", hash_password("lead123"), "lead", "", None, "active"),
            ("admin", hash_password("admin123"), "admin", SECURITY_OWNER_EMAIL, HEAD_ADMIN_USERNAME, "active"),
            (HEAD_ADMIN_USERNAME, hash_password(HEAD_ADMIN_PASSWORD), "head_admin", SECURITY_OWNER_EMAIL, None, "active"),
        ]
        db.executemany("INSERT OR IGNORE INTO users (username, password_hash, role, email, parent_username, status) VALUES (?, ?, ?, ?, ?, ?)", users)


@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_database()
    yield


app = FastAPI(
    title="CYBERGUARD AI Cyber Defense API",
    description="Threat detection, risk scoring, XAI, persistence, and response automation",
    version="2.0.0",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        origin.strip()
        for origin in os.getenv(
            "CYBERGUARD_FRONTEND_ORIGINS",
            "http://127.0.0.1:5173,http://localhost:5173,http://127.0.0.1:5174,http://localhost:5174,http://127.0.0.1:5175,http://localhost:5175,http://127.0.0.1:3000,http://localhost:3000,http://127.0.0.1:8000,http://localhost:8000",
        ).split(",")
        if origin.strip()
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_guard(request: Request, call_next):
    global HTTP_REQUEST_COUNT, HTTP_ERROR_COUNT
    HTTP_REQUEST_COUNT += 1
    if request.method.upper() == "OPTIONS":
        return await call_next(request)
    ip_address = request_ip(request)
    path = request.url.path.lower()
    now = time.time()
    with get_db() as db:
        blocked = db.execute("SELECT ip_address FROM blocked_ips WHERE ip_address = ?", (ip_address,)).fetchone()
    if blocked and ip_address not in {"127.0.0.1", "::1", "localhost"}:
        return JSONResponse(status_code=403, content={"detail": "Access denied by CyberGuard security controls", "containment": "internal sinkhole preview"})
    request_times = RATE_LIMIT_STORE.setdefault(ip_address, [])
    RATE_LIMIT_STORE[ip_address] = [stamp for stamp in request_times if now - stamp < RATE_LIMIT_WINDOW_SECONDS]
    if len(RATE_LIMIT_STORE[ip_address]) >= RATE_LIMIT_MAX_REQUESTS:
        record_security_event("rate-limit-exceeded", ip_address, request.url.path, "Request rate exceeded configured limit.")
        return JSONResponse(status_code=429, content={"detail": "Request rate limit exceeded"}, headers={"Retry-After": str(RATE_LIMIT_WINDOW_SECONDS)})
    RATE_LIMIT_STORE[ip_address].append(now)
    suspicious = any(marker in path for marker in ("/.env", "/.git", "/wp-admin", "/wp-login", "/etc/passwd", "/debug", "/phpmyadmin"))
    attempts = SECURITY_EVENT_WINDOW.setdefault(ip_address, [])
    SECURITY_EVENT_WINDOW[ip_address] = [stamp for stamp in attempts if now - stamp < 60]
    if suspicious:
        SECURITY_EVENT_WINDOW[ip_address].append(now)
        record_security_event("suspicious-code-or-admin-probe", ip_address, request.url.path, "Protected path probing detected.")
        if len(SECURITY_EVENT_WINDOW[ip_address]) >= 3 and ip_address not in {"127.0.0.1", "::1", "localhost"}:
            with get_db() as db:
                db.execute("INSERT INTO blocked_ips (ip_address, reason, blocked_at) VALUES (?, ?, ?) ON CONFLICT (ip_address) DO UPDATE SET reason = excluded.reason, blocked_at = excluded.blocked_at", (ip_address, "Repeated protected-path probing", datetime.now(timezone.utc).isoformat()))
            return JSONResponse(status_code=403, content={"detail": "IP blocked by CyberGuard", "containment": "internal sinkhole preview"})
    response = await call_next(request)
    if response.status_code >= 400:
        HTTP_ERROR_COUNT += 1
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.url.scheme == "https" or CYBERGUARD_ENV in {"production", "prod"}:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


def current_user(authorization: Optional[str] = Header(default=None)) -> dict[str, str]:
    if not authorization or not authorization.startswith("Bearer "):
        if os.getenv("CYBERGUARD_ALLOW_ANONYMOUS_EVAL", "false").lower() in {"true", "1", "yes"}:
            return {"username": "evaluator", "role": "lead"}
        raise HTTPException(status_code=401, detail="Authentication required")
    try:
        claims = jwt.decode(authorization.removeprefix("Bearer "), JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if not claims.get("username") or not claims.get("role"):
            raise HTTPException(status_code=401, detail="Invalid session claims")
        return claims
    except jwt.PyJWTError as error:
        if os.getenv("CYBERGUARD_ALLOW_ANONYMOUS_EVAL", "false").lower() in {"true", "1", "yes"}:
            return {"username": "evaluator", "role": "lead"}
        raise HTTPException(status_code=401, detail="Invalid or expired session") from error


def request_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    return forwarded or (request.client.host if request.client else "unknown")


def send_security_notice(subject: str, details: str):
    return send_email(SECURITY_OWNER_EMAIL, f"CyberGuard security alert: {subject}", details)


def send_email(recipient: str, subject: str, details: str):
    smtp_host = os.getenv("CYBERGUARD_SMTP_HOST")
    smtp_port = int(os.getenv("CYBERGUARD_SMTP_PORT", "587"))
    smtp_user = os.getenv("CYBERGUARD_SMTP_USER")
    smtp_password = os.getenv("CYBERGUARD_SMTP_PASSWORD")
    if not smtp_host or not smtp_user or not smtp_password:
        return None
    message = EmailMessage()
    message["From"] = smtp_user
    message["To"] = recipient
    message["Subject"] = subject
    message.set_content(details)
    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=8) as server:
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.send_message(message)
        return True
    except (OSError, smtplib.SMTPException):
        return False


def issue_admin_otp(username: str, recipient: str) -> dict[str, str]:
    otp = f"{secrets.randbelow(1_000_000):06d}"
    challenge_id = secrets.token_urlsafe(24)
    OTP_CHALLENGES[challenge_id] = {
        "username": username,
        "otp_hash": hashlib.sha256(otp.encode("utf-8")).hexdigest(),
        "expires_at": time.time() + OTP_TTL_SECONDS,
        "attempts": 0,
    }
    sent = send_email(
        recipient,
        "CyberGuard administrator verification code",
        f"Your CyberGuard administrator verification code is {otp}. It expires in {OTP_TTL_SECONDS // 60} minutes. If you did not request this, ignore this message.",
    )
    if sent is None:
        OTP_CHALLENGES.pop(challenge_id, None)
        raise HTTPException(status_code=503, detail="OTP email is not configured. Add CYBERGUARD_SMTP_HOST, CYBERGUARD_SMTP_USER, and CYBERGUARD_SMTP_PASSWORD to cyberguard-backend/.env.")
    if not sent:
        OTP_CHALLENGES.pop(challenge_id, None)
        raise HTTPException(status_code=503, detail="OTP email could not be delivered. Check the SMTP host, port, username, and app password.")
    return {"challenge_id": challenge_id, "masked_email": f"{recipient[:2]}***@{recipient.split('@', 1)[-1]}"}


def issue_session(user: sqlite3.Row) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    token = jwt.encode({"username": user["username"], "role": user["role"], "iat": int(now.timestamp()), "exp": int((now + timedelta(minutes=JWT_TTL_MINUTES)).timestamp())}, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return {"access_token": token, "token_type": "bearer", "user": {"username": user["username"], "role": user["role"]}}


def passkey_options(username: str) -> dict[str, Any]:
    with get_db() as db:
        credentials = db.execute("SELECT credential_id FROM passkeys WHERE username = ?", (username,)).fetchall()
    challenge_id = secrets.token_urlsafe(24)
    if credentials:
        options = generate_authentication_options(
            rp_id=PASSKEY_RP_ID,
            allow_credentials=[PublicKeyCredentialDescriptor(id=base64.urlsafe_b64decode(row["credential_id"] + "=" * (-len(row["credential_id"]) % 4))) for row in credentials],
            user_verification=UserVerificationRequirement.PREFERRED,
        )
        kind = "authentication"
    else:
        options = generate_registration_options(
            rp_id=PASSKEY_RP_ID,
            rp_name="CyberGuard Operations Center",
            user_name=username,
            user_id=username.encode("utf-8"),
            user_display_name="CyberGuard Administrator",
        )
        kind = "registration"
    PASSKEY_CHALLENGES[challenge_id] = {"username": username, "kind": kind, "challenge": options.challenge, "expires_at": time.time() + 300}
    return {"challenge_id": challenge_id, "kind": kind, "options": json.loads(options_to_json(options))}


def record_security_event(event_type: str, ip_address: str, path: str, details: str):
    with get_db() as db:
        db.execute("INSERT INTO security_events (event_type, ip_address, path, details, created_at) VALUES (?, ?, ?, ?, ?)", (event_type, ip_address, path, details, datetime.now(timezone.utc).isoformat()))
    send_security_notice(event_type, f"IP: {ip_address}\nPath: {path}\n{details}")


def hash_access_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def access_request_row(token: str):
    with get_db() as db:
        return db.execute("SELECT * FROM access_requests WHERE request_token_hash = ?", (hash_access_token(token),)).fetchone()


def access_request_state(row):
    if not row:
        raise HTTPException(status_code=404, detail="Access request not found")
    if row["status"] == "pending" and datetime.fromisoformat(row["expires_at"]) < datetime.now(timezone.utc):
        with get_db() as db:
            db.execute("UPDATE access_requests SET status = 'expired' WHERE id = ?", (row["id"],))
        return "expired"
    return row["status"]


def head_admin_user(request: Request, user: dict[str, str] = Depends(current_user)) -> dict[str, str]:
    if user.get("role") != "head_admin" or user.get("username") != HEAD_ADMIN_USERNAME:
        record_security_event("unauthorized-head-admin-access", request_ip(request), request.url.path, f"User {user.get('username', 'unknown')} attempted a head-admin action.")
        raise HTTPException(status_code=403, detail="Head Administrator approval required")
    return user


def admin_user(request: Request, user: dict[str, str] = Depends(current_user)) -> dict[str, str]:
    if user.get("role") != "head_admin" or user.get("username") != HEAD_ADMIN_USERNAME:
        record_security_event("unauthorized-admin-access", request_ip(request), request.url.path, f"User {user.get('username', 'unknown')} attempted an admin action.")
        raise HTTPException(status_code=403, detail="Administrator role required")
    return user


def store_incident(category: str, payload: str, assessment: dict, filename: str | None = None, file_hash: str | None = None):
    with get_db() as db:
        cursor = db.execute(
            "INSERT INTO incidents (category, payload, filename, file_hash, risk_score, risk_level, assessment, created_at, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (category, payload, filename, file_hash, assessment["risk_score"], assessment["risk_level"], json.dumps(assessment), datetime.now(timezone.utc).isoformat(), "Investigating" if assessment["risk_level"] in ["High", "Critical"] else "New"),
        )
        return cursor.lastrowid


def write_audit(user: dict[str, str], action: str, resource: str, details: str):
    with get_db() as db:
        db.execute("INSERT INTO audit_logs (username, action, resource, details, created_at) VALUES (?, ?, ?, ?, ?)", (user["username"], action, resource, details, datetime.now(timezone.utc).isoformat()))


def create_notification(username: str, title: str, message: str, severity: str):
    with get_db() as db:
        db.execute("INSERT INTO notifications (username, title, message, severity, created_at) VALUES (?, ?, ?, ?, ?)", (username, title, message, severity, datetime.now(timezone.utc).isoformat()))


def incident_context(incident_id: int) -> dict:
    with get_db() as db:
        row = db.execute("SELECT id, category, payload, risk_score, risk_level, assessment, created_at FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found")
    try:
        assessment = json.loads(row["assessment"])
    except json.JSONDecodeError:
        assessment = ast.literal_eval(row["assessment"])
    return {**dict(row), "assessment": assessment}


def recent_incident_context() -> list[dict]:
    with get_db() as db:
        rows = db.execute("SELECT id, category, payload, risk_score, risk_level, assessment, created_at FROM incidents ORDER BY id DESC LIMIT 100").fetchall()
    result = []
    for row in rows:
        try:
            assessment = json.loads(row["assessment"])
        except json.JSONDecodeError:
            assessment = ast.literal_eval(row["assessment"])
        result.append({**dict(row), "assessment": assessment})
    return result


def fatigue_routing(incidents: list[dict], analysts: list[dict]) -> dict:
    analyst_capacity = {}
    for analyst in analysts:
        role = str(analyst.get("role") or "analyst").lower()
        if role in {"lead", "sub_admin", "admin", "head_admin"}:
            analyst_capacity[analyst.get("username", f"{role}-{len(analyst_capacity)+1}")] = 1.0
        else:
            analyst_capacity[analyst.get("username", f"analyst-{len(analyst_capacity)+1}")] = 0.75

    queue = []
    for incident in incidents:
        risk = int(incident.get("risk_score", 0) or 0)
        status = str(incident.get("status") or "New")
        assigned = incident.get("assigned_to")
        if assigned and assigned in analyst_capacity:
            current_load = analyst_capacity[assigned]
            route_target = assigned
        else:
            target = min(analyst_capacity, key=lambda name: (analyst_capacity[name], name))
            route_target = target
            analyst_capacity[target] = min(1.4, analyst_capacity[target] + 0.25)
        queue.append({
            "incident_id": incident.get("database_id") or incident.get("id"),
            "risk_score": risk,
            "status": status,
            "target": route_target,
            "priority": "critical" if risk >= 85 else "high" if risk >= 65 else "medium",
            "copilot_load": round(analyst_capacity.get(route_target, 0.75), 2),
        })

    queue.sort(key=lambda item: (-item["risk_score"], item["copilot_load"]))
    route_summary = {
        "available_analysts": len(analysts),
        "alert_count": len(queue),
        "high_priority": sum(1 for item in queue if item["priority"] in {"critical", "high"}),
        "avg_load": round(sum(item["copilot_load"] for item in queue) / max(len(queue), 1), 2),
    }
    return {"recommended_queue": queue, "route_summary": route_summary}


def incident_intent(incident_id: int, user: dict[str, str] | None = None) -> dict:
    incident = incident_context(incident_id)
    related = [item for item in recent_incident_context() if item["id"] != incident_id]
    return generate_attacker_intent(incident, related)


def incident_drift(incident_id: int, user: dict[str, str] | None = None) -> dict:
    incident = incident_context(incident_id)
    related = [item for item in recent_incident_context() if item["id"] != incident_id]
    return compute_drift_snapshot(incident, related)


def incident_memory(incident_id: int, user: dict[str, str] | None = None) -> dict:
    incident = incident_context(incident_id)
    history = [item for item in recent_incident_context() if item["id"] != incident_id]
    return detect_memory_hits(incident.get("payload", ""), history)


def incident_explainability(incident_id: int, user: dict[str, str] | None = None) -> dict:
    incident = incident_context(incident_id)
    return score_explainability(incident)


def record_alert_outcome(incident_id: int, detection_type: str, alert_risk_score: int, final_resolution: str, reviewed_by: str = "analyst") -> dict:
    return fusion_record_alert_outcome(incident_id, detection_type, alert_risk_score, final_resolution, reviewed_by)


def alert_quality(user: dict[str, str] | None = None) -> dict:
    return alert_quality_report()


def persist_cyberguard_x(incident_id: int, incident: dict):
    genome = build_genome(incident)
    timeline = build_timeline(incident)
    related = recent_incident_context()
    campaign = correlate_incident(incident, [item for item in related if item["id"] != incident_id])
    with get_db() as db:
        now = datetime.now(timezone.utc).isoformat()
        db.execute("INSERT INTO threat_fingerprints (incident_id, fingerprint, genome_json, created_at) VALUES (?, ?, ?, ?) ON CONFLICT (incident_id) DO UPDATE SET fingerprint = excluded.fingerprint, genome_json = excluded.genome_json, created_at = excluded.created_at", (incident_id, genome["fingerprint"], serialize_genome(genome), now))
        db.execute("INSERT OR IGNORE INTO campaigns (campaign_id, confidence, stage, created_at) VALUES (?, ?, ?, ?)", (campaign["campaign_id"], campaign["confidence"], campaign["stage"], now))
        for match in campaign["related_incidents"]:
            db.execute("INSERT OR IGNORE INTO campaign_incidents (campaign_id, incident_id, score) VALUES (?, ?, ?)", (campaign["campaign_id"], match["incident_id"], match["score"]))
        db.execute("INSERT INTO campaign_incidents (campaign_id, incident_id, score) VALUES (?, ?, ?) ON CONFLICT DO NOTHING", (campaign["campaign_id"], incident_id, 100))
        db.executemany("INSERT INTO incident_timelines (incident_id, event_json, created_at) VALUES (?, ?, ?)", [(incident_id, json.dumps(event), now) for event in timeline])


@app.get("/")
def root():
    return {"status": "Active", "system": "CYBERGUARD AI Engine v2.0"}


@app.post("/api/v1/access/request")
def create_access_request(request: AccessRequestCreate):
    email = request.email.strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise HTTPException(status_code=400, detail="Enter a valid email address")
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(hours=ACCESS_REQUEST_TTL_HOURS)
    with get_db() as db:
        existing = db.execute("SELECT id, status, expires_at FROM access_requests WHERE email = ? ORDER BY id DESC LIMIT 1", (email,)).fetchone()
        if existing and existing["status"] == "pending" and datetime.fromisoformat(existing["expires_at"]) > now:
            raise HTTPException(status_code=409, detail="An access request for this email is already pending")
        request_token = secrets.token_urlsafe(32)
        approval_token = secrets.token_urlsafe(32)
        cursor = db.execute(
            "INSERT INTO access_requests (email, name, purpose, request_token_hash, approval_token_hash, requested_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (email, request.name.strip()[:120], request.purpose.strip()[:500], hash_access_token(request_token), hash_access_token(approval_token), now.isoformat(), expires_at.isoformat()),
        )
        request_id = cursor.lastrowid
    approval_url = f"{PUBLIC_APP_URL.rstrip('/')}/api/v1/access/approve?token={approval_token}"
    email_sent = send_email(
        SECURITY_OWNER_EMAIL,
        "CyberGuard access approval requested",
        f"A visitor requested CyberGuard access.\n\nEmail: {email}\nName: {request.name.strip() or 'Not provided'}\nPurpose: {request.purpose.strip() or 'Not provided'}\nRequest ID: {request_id}\n\nApprove access (valid for {ACCESS_REQUEST_TTL_HOURS} hours):\n{approval_url}\n",
    )
    return {"request_id": request_id, "request_token": request_token, "status": "pending", "expires_at": expires_at.isoformat(), "email_sent": email_sent}


@app.get("/api/v1/access/status")
def access_request_status(token: str = Query(..., min_length=20)):
    row = access_request_row(token)
    status = access_request_state(row)
    response = {"request_id": row["id"], "status": status, "expires_at": row["expires_at"]}
    if status == "approved":
        expires = datetime.now(timezone.utc) + timedelta(hours=8)
        username = f"guest:{row['email']}"
        response["access_token"] = jwt.encode({"username": username, "role": "analyst", "email": row["email"], "iat": int(datetime.now(timezone.utc).timestamp()), "exp": int(expires.timestamp())}, JWT_SECRET, algorithm="HS256")
        response["user"] = {"username": username, "role": "analyst", "email": row["email"]}
    return response


@app.get("/api/v1/access/approve", response_class=HTMLResponse)
def approve_access_request(token: str = Query(..., min_length=20)):
    with get_db() as db:
        row = db.execute("SELECT * FROM access_requests WHERE approval_token_hash = ?", (hash_access_token(token),)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Approval request not found")
        status = access_request_state(row)
        if status == "pending":
            db.execute("UPDATE access_requests SET status = 'approved', decided_at = ?, decided_by = ? WHERE id = ?", (datetime.now(timezone.utc).isoformat(), SECURITY_OWNER_EMAIL, row["id"]))
            status = "approved"
            send_email(row["email"], "CyberGuard access approved", "Your CyberGuard access request was approved. Return to the CyberGuard portal and select Check approval to continue.")
    safe_email = html.escape(row["email"])
    heading = "Access approved" if status == "approved" else f"Access request {html.escape(status)}"
    message = "The applicant can now return to the CyberGuard portal and check approval." if status == "approved" else "This approval link is no longer active."
    return HTMLResponse(f"<!doctype html><html><head><title>CyberGuard access</title></head><body style='font-family:Arial;background:#06111f;color:#e5f7ff;padding:48px'><h1>{heading}</h1><p>{message}</p><p>Applicant: {safe_email}</p></body></html>")


@app.get("/api/v1/demo/scenarios")
def demo_scenarios(user: dict[str, str] = Depends(current_user)):
    return {"scenarios": DEMO_SCENARIOS}


@app.post("/api/v1/auth/login")
def login(request: LoginRequest):
    initialize_database()
    username = request.username.strip()
    with get_db() as db:
        user = db.execute("SELECT username, role, password_hash, email FROM users WHERE lower(username) = lower(?)", (username,)).fetchone()
    if not user or user["password_hash"] != hash_password(request.password):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    return issue_session(user)


@app.post("/api/v1/auth/passkey")
def verify_passkey(request: PasskeyCredentialRequest):
    challenge = PASSKEY_CHALLENGES.pop(request.challenge_id, None)
    if not challenge or challenge["expires_at"] < time.time():
        raise HTTPException(status_code=401, detail="Passkey request expired. Authenticate again.")
    credential = request.credential
    if challenge["kind"] == "registration":
        verified = verify_registration_response(
            credential=credential,
            expected_challenge=challenge["challenge"],
            expected_rp_id=PASSKEY_RP_ID,
            expected_origin=PASSKEY_ORIGIN,
        )
        credential_id = base64.urlsafe_b64encode(verified.credential_id).decode().rstrip("=")
        public_key = base64.urlsafe_b64encode(verified.credential_public_key).decode().rstrip("=")
        with get_db() as db:
            db.execute("INSERT INTO passkeys (username, credential_id, public_key, sign_count, created_at) VALUES (?, ?, ?, ?, ?)", (challenge["username"], credential_id, public_key, verified.sign_count, datetime.now(timezone.utc).isoformat()))
            user = db.execute("SELECT username, role FROM users WHERE username = ?", (challenge["username"],)).fetchone()
        return issue_session(user)

    raw_id = credential.get("rawId") or credential.get("id")
    try:
        credential_id = base64.urlsafe_b64decode(raw_id + "=" * (-len(raw_id) % 4))
        credential_key = base64.urlsafe_b64encode(credential_id).decode().rstrip("=")
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="Invalid passkey credential.")
    with get_db() as db:
        stored = db.execute("SELECT * FROM passkeys WHERE credential_id = ? AND username = ?", (credential_key, challenge["username"])).fetchone()
    if not stored:
        raise HTTPException(status_code=401, detail="Passkey is not registered for this administrator.")
    verified = verify_authentication_response(
        credential=credential,
        expected_challenge=challenge["challenge"],
        expected_rp_id=PASSKEY_RP_ID,
        expected_origin=PASSKEY_ORIGIN,
        credential_public_key=base64.urlsafe_b64decode(stored["public_key"] + "=" * (-len(stored["public_key"]) % 4)),
        credential_current_sign_count=stored["sign_count"],
    )
    with get_db() as db:
        db.execute("UPDATE passkeys SET sign_count = ? WHERE id = ?", (verified.new_sign_count, stored["id"]))
        user = db.execute("SELECT username, role FROM users WHERE username = ?", (challenge["username"],)).fetchone()
    return issue_session(user)


@app.post("/api/v1/auth/verify-otp")
def verify_admin_otp(request: OtpVerificationRequest):
    challenge = OTP_CHALLENGES.get(request.challenge_id)
    if not challenge or challenge["expires_at"] < time.time():
        OTP_CHALLENGES.pop(request.challenge_id, None)
        raise HTTPException(status_code=401, detail="OTP expired. Authenticate again to request a new code.")
    challenge["attempts"] += 1
    if challenge["attempts"] > OTP_MAX_ATTEMPTS:
        OTP_CHALLENGES.pop(request.challenge_id, None)
        raise HTTPException(status_code=429, detail="Too many invalid OTP attempts. Authenticate again to request a new code.")
    if not secrets.compare_digest(challenge["otp_hash"], hashlib.sha256(request.otp.strip().encode("utf-8")).hexdigest()):
        raise HTTPException(status_code=401, detail="Invalid OTP.")
    with get_db() as db:
        user = db.execute("SELECT username, role FROM users WHERE username = ? AND role = 'head_admin'", (challenge["username"],)).fetchone()
    OTP_CHALLENGES.pop(request.challenge_id, None)
    if not user:
        raise HTTPException(status_code=401, detail="Administrator account is unavailable.")
    return issue_session(user)


@app.get("/api/v1/auth/me")
def me(user: dict[str, str] = Depends(current_user)):
    return user


@app.post("/api/v1/analyze")
def analyze_threat(request: ThreatAnalysisRequest, user: dict[str, str] = Depends(current_user)):
    if not request.payload.strip():
        raise HTTPException(status_code=400, detail="Payload content cannot be empty.")
    assessment = evaluate_threat_payload(request.category, request.payload)
    assessment["iocs"] = enrich_iocs(extract_iocs(request.payload))
    incident_id = store_incident(request.category, request.payload, assessment)
    persist_cyberguard_x(incident_id, {"id": incident_id, "category": request.category, "payload": request.payload, "risk_score": assessment["risk_score"], "risk_level": assessment["risk_level"], "assessment": assessment, "created_at": datetime.now(timezone.utc).isoformat()})
    write_audit(user, "analyze", f"incident:{incident_id}", request.category)
    if assessment["risk_level"] in ["High", "Critical"]:
        create_notification(user["username"], f"{assessment['risk_level']} threat detected", f"Incident INC-{incident_id:04d} requires review.", assessment["risk_level"])
    return {"status": "success", "incident_id": incident_id, "category": request.category, "assessment": assessment, "user": user["username"]}


@app.post("/api/v1/analyze/preview")
def preview_threat(request: ThreatAnalysisRequest, user: dict[str, str] = Depends(current_user)):
    if not request.payload.strip():
        raise HTTPException(status_code=400, detail="Payload content cannot be empty.")
    assessment = evaluate_threat_payload(request.category, request.payload)
    assessment["iocs"] = enrich_iocs(extract_iocs(request.payload))
    return {"status": "success", "category": request.category, "assessment": assessment}


@app.post("/api/v1/analyze/file")
async def analyze_file(category: str = Form(...), file: UploadFile = File(...), user: dict[str, str] = Depends(current_user)):
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file cannot be empty.")
    file_hash = hashlib.sha256(content).hexdigest()
    is_text = (file.content_type or "").startswith("text/") or (file.filename or "").lower().endswith((".txt", ".log", ".json", ".csv"))
    payload = content.decode("utf-8", errors="replace") if is_text else f"Uploaded {file.content_type or 'media'} file: {file.filename}"
    assessment = evaluate_threat_payload(category, payload)
    assessment["iocs"] = enrich_iocs(extract_iocs(payload))
    if not is_text:
        media_result = analyze_media(content, file.content_type or "", file.filename or "upload", category)
        assessment["risk_score"] = max(assessment["risk_score"], media_result["score"])
        assessment["indicators"].extend(media_result["indicators"])
        assessment["xai_explanation"] += " " + " ".join(media_result["reasons"])
        assessment["media_method"] = media_result["method"]
    incident_id = store_incident(category, payload, assessment, file.filename, file_hash)
    persist_cyberguard_x(incident_id, {"id": incident_id, "category": category, "payload": payload, "risk_score": assessment["risk_score"], "risk_level": assessment["risk_level"], "assessment": assessment, "created_at": datetime.now(timezone.utc).isoformat()})
    write_audit(user, "analyze_file", f"incident:{incident_id}", file.filename or category)
    if assessment["risk_level"] in ["High", "Critical"]:
        create_notification(user["username"], f"{assessment['risk_level']} media threat detected", f"Incident INC-{incident_id:04d} requires review.", assessment["risk_level"])
    return {"status": "success", "incident_id": incident_id, "filename": file.filename, "file_hash": file_hash, "assessment": assessment, "media_method": assessment.get("media_method"), "user": user["username"]}


@app.get("/api/v1/incidents")
def incidents(search: Optional[str] = Query(default=None), status: Optional[str] = Query(default=None), user: dict[str, str] = Depends(current_user)):
    with get_db() as db:
        clauses = []
        values = []
        if search:
            clauses.append("(category LIKE ? OR payload LIKE ? OR filename LIKE ?)")
            values.extend([f"%{search}%"] * 3)
        if status:
            clauses.append("status = ?")
            values.append(status)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = db.execute(f"SELECT id, category, payload, filename, file_hash, risk_score, risk_level, assessment, created_at, status, assigned_to, notes FROM incidents {where} ORDER BY id DESC LIMIT 100", values).fetchall()
    result = []
    for row in rows:
        try:
            assessment = json.loads(row["assessment"])
        except json.JSONDecodeError:
            assessment = ast.literal_eval(row["assessment"])
        result.append({
            "id": f"INC-{row['id']:04d}",
            "database_id": row["id"],
            "timestamp": row["created_at"],
            "source": row["filename"] or row["category"].replace("_", " ").title(),
            "target": "Security Operations Center",
            "category": row["category"].replace("_", " ").title(),
            "riskLevel": row["risk_level"],
            "riskScore": row["risk_score"],
            "status": row["status"],
            "assigned_to": row["assigned_to"],
            "notes": row["notes"],
            "explanation": assessment.get("xai_explanation", ""),
            "indicators": assessment.get("indicators", []),
        })
        with get_db() as db:
            x_row = db.execute("SELECT fingerprint FROM threat_fingerprints WHERE incident_id = ?", (row["id"],)).fetchone()
            campaign_row = db.execute("SELECT campaign_id FROM campaign_incidents WHERE incident_id = ? LIMIT 1", (row["id"],)).fetchone()
        result[-1]["dnaScore"] = int(assessment.get("risk_score", 0))
        result[-1]["fingerprint"] = x_row["fingerprint"] if x_row else None
        result[-1]["campaignId"] = campaign_row["campaign_id"] if campaign_row else None
    return {"incidents": result}


@app.patch("/api/v1/incidents/{incident_id}")
def update_incident(incident_id: int, request: IncidentUpdate, user: dict[str, str] = Depends(current_user)):
    allowed_statuses = {"New", "Investigating", "Contained", "Mitigated", "Closed"}
    if request.status and request.status not in allowed_statuses:
        raise HTTPException(status_code=400, detail=f"Status must be one of: {', '.join(sorted(allowed_statuses))}")
    with get_db() as db:
        current = db.execute("SELECT notes FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        if not current:
            raise HTTPException(status_code=404, detail="Incident not found")
        notes = current["notes"] or ""
        if request.note:
            notes = f"{notes}\n[{datetime.now(timezone.utc).isoformat()}] {user['username']}: {request.note}".strip()
        db.execute("UPDATE incidents SET status = COALESCE(?, status), assigned_to = COALESCE(?, assigned_to), notes = ? WHERE id = ?", (request.status, request.assigned_to, notes, incident_id))
    return {"status": "updated", "incident_id": incident_id}


@app.post("/api/v1/incidents/{incident_id}/comments")
def comment_incident(incident_id: int, request: IncidentComment, user: dict[str, str] = Depends(current_user)):
    return update_incident(incident_id, IncidentUpdate(note=request.comment), user)


@app.get("/api/v1/incidents/{incident_id}")
def incident_detail(incident_id: int, user: dict[str, str] = Depends(current_user)):
    with get_db() as db:
        incident = db.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        actions = db.execute("SELECT action_id, target, username, status, created_at FROM actions WHERE incident_id IN (?, ?) ORDER BY id DESC", (str(incident_id), f"INC-{incident_id:04d}")).fetchall()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    try:
        assessment = json.loads(incident["assessment"])
    except json.JSONDecodeError:
        assessment = ast.literal_eval(incident["assessment"])
    return {"incident": {"id": f"INC-{incident_id:04d}", "database_id": incident_id, "category": incident["category"], "payload": incident["payload"], "filename": incident["filename"], "file_hash": incident["file_hash"], "risk_score": incident["risk_score"], "risk_level": incident["risk_level"], "status": incident["status"], "assigned_to": incident["assigned_to"], "notes": incident["notes"], "created_at": incident["created_at"], "assessment": assessment, "actions": [dict(action) for action in actions]}}


@app.get("/api/v1/incidents/{incident_id}/genome")
@app.get("/api/v1/incidents/{incident_id}/dna")
@app.get("/incidents/{incident_id}/dna")
@app.get("/incidents/{incident_id}/genome")
def incident_genome(incident_id: int, user: dict[str, str] = Depends(current_user)):
    incident = incident_context(incident_id)
    return {"incident_id": incident_id, "genome": build_genome(incident)}


@app.get("/api/v1/incidents/{incident_id}/correlations")
@app.get("/incidents/{incident_id}/correlations")
def incident_correlations(incident_id: int, user: dict[str, str] = Depends(current_user)):
    incident = incident_context(incident_id)
    related = [item for item in recent_incident_context() if item["id"] != incident_id]
    return correlate_incident(incident, related)


@app.get("/api/v1/incidents/{incident_id}/timeline")
@app.get("/api/v1/incidents/{incident_id}/attack-chain")
@app.get("/incidents/{incident_id}/attack-chain")
@app.get("/incidents/{incident_id}/timeline")
def incident_attack_chain(incident_id: int, user: dict[str, str] = Depends(current_user)):
    return {"incident_id": incident_id, "events": build_timeline(incident_context(incident_id))}


@app.get("/api/v1/incidents/{incident_id}/intent")
def incident_intent_route(incident_id: int, user: dict[str, str] = Depends(current_user)):
    return incident_intent(incident_id, user)


@app.get("/api/v1/incidents/{incident_id}/drift")
def incident_drift_route(incident_id: int, user: dict[str, str] = Depends(current_user)):
    return incident_drift(incident_id, user)


@app.get("/api/v1/incidents/{incident_id}/memory")
def incident_memory_route(incident_id: int, user: dict[str, str] = Depends(current_user)):
    return incident_memory(incident_id, user)


@app.get("/api/v1/incidents/{incident_id}/explainability")
def incident_explainability_route(incident_id: int, user: dict[str, str] = Depends(current_user)):
    return incident_explainability(incident_id, user)


@app.post("/api/v1/alert-routing")
def alert_routing_endpoint(request: dict | None = None, user: dict[str, str] = Depends(current_user)):
    payload = request or {}
    incidents = payload.get("incidents", recent_incident_context())
    analysts = payload.get("analysts", [{"username": user.get("username", "analyst"), "role": user.get("role", "analyst")}])
    return fatigue_routing(incidents, analysts)


@app.get("/api/v1/alert-quality")
def alert_quality_route(user: dict[str, str] = Depends(current_user)):
    return alert_quality(user)


@app.post("/api/v1/alert-quality/record")
def alert_quality_record(request: dict, user: dict[str, str] = Depends(current_user)):
    return record_alert_outcome(
        int(request.get("incident_id", 0)),
        str(request.get("detection_type", "unknown")),
        int(request.get("alert_risk_score", 0)),
        str(request.get("final_resolution", "unknown")),
        str(request.get("reviewed_by", user.get("username", "analyst"))),
    )


@app.get("/api/v1/campaigns")
def campaigns(user: dict[str, str] = Depends(current_user)):
    with get_db() as db:
        rows = db.execute("SELECT campaign_id, confidence, stage, created_at FROM campaigns ORDER BY created_at DESC").fetchall()
        result = []
        for row in rows:
            count = db.execute("SELECT COUNT(*) AS count FROM campaign_incidents WHERE campaign_id = ?", (row["campaign_id"],)).fetchone()["count"]
            result.append({**dict(row), "incident_count": count})
    return {"campaigns": result}


@app.get("/api/v1/campaigns/{campaign_id}")
def campaign_detail(campaign_id: str, user: dict[str, str] = Depends(current_user)):
    with get_db() as db:
        campaign = db.execute("SELECT campaign_id, confidence, stage, created_at FROM campaigns WHERE campaign_id = ?", (campaign_id,)).fetchone()
        links = db.execute("SELECT incident_id, score FROM campaign_incidents WHERE campaign_id = ? ORDER BY score DESC", (campaign_id,)).fetchall()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return {"campaign": {**dict(campaign), "incidents": [dict(link) for link in links]}}


@app.get("/api/v1/network/twin")
def network_twin(user: dict[str, str] = Depends(current_user)):
    return build_twin(recent_incident_context())


@app.post("/api/v1/psychology/analyze")
def psychology_analysis(request: PsychologyRequest, user: dict[str, str] = Depends(current_user)):
    if not request.payload.strip():
        raise HTTPException(status_code=400, detail="Payload content cannot be empty.")
    return analyze_psychology(request.payload)


@app.post("/api/v1/forecast")
@app.post("/forecast")
def threat_forecast(request: ForecastRequest, user: dict[str, str] = Depends(current_user)):
    result = forecast_risk(recent_incident_context(), max(1, min(request.horizon, 24)))
    with get_db() as db:
        db.execute("INSERT INTO threat_forecasts (forecast_json, created_at) VALUES (?, ?)", (json.dumps(result), datetime.now(timezone.utc).isoformat()))
    return result


@app.post("/api/v1/incidents/{incident_id}/simulate")
@app.post("/incidents/{incident_id}/simulate")
def incident_simulation(incident_id: int, request: SimulationRequest, user: dict[str, str] = Depends(current_user)):
    incident = incident_context(incident_id)
    result = simulate_response(incident["risk_score"], request.actions)
    with get_db() as db:
        db.execute("INSERT INTO response_simulations (incident_id, simulation_json, created_at) VALUES (?, ?, ?)", (incident_id, json.dumps(result), datetime.now(timezone.utc).isoformat()))
    return result



@app.post("/api/v1/simulate")
def generic_simulation(request: SimulationRequest, user: dict[str, str] = Depends(current_user)):
    latest = recent_incident_context()[0] if recent_incident_context() else {"risk_score": 0}
    return simulate_response(latest.get("risk_score", 0), request.actions)


@app.post("/api/v1/self-heal")
def self_heal(incident_id: Optional[int] = None, user: dict[str, str] = Depends(current_user)):
    incident = incident_context(incident_id) if incident_id else (recent_incident_context()[0] if recent_incident_context() else {"risk_score": 0})
    return recommend_healing(incident)


@app.post("/api/v1/battle")
def battle(request: BattleRequest, user: dict[str, str] = Depends(current_user)):
    latest = recent_incident_context()[0] if recent_incident_context() else {"risk_score": 0}
    result = run_battle(latest.get("risk_score", 0), request.defender_actions)
    with get_db() as db:
        db.execute("INSERT INTO battle_sessions (defender_actions_json, result_json, created_at) VALUES (?, ?, ?)", (json.dumps(request.defender_actions), json.dumps(result), datetime.now(timezone.utc).isoformat()))
    return result


@app.get("/api/v1/notifications")
def notifications(user: dict[str, str] = Depends(current_user)):
    with get_db() as db:
        rows = db.execute("SELECT id, title, message, severity, read, created_at FROM notifications WHERE username = ? ORDER BY id DESC LIMIT 50", (user["username"],)).fetchall()
    return {"notifications": [dict(row) for row in rows], "unread": sum(not row["read"] for row in rows)}


@app.patch("/api/v1/notifications/{notification_id}")
def update_notification(notification_id: int, request: NotificationUpdate, user: dict[str, str] = Depends(current_user)):
    with get_db() as db:
        db.execute("UPDATE notifications SET read = ? WHERE id = ? AND username = ?", (int(request.read), notification_id, user["username"]))
    return {"status": "updated", "notification_id": notification_id}


@app.post("/api/v1/threat-intel/lookup")
def threat_intel_lookup(request: ThreatIntelLookup, user: dict[str, str] = Depends(current_user)):
    iocs = enrich_iocs(extract_iocs(request.value))
    if not iocs:
        iocs = [{"type": request.indicator_type or "unknown", "value": request.value, "indicator": request.value, "reputation": "unknown"}]
    write_audit(user, "threat_intel_lookup", request.value, request.indicator_type or "auto")
    return {"results": iocs, "provider": "local-heuristic", "external_enrichment": False}


@app.post("/api/v1/adversarial/self-test")
def adversarial_self_test_route(request: dict, user: dict[str, str] = Depends(current_user)):
    payload = str(request.get("payload") or "").strip()
    category = str(request.get("category") or "email").strip() or "email"
    if not payload:
        raise HTTPException(status_code=400, detail="Payload content cannot be empty.")
    result = adversarial_self_test(category, payload)
    write_audit(user, "adversarial_self_test", category, result["recommendation"])
    return result


@app.post("/api/v1/roadmap/media-consistency")
async def roadmap_media_consistency(files: list[UploadFile] = File(...), user: dict[str, str] = Depends(current_user)):
    if len(files) < 2:
        raise HTTPException(status_code=400, detail="Upload at least two media channels for cross-modal comparison.")
    results = []
    for file in files[:4]:
        content = await file.read()
        if content:
            result = analyze_media(content, file.content_type or "", file.filename or "upload", "deepfake")
            result["media_type"] = file.content_type or file.filename or "unknown"
            results.append(result)
    return cross_modal_consistency(results)


@app.post("/api/v1/scanner/scan")
def scanner_scan(request: ScannerRequest, user: dict[str, str] = Depends(current_user)):
    if not request.payload.strip():
        raise HTTPException(status_code=400, detail="Scan payload cannot be empty.")
    result = scan_payload(request.payload)
    if request.indicator_type and not result["results"]:
        result["results"] = [inspect_indicator(request.payload, request.indicator_type)]
    write_audit(user, "scanner_scan", "payload", result["genome"])
    return result


@app.get("/api/v1/threat-intel/feed")
def threat_intel_feed(user: dict[str, str] = Depends(current_user)):
    items = []
    for incident in recent_incident_context()[:20]:
        assessment = incident.get("assessment", {})
        iocs = assessment.get("iocs", [])
        for ioc in iocs[:3]:
            item = inspect_indicator(ioc.get("value", ioc.get("indicator", "")), ioc.get("type"))
            item["incident_id"] = incident["id"]
            items.append(item)
    return {"items": items, "provider": "local-heuristic"}


@app.get("/api/v1/threat-map")
def threat_map(user: dict[str, str] = Depends(current_user)):
    return build_global_threat_map(recent_incident_context())


@app.get("/api/v1/identity-risk")
def identity_risk(user: dict[str, str] = Depends(current_user)):
    return build_identity_heatmap(recent_incident_context())


@app.post("/api/v1/media/trust")
async def media_trust(file: UploadFile = File(...), user: dict[str, str] = Depends(current_user)):
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Uploaded media cannot be empty.")
    return analyze_trust_media(content, file.filename or "upload", file.content_type or "")


@app.websocket("/api/v1/ws/events")
async def events_socket(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            await websocket.send_json({"type": "heartbeat", "status": "connected"})
            await websocket.receive_text()
    except WebSocketDisconnect:
        return


@app.get("/api/v1/frontier/overview")
def frontier_summary(user: dict[str, str] = Depends(current_user)):
    return frontier_overview(recent_incident_context())


@app.post("/api/v1/frontier/threat-physics")
def frontier_threat_physics(request: ThreatPhysicsRequest, user: dict[str, str] = Depends(current_user)):
    return predict_threat_physics(request.nodes, request.edges)


@app.post("/api/v1/frontier/deception-session")
def frontier_deception(request: DeceptionRequest, user: dict[str, str] = Depends(current_user)):
    return cognitive_deception_session(request.message, request.replies)


@app.post("/api/v1/frontier/topology-morph")
def frontier_topology(request: TopologyMorphRequest, user: dict[str, str] = Depends(current_user)):
    return morph_topology(request.nodes, request.edges, request.trigger)


@app.post("/api/v1/frontier/static-analysis")
async def frontier_static_analysis(file: UploadFile = File(...), user: dict[str, str] = Depends(current_user)):
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Artifact cannot be empty.")
    return static_artifact_analysis(content, file.filename or "artifact")


@app.post("/api/v1/frontier/agent-consensus")
def frontier_agents(request: AgentConsensusRequest, user: dict[str, str] = Depends(current_user)):
    return agent_consensus(request.telemetry)


@app.post("/api/v1/frontier/analyst-load")
def frontier_analyst_load(request: AnalystLoadRequest, user: dict[str, str] = Depends(current_user)):
    return assess_analyst_load(request.telemetry)


@app.post("/api/v1/frontier/q-state")
def frontier_q_state(request: QStateRequest, user: dict[str, str] = Depends(current_user)):
    return assess_q_state(request.telemetry)


@app.post("/api/v1/frontier/satellite-link")
def frontier_satellite(request: SatelliteRequest, user: dict[str, str] = Depends(current_user)):
    return assess_satellite_link(request.telemetry)


@app.post("/api/v1/frontier/cognitive-echo")
def frontier_cognitive_echo(request: CognitiveEchoRequest, user: dict[str, str] = Depends(current_user)):
    if not request.query.strip():
        raise HTTPException(status_code=400, detail="Query cannot be empty.")
    return build_cognitive_echo(request.query)


@app.post("/api/v1/frontier/neuromorphic")
def frontier_neuromorphic(request: NeuromorphicRequest, user: dict[str, str] = Depends(current_user)):
    return assess_neuromorphic_telemetry(request.telemetry)


@app.post("/api/v1/advanced/heartbeat-keying")
def advanced_heartbeat(request: AdvancedTelemetryRequest, user: dict[str, str] = Depends(current_user)):
    return heartbeat_keying(request.telemetry, user.get("username", "session"))


@app.post("/api/v1/advanced/quantum-decoy")
def advanced_quantum_decoy(request: QuantumDecoyRequest, user: dict[str, str] = Depends(current_user)):
    return quantum_decoy(request.model_dump())


@app.post("/api/v1/advanced/temporal-healing")
def advanced_temporal_healing(request: TemporalHealingRequest, user: dict[str, str] = Depends(current_user)):
    return temporal_healing(request.state)


@app.post("/api/v1/advanced/acoustic-channel")
def advanced_acoustic(request: AdvancedTelemetryRequest, user: dict[str, str] = Depends(current_user)):
    return acoustic_channel(request.telemetry)


@app.post("/api/v1/advanced/polymorphism")
def advanced_polymorphism(request: PolymorphismRequest, user: dict[str, str] = Depends(current_user)):
    return polymorphism_plan(request.binary)


@app.post("/api/v1/advanced/infrastructure-echo")
def advanced_infrastructure_echo(request: InfrastructureEchoRequest, user: dict[str, str] = Depends(current_user)):
    if not request.query.strip():
        raise HTTPException(status_code=400, detail="Query cannot be empty.")
    return hallucinated_infrastructure(request.query)


@app.post("/api/v1/advanced/dark-mesh")
def advanced_dark_mesh(request: DarkMeshRequest, user: dict[str, str] = Depends(current_user)):
    return dark_mesh_schedule(request.nodes, request.epoch)


@app.post("/api/v1/advanced/vaccine-recommendations")
def advanced_vaccines(request: VaccineRequest, user: dict[str, str] = Depends(current_user)):
    return vaccine_recommendations(request.indicators)


@app.post("/api/v1/advanced/space-weather")
def advanced_space_weather(request: AdvancedTelemetryRequest, user: dict[str, str] = Depends(current_user)):
    return space_weather_correlation(request.telemetry)


@app.post("/api/v1/advanced/counter-agent")
def advanced_counter_agent(request: AdvancedTelemetryRequest, user: dict[str, str] = Depends(current_user)):
    return counter_agent_proxy(request.telemetry)


@app.get("/api/v1/speculative/overview")
def speculative_summary(user: dict[str, str] = Depends(current_user)):
    return speculative_overview()


@app.post("/api/v1/speculative/chrono-causal")
def speculative_chrono(request: SpeculativeTelemetryRequest, user: dict[str, str] = Depends(current_user)):
    return chrono_causal_trap(request.telemetry)


@app.post("/api/v1/speculative/holographic-memory")
def speculative_memory(request: SpeculativeTelemetryRequest, user: dict[str, str] = Depends(current_user)):
    return holographic_memory(request.telemetry)


@app.post("/api/v1/speculative/hyperbolic-network")
def speculative_hyperbolic(request: SpeculativeTelemetryRequest, user: dict[str, str] = Depends(current_user)):
    return hyperbolic_network(request.telemetry)


@app.post("/api/v1/speculative/singularity-sinkhole")
def speculative_sinkhole(request: SpeculativeTelemetryRequest, user: dict[str, str] = Depends(current_user)):
    return singularity_sinkhole(request.telemetry)


@app.post("/api/v1/speculative/vacuum-keying")
def speculative_vacuum(request: SpeculativeTelemetryRequest, user: dict[str, str] = Depends(current_user)):
    return vacuum_keying(request.telemetry)


@app.post("/api/v1/speculative/software-apoptosis")
def speculative_apoptosis(request: SpeculativeTelemetryRequest, user: dict[str, str] = Depends(current_user)):
    return software_apoptosis(request.telemetry)


@app.post("/api/v1/speculative/plasma-channel")
def speculative_plasma(request: SpeculativeTelemetryRequest, user: dict[str, str] = Depends(current_user)):
    return plasma_channel(request.telemetry)


@app.post("/api/v1/speculative/cognitive-poisoning")
def speculative_poisoning(request: SpeculativeTelemetryRequest, user: dict[str, str] = Depends(current_user)):
    return cognitive_poisoning(request.telemetry)


@app.post("/api/v1/speculative/phase-change-zeroization")
def speculative_phase_change(request: SpeculativeTelemetryRequest, user: dict[str, str] = Depends(current_user)):
    return phase_change_zeroization(request.telemetry)


@app.post("/api/v1/speculative/photonic-bus")
def speculative_photonic(request: SpeculativeTelemetryRequest, user: dict[str, str] = Depends(current_user)):
    return photonic_bus(request.telemetry)


@app.get("/api/v1/admin/users")
def admin_users(user: dict[str, str] = Depends(admin_user)):
    with get_db() as db:
        rows = db.execute("SELECT username, role, email, parent_username, status FROM users ORDER BY username").fetchall()
    write_audit(user, "list_users", "users", "admin console")
    return {"users": [dict(row) for row in rows]}


@app.post("/api/v1/admin/users")
def create_user(request: UserCreate, user: dict[str, str] = Depends(head_admin_user)):
    if request.role not in {"analyst", "lead", "sub_admin"}:
        raise HTTPException(status_code=400, detail="Invalid role")
    if request.role == "sub_admin":
        with get_db() as db:
            count = db.execute("SELECT COUNT(*) AS count FROM users WHERE role = 'sub_admin'").fetchone()["count"]
        if count >= 5:
            raise HTTPException(status_code=409, detail="The five sub-admin slots are already allocated")
    try:
        with get_db() as db:
            db.execute("INSERT INTO users (username, password_hash, role, email, parent_username, status) VALUES (?, ?, ?, ?, ?, ?)", (request.username, hash_password(request.password), request.role, "", HEAD_ADMIN_USERNAME, "active"))
    except sqlite3.IntegrityError as error:
        raise HTTPException(status_code=409, detail="Username already exists") from error
    write_audit(user, "create_user", f"user:{request.username}", request.role)
    return {"status": "created", "username": request.username, "role": request.role}


@app.post("/api/v1/admin/permissions/request")
def request_permission(request: PermissionRequest, user: dict[str, str] = Depends(current_user)):
    if user.get("role") != "sub_admin":
        raise HTTPException(status_code=403, detail="Only sub-admins request elevated permissions")
    with get_db() as db:
        db.execute("INSERT INTO permission_requests (username, permission, requested_at) VALUES (?, ?, ?)", (user["username"], request.permission, datetime.now(timezone.utc).isoformat()))
    send_security_notice("sub-admin permission request", f"{user['username']} requested: {request.permission}")
    return {"status": "pending", "owner": SECURITY_OWNER_EMAIL}


@app.get("/api/v1/admin/permissions")
def permission_requests(user: dict[str, str] = Depends(head_admin_user)):
    with get_db() as db:
        rows = db.execute("SELECT * FROM permission_requests ORDER BY id DESC LIMIT 100").fetchall()
    return {"requests": [dict(row) for row in rows]}


@app.patch("/api/v1/admin/permissions/{request_id}")
def decide_permission(request_id: int, approved: bool = Query(...), user: dict[str, str] = Depends(head_admin_user)):
    status = "approved" if approved else "denied"
    with get_db() as db:
        row = db.execute("SELECT username, permission FROM permission_requests WHERE id = ?", (request_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Permission request not found")
        db.execute("UPDATE permission_requests SET status = ?, decided_by = ?, decided_at = ? WHERE id = ?", (status, user["username"], datetime.now(timezone.utc).isoformat(), request_id))
    send_security_notice(f"permission {status}", f"{row['username']} / {row['permission']}")
    return {"status": status, "request_id": request_id}


@app.get("/api/v1/admin/security-events")
def security_events(user: dict[str, str] = Depends(admin_user)):
    with get_db() as db:
        rows = db.execute("SELECT * FROM security_events ORDER BY id DESC LIMIT 100").fetchall()
        blocked = db.execute("SELECT * FROM blocked_ips ORDER BY blocked_at DESC").fetchall()
    return {"events": [dict(row) for row in rows], "blocked_ips": [dict(row) for row in blocked], "owner_email": SECURITY_OWNER_EMAIL}


@app.post("/api/v1/admin/security-events/block")
def block_ip(ip_address: str = Query(...), reason: str = Query("Head-admin containment"), user: dict[str, str] = Depends(head_admin_user)):
    with get_db() as db:
        db.execute("INSERT INTO blocked_ips (ip_address, reason, blocked_at) VALUES (?, ?, ?) ON CONFLICT (ip_address) DO UPDATE SET reason = excluded.reason, blocked_at = excluded.blocked_at", (ip_address, reason, datetime.now(timezone.utc).isoformat()))
    record_security_event("manual-ip-block", ip_address, "admin-console", reason)
    return {"status": "blocked", "ip_address": ip_address}


@app.get("/api/v1/admin/cloudflare/status")
def cloudflare_status(user: dict[str, str] = Depends(head_admin_user)):
    return cloudflare_configuration()


@app.post("/api/v1/admin/cloudflare/block-ip")
def cloudflare_block(ip_address: str = Query(...), reason: str = Query("CyberGuard WAF containment"), user: dict[str, str] = Depends(head_admin_user)):
    try:
        result = cloudflare_block_ip(ip_address, reason)
    except requests.RequestException as error:
        raise HTTPException(status_code=502, detail=f"Cloudflare WAF request failed: {error}") from error
    except RuntimeError as error:
        raise HTTPException(status_code=502, detail=str(error)) from error
    if result.get("status") == "blocked":
        record_security_event("cloudflare-waf-ip-block", ip_address, "cloudflare", reason)
    return result


@app.get("/api/v1/admin/audit")
def audit_logs(user: dict[str, str] = Depends(admin_user)):
    with get_db() as db:
        rows = db.execute("SELECT username, action, resource, details, created_at FROM audit_logs ORDER BY id DESC LIMIT 100").fetchall()
    return {"audit": [dict(row) for row in rows]}


@app.get("/api/v1/events/recent")
def recent_events(after_id: int = 0, user: dict[str, str] = Depends(current_user)):
    with get_db() as db:
        rows = db.execute("SELECT id, category, risk_level, risk_score, created_at FROM incidents WHERE id > ? ORDER BY id ASC LIMIT 50", (after_id,)).fetchall()
    return {"events": [dict(row) for row in rows]}


@app.get("/api/v1/dashboard/metrics")
def dashboard_metrics(user: dict[str, str] = Depends(current_user)):
    with get_db() as db:
        total = db.execute("SELECT COUNT(*) AS count FROM incidents").fetchone()["count"]
        threats = db.execute("SELECT COUNT(*) AS count FROM incidents WHERE risk_level IN ('Critical', 'High', 'Medium')").fetchone()["count"]
        critical = db.execute("SELECT COUNT(*) AS count FROM incidents WHERE risk_level = 'Critical'").fetchone()["count"]
        active = db.execute("SELECT COUNT(*) AS count FROM incidents WHERE status NOT IN ('Closed', 'Mitigated')").fetchone()["count"]
        safe = db.execute("SELECT COUNT(*) AS count FROM incidents WHERE risk_level = 'Safe'").fetchone()["count"]
        rows = db.execute("SELECT category, risk_level, COUNT(*) AS count FROM incidents GROUP BY category, risk_level").fetchall()
    by_category = {}
    by_level = {}
    for row in rows:
        by_category[row["category"]] = by_category.get(row["category"], 0) + row["count"]
        by_level[row["risk_level"]] = by_level.get(row["risk_level"], 0) + row["count"]
    return {
        "totalEvents": total,
        "threatsDetected": threats,
        "criticalAlerts": critical,
        "activeIncidents": active,
        "safeRequests": safe,
        "phishingCount": by_category.get("phishing", 0) + by_category.get("url", 0),
        "deepfakeCount": by_category.get("deepfake", 0),
        "impersonationCount": by_category.get("impersonation", 0),
        "atoCount": by_category.get("ato", 0) + by_category.get("auth_logs", 0),
        "byCategory": by_category,
        "byLevel": by_level,
    }


@app.get("/api/v1/dashboard/timeline")
def dashboard_timeline(user: dict[str, str] = Depends(current_user)):
    with get_db() as db:
        rows = db.execute(
            "SELECT substr(created_at, 12, 2) AS hour, risk_level, COUNT(*) AS count "
            "FROM incidents GROUP BY hour, risk_level ORDER BY hour"
        ).fetchall()
    timeline = {}
    for row in rows:
        point = timeline.setdefault(f"{row['hour']}:00", {"Safe": 0, "Low": 0, "Medium": 0, "High": 0, "Critical": 0})
        point[row["risk_level"]] = row["count"]
    return [{"time": key, **value} for key, value in timeline.items()]


@app.get("/api/v1/dashboard/graph")
def dashboard_graph(user: dict[str, str] = Depends(current_user)):
    with get_db() as db:
        rows = db.execute("SELECT category, risk_level, COUNT(*) AS count FROM incidents GROUP BY category, risk_level").fetchall()
    nodes = [{"id": "origin", "position": {"x": 20, "y": 120}, "data": {"label": "External Threat Sources"}, "style": {"background": "#b91c1c", "color": "#fff"}}]
    edges = []
    for index, row in enumerate(rows):
        node_id = f"category-{index}"
        label = f"{row['category'].replace('_', ' ').title()} ({row['count']})"
        nodes.append({"id": node_id, "position": {"x": 260, "y": index * 80}, "data": {"label": label}, "style": {"background": "#0e7490", "color": "#fff"}})
        edges.append({"id": f"origin-{node_id}", "source": "origin", "target": node_id, "animated": row["risk_level"] in ["High", "Critical"], "label": row["risk_level"]})
    return {"nodes": nodes, "edges": edges}


@app.get("/api/v1/system/health")
def system_health(user: dict[str, str] = Depends(current_user)):
    with get_db() as db:
        event_count = db.execute("SELECT COUNT(*) AS count FROM incidents").fetchone()["count"]
        recent_created = [row["created_at"] for row in db.execute("SELECT created_at FROM incidents ORDER BY id DESC LIMIT 200").fetchall()]
    uptime = (datetime.now(timezone.utc) - STARTED_AT).total_seconds()
    one_minute_ago = datetime.now(timezone.utc) - timedelta(minutes=1)
    events_per_minute = 0
    for value in recent_created:
        try:
            if datetime.fromisoformat(value) >= one_minute_ago:
                events_per_minute += 1
        except (TypeError, ValueError):
            continue
    quality = alert_quality_report()
    return {
        "status": "healthy",
        "uptime_seconds": round(uptime),
        "events_stored": event_count,
        "model_loaded": TEXT_MODEL is not None,
        "model_confidence": "loaded" if TEXT_MODEL is not None else "heuristics active",
        "api_latency_ms": 0,
        "events_per_minute": events_per_minute,
        "threat_accuracy": quality.get("overall_score", 0),
        "database": database_backend(),
        "response_integrations": bool(os.getenv("CYBERGUARD_RESPONSE_WEBHOOK_URL")),
    }


@app.get("/api/v1/system/production-readiness")
def production_readiness(user: dict[str, str] = Depends(head_admin_user)):
    integrations = provider_status()
    configured = [name for name, status in integrations.items() if status["configured"]]
    missing = [name for name, status in integrations.items() if not status["configured"]]
    return {
        "environment": CYBERGUARD_ENV,
        "status": "ready" if not missing else "configuration_required",
        "configured": configured,
        "configuration_required": missing,
        "database": database_backend(),
        "https_required_in_production": CYBERGUARD_ENV in {"production", "prod"},
    }


@app.get("/metrics", include_in_schema=False)
def metrics():
    with get_db() as db:
        active_incidents = db.execute("SELECT COUNT(*) AS count FROM incidents WHERE status NOT IN ('Closed', 'Mitigated')").fetchone()["count"]
    provider_count = sum(1 for status in provider_status().values() if status.get("configured"))
    return PlainTextResponse(prometheus_metrics(HTTP_REQUEST_COUNT, HTTP_ERROR_COUNT, active_incidents, provider_count), media_type="text/plain; version=0.0.4")


@app.post("/api/v1/admin/backup")
def create_database_backup(user: dict[str, str] = Depends(head_admin_user)):
    try:
        result = backup_database()
    except (OSError, RuntimeError, sqlite3.Error) as error:
        raise HTTPException(status_code=503, detail=f"Database backup unavailable: {error}") from error
    write_audit(user, "database_backup", result["destination"], "Online database backup completed")
    return result


@app.get("/api/v1/integrations/status")
def integrations_status(user: dict[str, str] = Depends(head_admin_user)):
    return provider_status()


@app.post("/api/v1/integrations/ticket")
def integrations_ticket(request: dict, user: dict[str, str] = Depends(head_admin_user)):
    try:
        result = create_ticket(request)
    except IntegrationNotConfigured as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    write_audit(user, "ticket_created", str(request.get("incident_id", "unknown")), result["provider"])
    return result


@app.post("/api/v1/integrations/identity/disable")
def integrations_disable_identity(request: dict, user: dict[str, str] = Depends(head_admin_user)):
    identity = str(request.get("identity", "")).strip()
    if not identity:
        raise HTTPException(status_code=422, detail="identity is required")
    try:
        result = disable_identity(identity)
    except IntegrationNotConfigured as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    write_audit(user, "identity_disabled", identity, result["provider"])
    return result


@app.post("/api/v1/integrations/endpoint/isolate")
def integrations_isolate_endpoint(request: dict, user: dict[str, str] = Depends(head_admin_user)):
    endpoint_id = str(request.get("endpoint_id", "")).strip()
    if not endpoint_id:
        raise HTTPException(status_code=422, detail="endpoint_id is required")
    try:
        result = isolate_endpoint(endpoint_id)
    except IntegrationNotConfigured as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    write_audit(user, "endpoint_isolated", endpoint_id, result["provider"])
    return result


@app.get("/api/v1/models/status")
def model_status(user: dict[str, str] = Depends(current_user)):
    return {
        "text_classifier": {"loaded": TEXT_MODEL is not None, "algorithm": "TF-IDF + Logistic Regression"},
        "media_inspection": {"loaded": True, "algorithm": "Lightweight Isolation Forest over image/audio features plus video metadata"},
        "deep_learning_adapter": {"loaded": bool(os.getenv("CYBERGUARD_MEDIA_MODEL_PATH")), "path_configured": bool(os.getenv("CYBERGUARD_MEDIA_MODEL_PATH"))},
        "threat_intelligence": {"loaded": True, "algorithm": "Local IOC reputation with optional external provider", "external_configured": bool(os.getenv("CYBERGUARD_THREAT_INTEL_URL"))},
    }


@app.get("/api/v1/compliance/controls")
def compliance_controls(user: dict[str, str] = Depends(current_user)):
    return {"controls": [
        {"id": "cert-in-6h", "framework": "CERT-In 6-Hour Reporting", "status": "Compliant", "score": 100, "evidence": "Persisted incident records and alert dispatch API"},
        {"id": "dpdp-rbac", "framework": "DPDP Act / Privacy", "status": "Compliant", "score": 98, "evidence": "JWT authentication and Analyst/Lead authorization"},
        {"id": "iso-access", "framework": "ISO 27001 Access Control", "status": "Needs Review", "score": 84, "evidence": "Role controls active; production SSO remains required"},
    ]}


@app.get("/api/v1/compliance/mitre")
def mitre_mapping(user: dict[str, str] = Depends(current_user)):
    return {"mappings": [
        {"technique": "T1566", "name": "Phishing", "categories": ["email", "sms", "social"]},
        {"technique": "T1566.002", "name": "Phishing: Spearphishing Link", "categories": ["url"]},
        {"technique": "T1078", "name": "Valid Accounts", "categories": ["ato", "auth_logs"]},
        {"technique": "T1110", "name": "Brute Force", "categories": ["ato", "auth_logs"]},
        {"technique": "T1036", "name": "Masquerading", "categories": ["impersonation", "deepfake"]},
        {"technique": "T1585", "name": "Establish Accounts", "categories": ["deepfake"]},
        {"technique": "T1041", "name": "Exfiltration Over C2 Channel", "categories": ["exfiltration", "network"]},
        {"technique": "T1190", "name": "Exploit Public-Facing Application", "categories": ["api_logs", "malware"]},
    ]}


@app.get("/api/v1/integrations/status")
def integration_status(user: dict[str, str] = Depends(current_user)):
    return {"integrations": [
        {"name": "Response Webhook", "configured": bool(os.getenv("CYBERGUARD_RESPONSE_WEBHOOK_URL"))},
        {"name": "Alert Webhook", "configured": bool(os.getenv("CYBERGUARD_ALERT_WEBHOOK_URL"))},
        {"name": "SIEM Ingestion", "configured": bool(os.getenv("CYBERGUARD_SIEM_URL"))},
    ], "providers": provider_integration_status()}


@app.post("/api/v1/integrations/siem/ingest")
def ingest_siem_event_route(request: ThreatAnalysisRequest, user: dict[str, str] = Depends(current_user)):
    result = analyze_threat(request, user)
    siem_url = os.getenv("CYBERGUARD_SIEM_URL")
    if siem_url:
        try:
            response = requests.post(siem_url, json=result, timeout=5)
            response.raise_for_status()
            result["siem_delivery"] = "delivered"
        except requests.RequestException as error:
            raise HTTPException(status_code=502, detail=f"SIEM delivery failed: {error}") from error
    else:
        result["siem_delivery"] = "recorded"
    return result


@app.post("/api/v1/siem/log")
def siem_ingest_event_route_json(payload: dict, user: dict[str, str] = Depends(current_user)):
    return siem_ingest_event(payload, user)


@app.get("/api/v1/siem/logs")
def siem_logs(user: dict[str, str] = Depends(current_user)):
    return read_siem_events(user)


@app.post("/api/v1/idp/authenticate")
def idp_authenticate_route(payload: dict, user: dict[str, str] = Depends(current_user)):
    return idp_authenticate_user(payload, user)


@app.post("/api/v1/response/execute")
def execute_response(request: ResponseExecutionRequest, user: dict[str, str] = Depends(current_user)):
    if user["role"] != "lead":
        raise HTTPException(status_code=403, detail="Senior SOC Lead role required")
    status = "simulated"
    webhook_url = os.getenv("CYBERGUARD_RESPONSE_WEBHOOK_URL")
    if webhook_url:
        try:
            response = requests.post(webhook_url, json=request.model_dump(), timeout=5)
            response.raise_for_status()
            status = "delivered"
        except requests.RequestException as error:
            raise HTTPException(status_code=502, detail=f"Response integration failed: {error}") from error
    with get_db() as db:
        db.execute("INSERT INTO actions (incident_id, action_id, target, username, status, created_at) VALUES (?, ?, ?, ?, ?, ?)", (request.incident_id, request.action_id, request.target, user["username"], status, datetime.now(timezone.utc).isoformat()))
    return {"status": status, "incident_id": request.incident_id, "action": request.action_id, "message": f"Response action {request.action_id} recorded for {request.target}"}


@app.post("/api/v1/alert/dispatch")
def dispatch_alert(request: AlertRequest, user: dict[str, str] = Depends(current_user)):
    webhook_url = os.getenv("CYBERGUARD_ALERT_WEBHOOK_URL")
    if webhook_url:
        try:
            response = requests.post(webhook_url, json=request.model_dump(), timeout=5)
            response.raise_for_status()
            return {"status": "dispatched", "channel": request.channel, "delivery": "webhook"}
        except requests.RequestException as error:
            raise HTTPException(status_code=502, detail=f"Alert integration failed: {error}") from error
    return {"status": "recorded", "channel": request.channel, "delivery": "simulation", "user": user["username"]}


@app.post("/api/v1/prevention/decision")
def prevention_decision(request: dict, user: dict[str, str] = Depends(current_user)):
    decision = risk_aware_prevention_decision(
        {
            "risk_score": request.get("risk_score", 0),
            "category": request.get("category", "unknown"),
            "payload": request.get("payload", ""),
            "asset_criticality": request.get("asset_criticality", "medium"),
        },
        {
            "role": request.get("user", {}).get("role") if isinstance(request.get("user"), dict) else user.get("role"),
            "team": request.get("user", {}).get("team") if isinstance(request.get("user"), dict) else user.get("username"),
        },
    )
    write_audit(user, "prevention_decision", str(request.get("category", "unknown")), decision["action"])
    return decision


@app.post("/api/v1/prevention/containment")
def prevention_containment(request: dict, user: dict[str, str] = Depends(current_user)):
    risk_score = int(request.get("risk_score", 0))
    if risk_score >= 85 and user.get("role") not in {"lead", "head_admin"}:
        write_audit(user, "prevention_containment_denied", str(request.get("incident_id", "unknown")), "High-impact containment requires SOC lead approval")
        raise HTTPException(status_code=403, detail="SOC lead approval required for high-impact containment")
    result = containment_action_plan({
        "risk_score": risk_score,
        "source_ip": request.get("source_ip", "unknown"),
        "category": request.get("category", "unknown"),
    })
    write_audit(user, "prevention_containment", str(request.get("incident_id", "unknown")), ",".join(result["actions"]))
    return result


@app.post("/api/v1/prevention/campaign-watch")
def prevention_campaign_watch(request: dict, user: dict[str, str] = Depends(current_user)):
    incidents = request.get("incidents", [])
    return campaign_aware_prevention(incidents)


@app.get("/api/v1/prevention/identity-trust")
def prevention_identity_trust(user: dict[str, str] = Depends(current_user)):
    return identity_trust_evaluation({"country": "US", "device": "new-device", "login_count": 3, "source_ip": "203.0.113.14"})


@app.get("/api/v1/prevention/insider-risk")
def prevention_insider_risk(user: dict[str, str] = Depends(current_user)):
    return insider_threat_risk({"downloads": 8, "off_hours": True, "privilege_change": True, "sensitive_access": 5})


@app.get("/api/v1/prevention/deception-status")
def prevention_deception_status(user: dict[str, str] = Depends(current_user)):
    return {"active_decoys": [{"type": "honeytoken", "host": "finance-host-01", "user": user.get("username", "analyst")}], "triggered_decoys": [
        {"type": "honeytoken", "host": "finance-host-01", "user": user.get("username", "analyst")}
    ], "compromised_assets": ["finance-host-01"]}


@app.get("/api/v1/prevention/policies")
def prevention_policies(user: dict[str, str] = Depends(current_user)):
    return {"policy_rules": ["strict_admin_controls", "phishing_blocking", "device_revalidation"], "department_profile": user.get("role", "analyst"), "enforcement_level": "strict"}


@app.post("/api/v1/rescue/scan")
def rescue_scan(request: dict, user: dict[str, str] = Depends(current_user)):
    result = scan_account(request)
    write_audit(user, "account_rescue_scan", result["scan_id"], f"risk={result['score']} level={result['risk_level']}")
    return result


@app.post("/api/v1/rescue/plan")
def rescue_plan_route(request: dict, user: dict[str, str] = Depends(current_user)):
    scan = request.get("scan") if isinstance(request.get("scan"), dict) else scan_account(request)
    result = rescue_plan(scan)
    write_audit(user, "account_rescue_plan", result["plan_id"], "Personalized rescue plan generated")
    return result


@app.post("/api/v1/rescue/step")
def rescue_step(request: dict, user: dict[str, str] = Depends(current_user)):
    plan = request.get("plan") or {}
    result = execute_step(plan, str(request.get("step_id", "")), bool(request.get("confirmed", False)))
    write_audit(user, "account_rescue_step", str(request.get("step_id", "unknown")), result["status"])
    return result


@app.post("/api/v1/rescue/evidence")
def rescue_evidence(request: dict, user: dict[str, str] = Depends(current_user)):
    result = evidence_snapshot(request.get("scan") or scan_account(request), str(request.get("account_label") or user.get("username", "connected-account")))
    write_audit(user, "account_rescue_evidence", result["evidence_id"], "Pre-action security snapshot created")
    return result


@app.post("/api/v1/rescue/lockdown")
def rescue_lockdown(request: dict, user: dict[str, str] = Depends(current_user)):
    if not request.get("confirmed"):
        return lockdown_plan(request.get("scan") or scan_account(request))
    if user.get("role") not in {"lead", "head_admin", "admin"}:
        raise HTTPException(status_code=403, detail="SOC lead approval required for emergency lockdown")
    result = lockdown_plan(request.get("scan") or scan_account(request))
    result.update({"status": "queued", "confirmed_by": user.get("username")})
    write_audit(user, "account_rescue_lockdown", result["lockdown_id"], "Emergency lockdown confirmed")
    return result


@app.post("/api/v1/rescue/guardian")
def rescue_guardian(request: dict, user: dict[str, str] = Depends(current_user)):
    result = guardian_watch(request.get("scan") or scan_account(request), bool(request.get("enabled", True)))
    write_audit(user, "guardian_mode", result["watch_id"], result["status"])
    return result


@app.get("/api/v1/rescue/locked-out")
def rescue_locked_out(provider: str = Query("generic"), user: dict[str, str] = Depends(current_user)):
    return locked_out_recovery(provider)


@app.get("/api/v1/rescue/blast-radius")
def rescue_blast_radius(provider: str = Query("generic"), user: dict[str, str] = Depends(current_user)):
    return blast_radius(provider)


@app.get("/api/v1/rescue/offline-card")
def rescue_offline_card(provider: str = Query("generic"), user: dict[str, str] = Depends(current_user)):
    return offline_rescue_card(provider)


@app.get("/api/v1/rescue/capabilities")
def rescue_capabilities(provider: str = Query("generic"), user: dict[str, str] = Depends(current_user)):
    return provider_capabilities(provider)


@app.post("/api/v1/rescue/simulate")
def rescue_simulate(request: dict, user: dict[str, str] = Depends(current_user)):
    return rescue_simulation(request.get("scan") or scan_account(request))


@app.post("/api/v1/rescue/report")
def rescue_report_route(request: dict, user: dict[str, str] = Depends(current_user)):
    result = rescue_report(request.get("scan") or scan_account(request), request.get("plan") or rescue_plan(request.get("scan") or scan_account(request)), request.get("actions", []))
    write_audit(user, "account_rescue_report", result["report_id"], "Incident rescue report generated")
    return result


@app.post("/api/v1/rescue/rollback")
def rescue_rollback(request: dict, user: dict[str, str] = Depends(current_user)):
    result = rollback_record(str(request.get("action_id", "unknown")), request.get("snapshot", {}))
    write_audit(user, "account_rescue_rollback", result["action_id"], "Rollback record prepared; provider restore requires authorization")
    return result


@app.post("/api/v1/rescue/consent")
def rescue_consent(request: dict, user: dict[str, str] = Depends(current_user)):
    return consent_record(str(request.get("provider", "generic")), [str(scope) for scope in request.get("scopes", [])], str(request.get("action", "scan")), bool(request.get("confirmed", False)))


@app.post("/api/v1/rescue/contact-warning")
def rescue_contact_warning(request: dict, user: dict[str, str] = Depends(current_user)):
    return contact_warning_draft(str(request.get("account_label", user.get("username", "account"))), request.get("contacts", []))


@app.post("/api/v1/rescue/guardian-contact")
def rescue_guardian_contact(request: dict, user: dict[str, str] = Depends(current_user)):
    contact = str(request.get("contact", "")).strip()
    if not contact:
        raise HTTPException(status_code=422, detail="contact is required")
    return guardian_contact(contact, bool(request.get("enabled", True)))


@app.post("/api/v1/rescue/fleet")
def rescue_fleet(request: dict, user: dict[str, str] = Depends(current_user)):
    return fleet_summary(request.get("accounts", []))


def _roadmap_incidents() -> list[dict[str, Any]]:
    return recent_incident_context()


@app.get("/api/v1/roadmap/economics/{incident_id}")
def roadmap_economics(incident_id: int, user: dict[str, str] = Depends(current_user)):
    return breach_economics(incident_context(incident_id))


@app.post("/api/v1/roadmap/honeytokens")
def roadmap_honeytokens(request: dict, user: dict[str, str] = Depends(current_user)):
    incident_id = request.get("incident_id")
    incident = incident_context(int(incident_id)) if incident_id else (_roadmap_incidents()[0] if _roadmap_incidents() else {"id": "preview", "category": "unknown"})
    result = seed_honeytokens(incident, int(request.get("count", 3)))
    write_audit(user, "honeytoken_preview", str(result["incident_id"]), "Simulation-only canary plan generated")
    return result


@app.post("/api/v1/roadmap/honeytokens/deploy")
def roadmap_honeytokens_deploy(request: dict, user: dict[str, str] = Depends(head_admin_user)):
    tokens = request.get("tokens", [])
    result = deploy_honeytokens(tokens, request.get("incident_id"))
    write_audit(user, "honeytoken_deploy", str(request.get("incident_id", "unknown")), result["status"])
    return result


@app.get("/api/v1/roadmap/bias")
def roadmap_bias(user: dict[str, str] = Depends(current_user)):
    with get_db() as db:
        audit = [dict(row) for row in db.execute("SELECT username, action, resource, created_at FROM audit_logs ORDER BY id DESC LIMIT 200").fetchall()]
    return analyst_bias_report(_roadmap_incidents(), audit)


@app.get("/api/v1/roadmap/immunity")
def roadmap_immunity(user: dict[str, str] = Depends(current_user)):
    return shared_immunity(_roadmap_incidents(), user.get("username", "default"))


@app.post("/api/v1/roadmap/immunity/publish")
def roadmap_immunity_publish(request: dict, user: dict[str, str] = Depends(head_admin_user)):
    signatures = request.get("signatures") or shared_immunity(_roadmap_incidents(), user.get("username", "default"))["shared_signatures"]
    result = publish_tenant_signatures(signatures, str(request.get("tenant_id") or user.get("username", "default")))
    write_audit(user, "tenant_immunity_publish", str(result.get("published", 0)), result["status"])
    return result


@app.get("/api/v1/roadmap/resource/{incident_id}")
def roadmap_resource_cost(incident_id: int, user: dict[str, str] = Depends(current_user)):
    return attacker_resource_cost(incident_context(incident_id))


@app.get("/api/v1/roadmap/attention")
def roadmap_attention(user: dict[str, str] = Depends(current_user)):
    with get_db() as db:
        events = [dict(row) for row in db.execute("SELECT action, resource, created_at FROM audit_logs ORDER BY id DESC LIMIT 200").fetchall()]
    return attention_heatmap(events)


@app.get("/api/v1/roadmap/jurisdiction/{incident_id}")
def roadmap_jurisdiction(incident_id: int, user: dict[str, str] = Depends(current_user)):
    return jurisdiction_route(incident_context(incident_id))


@app.post("/api/v1/roadmap/counterfactual/{incident_id}")
def roadmap_counterfactual(incident_id: int, request: dict, user: dict[str, str] = Depends(current_user)):
    return counterfactual_replay(
        incident_context(incident_id),
        [str(action) for action in request.get("actions", [])],
        str(request.get("variable", "response_delay_hours")),
        int(request.get("value", 4)),
    )


@app.post("/api/v1/roadmap/compliance-diff")
def roadmap_compliance_diff(request: dict, user: dict[str, str] = Depends(current_user)):
    controls = compliance_controls(user)["controls"]
    return compliance_diff(controls, request.get("cves", []))


@app.post("/api/v1/roadmap/compliance-diff/sync")
def roadmap_compliance_diff_sync(user: dict[str, str] = Depends(head_admin_user)):
    try:
        feed = sync_cve_feed()
    except requests.RequestException as error:
        raise HTTPException(status_code=502, detail=f"CVE feed synchronization failed: {error}") from error
    result = compliance_diff(compliance_controls(user)["controls"], feed.get("cves", []))
    return {"feed": feed, "diff": result}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
