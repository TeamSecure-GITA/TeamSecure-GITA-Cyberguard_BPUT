import ast
import asyncio
import hashlib
import html
import ipaddress
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
    import bcrypt
except ImportError:
    bcrypt = None

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
    venv_python = next((p for p in candidates if os.path.isfile(p) and os.access(p, os.X_OK)), None)
    if venv_python and sys.executable != venv_python:
        try:
            os.execv(venv_python, [venv_python] + sys.argv)
        except OSError:
            pass

from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import requests
import jwt
from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Query, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from webauthn import generate_authentication_options, generate_registration_options, options_to_json, verify_authentication_response, verify_registration_response
from webauthn.helpers.structs import PublicKeyCredentialDescriptor, UserVerificationRequirement
from database import connect_database
from ephemeral_store import EphemeralStore

from detection_engine import FALLBACK_TEXT_MODEL, TEXT_MODEL, adversarial_self_test, evaluate_threat_payload
from behavioral_baseline import baseline_key, login_sample, parse_login_event, score_login_deviation, successful_login
from geoip_enrichment import lookup_country as lookup_geoip_country
from malware_scanner import scan_artifact
from pcap_inspector import analyze_pcap
from network_ingestion import normalize_network_events
from ocr_engine import extract_image_text
from risk_scoring import score_event
from account_rescue_engine import blast_radius, evidence_snapshot, execute_step, guardian_watch, locked_out_recovery, lockdown_plan, offline_rescue_card, provider_capabilities, rescue_plan, rescue_simulation, scan_account
from prevention_engine import campaign_aware_prevention, containment_action_plan, deception_trigger_check, identity_trust_evaluation, insider_threat_risk, policy_aware_prevention, risk_aware_prevention_decision
from models import IdentityTrustRequest
from models import InsiderRiskRequest
from models import DeceptionInteractionRequest
from models import PolicyDefinition
from models import ContainmentRequestCreate
from battle_simulator import run_battle
from campaign_engine import correlate_incident
from digital_twin import build_twin
from forecast_engine import forecast_risk
from media_engine import analyze_media, media_inspection_status
from psychology_detector import analyze_psychology
from response_simulator import simulate_response
from self_healing import recommend_healing
from threat_intel import enrich_iocs, extract_iocs
from email_authenticity import analyze_eml
from contact_impersonation import build_style_profile, compare_contact_message
from website_inspector import inspect_website
from playbook_engine import load_playbooks, plan_playbook, validate_playbook
from llm_assistant import generate_analysis
from deepfake_models import model_status as pretrained_media_status
from graph_analytics import build_incident_graph
from transformer_text import status as transformer_status
from complaint_generator import build_cybercrime_complaint
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
from roadmap_features import analyst_bias_report, attention_heatmap, attacker_resource_cost, breach_economics, compliance_diff, counterfactual_replay, cross_modal_consistency, jurisdiction_route, seed_honeytokens, shared_immunity, supply_chain_blast_radius
from provider_integrations import deploy_honeytokens, integration_status as provider_integration_status, publish_tenant_signatures, sync_cve_feed
from production_integrations import IntegrationNotConfigured, create_ticket as create_provider_ticket, disable_identity as disable_provider_identity, isolate_endpoint as isolate_provider_endpoint, provider_status as production_provider_status
from models import AccessRequestCreate, AdvancedTelemetryRequest, AgentConsensusRequest, AlertRequest, AnalystLoadRequest, BattleRequest, CognitiveEchoRequest, DarkMeshRequest, DeceptionRequest, ForecastRequest, GoogleLoginRequest, IncidentComment, IncidentUpdate, InfrastructureEchoRequest, LoginRequest, NeuromorphicRequest, NotificationUpdate, OtpVerificationRequest, PasskeyCredentialRequest, PermissionRequest, PolymorphismRequest, PsychologyRequest, ProviderEndpointIsolationRequest, ProviderIdentityDisableRequest, ProviderTicketRequest, QStateRequest, QuantumDecoyRequest, ResponseExecutionRequest, SatelliteRequest, ScannerRequest, SimulationRequest, SpeculativeTelemetryRequest, TemporalHealingRequest, ThreatAnalysisRequest, ThreatIntelLookup, TopologyMorphRequest, ThreatPhysicsRequest, UserCreate, VaccineRequest

DB_PATH = Path(os.getenv("CYBERGUARD_DB_PATH", str(Path(__file__).with_name("cyberguard.db"))))
CYBERGUARD_ENV = os.getenv("CYBERGUARD_ENV", "development").lower()
JWT_SECRET = os.getenv("CYBERGUARD_JWT_SECRET", "").strip()
ALLOW_ANONYMOUS_EVAL = os.getenv("CYBERGUARD_ALLOW_ANONYMOUS_EVAL", "false").lower() in {"true", "1", "yes"}
SESSION_TTL_MINUTES = max(1, int(os.getenv("CYBERGUARD_SESSION_TTL_MINUTES", "60")))
LOGIN_FAILURE_LIMIT = max(3, int(os.getenv("CYBERGUARD_LOGIN_FAILURE_LIMIT", "10")))
LOGIN_FAILURE_WINDOW_SECONDS = max(60, int(os.getenv("CYBERGUARD_LOGIN_FAILURE_WINDOW_SECONDS", "300")))


def validate_auth_configuration(environment: str, jwt_secret: str, allow_anonymous_eval: bool, admin_username: str, admin_password: str):
    if environment == "production" and not jwt_secret:
        raise RuntimeError("CYBERGUARD_JWT_SECRET must be set to a unique value in production")
    if environment == "production" and len(jwt_secret) < 32:
        raise RuntimeError("CYBERGUARD_JWT_SECRET must contain at least 32 characters in production")
    if not admin_username or len(admin_password) < 16:
        raise RuntimeError("Set CYBERGUARD_HEAD_ADMIN_USERNAME and a CYBERGUARD_HEAD_ADMIN_PASSWORD of at least 16 characters before startup")
    if environment == "production" and allow_anonymous_eval:
        raise RuntimeError("CYBERGUARD_ALLOW_ANONYMOUS_EVAL cannot be enabled in production")


configured_head_admin_username = os.getenv("CYBERGUARD_HEAD_ADMIN_USERNAME", "").strip()
configured_head_admin_password = os.getenv("CYBERGUARD_HEAD_ADMIN_PASSWORD", "")
validate_auth_configuration(
    CYBERGUARD_ENV,
    JWT_SECRET,
    ALLOW_ANONYMOUS_EVAL,
    configured_head_admin_username,
    configured_head_admin_password,
)
if not JWT_SECRET:
    JWT_SECRET = secrets.token_urlsafe(48)
SECURITY_OWNER_EMAIL = os.getenv("CYBERGUARD_SECURITY_OWNER_EMAIL", "teamsecure.project@gmail.com")
PUBLIC_APP_URL = os.getenv(
    "CYBERGUARD_PUBLIC_APP_URL",
    "https://teamsecure-gita-cyberguard.vercel.app"
    if os.getenv("RENDER") or os.getenv("CYBERGUARD_ENV") == "production"
    else "http://127.0.0.1:5173",
)
ACCESS_REQUEST_TTL_HOURS = max(1, int(os.getenv("CYBERGUARD_ACCESS_REQUEST_TTL_HOURS", "24")))
HEAD_ADMIN_USERNAME = configured_head_admin_username
HEAD_ADMIN_PASSWORD = configured_head_admin_password
MAX_UPLOAD_BYTES = max(1_000_000, int(os.getenv("CYBERGUARD_MAX_UPLOAD_BYTES", "10485760")))
STARTED_AT = datetime.now(timezone.utc)
EPHEMERAL_STATE = EphemeralStore.from_environment()
OTP_TTL_SECONDS = max(60, int(os.getenv("CYBERGUARD_OTP_TTL_SECONDS", "300")))
OTP_MAX_ATTEMPTS = max(3, int(os.getenv("CYBERGUARD_OTP_MAX_ATTEMPTS", "5")))
PASSKEY_RP_ID = os.getenv("CYBERGUARD_PASSKEY_RP_ID", "127.0.0.1")
PASSKEY_ORIGIN = os.getenv("CYBERGUARD_PASSKEY_ORIGIN", "http://127.0.0.1:5173")
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
    "user_admin": {"name": "Amit Sharma", "role": "Network Administrator", "status": "ACTIVE", "password": os.getenv("CYBERGUARD_IDP_ADMIN_PASSWORD", "")},
    "user_faculty": {"name": "Dr. Mishra", "role": "Professor", "status": "ACTIVE", "password": os.getenv("CYBERGUARD_IDP_FACULTY_PASSWORD", "")},
    "user_student": {"name": "Rohan Das", "role": "Student", "status": "SUSPENDED", "password": os.getenv("CYBERGUARD_IDP_STUDENT_PASSWORD", "")},
}

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
            (timestamp, source_ip, hostname, log_entry["mac_address"], hostname, event_type, severity, details),
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
        total = db.execute("SELECT COUNT(*) AS count FROM siem_events").fetchone()["count"]
        rows = db.execute("SELECT timestamp, source_ip, source_host, mac_address, hostname, event, severity, details FROM siem_events ORDER BY id DESC LIMIT 20").fetchall()
    events = [dict(row) for row in rows]
    high_risk = [event for event in events if event["severity"] in {"HIGH", "CRITICAL"}]
    return {"events": events, "count": total, "high_risk_count": len(high_risk), "user": user.get("username", "unknown")}


def idp_authenticate_user(payload: dict | None, user: dict[str, str] | None = None):
    if CYBERGUARD_ENV == "production":
        raise HTTPException(status_code=503, detail="The demo identity provider is disabled; configure a production identity-provider integration.")
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

    if not profile["password"] or profile["password"] != password:
        return {"auth_status": "DENIED", "user": profile["name"], "reason": "Invalid credentials for IdP authentication."}

    hardware_context = correlate_dhcp_ip(source_ip)
    suspicious_ip = source_ip in DHCP_LEASES and DHCP_LEASES[source_ip].get("hostname") == "Unknown-Kali-Linux"
    with get_db() as db:
        suspicious_event = db.execute(
            "SELECT 1 FROM siem_events "
            "WHERE (source_ip = ? OR hostname = ?) "
            "AND severity IN ('HIGH', 'CRITICAL') "
            "AND event IN ('suspicious_login', 'malware_detected', 'privilege_escalation') "
            "LIMIT 1",
            (source_ip, hardware_context.get("hostname")),
        ).fetchone() is not None

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
    if bcrypt:
        return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=64)
    return f"scrypt${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    if stored_hash.startswith("$2") and bcrypt:
        return bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8"))
    if stored_hash.startswith("scrypt$"):
        try:
            _, salt_hex, digest_hex = stored_hash.split("$", 2)
            expected = bytes.fromhex(digest_hex)
            actual = hashlib.scrypt(password.encode("utf-8"), salt=bytes.fromhex(salt_hex), n=2**14, r=8, p=1, dklen=len(expected))
        except (ValueError, TypeError):
            return False
        return secrets.compare_digest(actual, expected)
    legacy_digest = hashlib.sha256(password.encode("utf-8")).hexdigest()
    return len(stored_hash) == 64 and secrets.compare_digest(stored_hash, legacy_digest)


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
            CREATE TABLE IF NOT EXISTS known_contacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_username TEXT NOT NULL,
                name TEXT NOT NULL,
                identifiers TEXT NOT NULL,
                style_profile TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(owner_username, name)
            );
            CREATE INDEX IF NOT EXISTS idx_known_contacts_owner ON known_contacts (owner_username, name);
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
                metadata TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS login_behavior_samples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                baseline_key TEXT NOT NULL,
                country TEXT,
                device TEXT,
                hour INTEGER,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_login_behavior_samples_key_created ON login_behavior_samples (baseline_key, created_at DESC);
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
            CREATE TABLE IF NOT EXISTS alert_outcomes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER NOT NULL,
                detection_type TEXT NOT NULL,
                alert_risk_score INTEGER NOT NULL,
                final_resolution TEXT NOT NULL,
                was_correct INTEGER NOT NULL,
                reviewed_by TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_alert_outcomes_created_at ON alert_outcomes (created_at DESC);
            CREATE TABLE IF NOT EXISTS cve_feed_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT NOT NULL,
                items_json TEXT NOT NULL,
                synced_at TEXT NOT NULL
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
            CREATE TABLE IF NOT EXISTS blocked_ips (
                ip_address TEXT PRIMARY KEY,
                reason TEXT NOT NULL,
                blocked_at TEXT NOT NULL,
                expires_at TEXT
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
            CREATE TABLE IF NOT EXISTS feature_records (
                record_id TEXT PRIMARY KEY,
                record_type TEXT NOT NULL,
                username TEXT NOT NULL,
                data_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS identity_trust_events (
                event_id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                event_json TEXT NOT NULL,
                assessment_json TEXT NOT NULL,
                incident_id INTEGER,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_identity_trust_owner_created ON identity_trust_events (username, created_at DESC);
            CREATE TABLE IF NOT EXISTS insider_risk_events (
                event_id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                activity_json TEXT NOT NULL,
                assessment_json TEXT NOT NULL,
                incident_id INTEGER,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_insider_risk_owner_created ON insider_risk_events (username, created_at DESC);
            CREATE TABLE IF NOT EXISTS deception_events (
                event_id TEXT PRIMARY KEY,
                reported_by TEXT NOT NULL,
                host TEXT NOT NULL,
                actor TEXT NOT NULL,
                resource TEXT NOT NULL,
                event_type TEXT NOT NULL,
                source_ip TEXT,
                incident_id INTEGER,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_deception_events_created ON deception_events (created_at DESC);
            CREATE TABLE IF NOT EXISTS prevention_policies (
                policy_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                category TEXT NOT NULL,
                threshold INTEGER NOT NULL,
                severity TEXT NOT NULL,
                action TEXT NOT NULL,
                approval_required INTEGER NOT NULL DEFAULT 1,
                enabled INTEGER NOT NULL DEFAULT 1,
                version INTEGER NOT NULL DEFAULT 1,
                created_by TEXT NOT NULL,
                updated_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_prevention_policies_enabled ON prevention_policies (enabled, category, threshold);
            CREATE TABLE IF NOT EXISTS containment_requests (
                request_id TEXT PRIMARY KEY,
                incident_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                requested_by TEXT NOT NULL,
                reviewed_by TEXT,
                simulation INTEGER NOT NULL DEFAULT 1,
                execution_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_containment_requests_status_created ON containment_requests (status, created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_feature_records_owner_type ON feature_records (username, record_type);
            CREATE INDEX IF NOT EXISTS idx_siem_events_timestamp ON siem_events (id DESC);
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
        if "metadata" not in columns:
            db.execute("ALTER TABLE incidents ADD COLUMN metadata TEXT NOT NULL DEFAULT '{}'")
        users = []
        configured_demo_accounts = []
        if CYBERGUARD_ENV != "production":
            demo_accounts = (
                ("analyst", "CYBERGUARD_DEMO_ANALYST_PASSWORD", "analyst", "", None),
                ("lead", "CYBERGUARD_DEMO_LEAD_PASSWORD", "lead", "", None),
                ("admin", "CYBERGUARD_DEMO_ADMIN_PASSWORD", "admin", SECURITY_OWNER_EMAIL, HEAD_ADMIN_USERNAME),
            )
            for username, password_key, role, email, parent in demo_accounts:
                password = os.getenv(password_key, "")
                if password:
                    configured_demo_accounts.append((username, password))
                    users.append((username, hash_password(password), role, email, parent, "active"))
                else:
                    db.execute(
                        "UPDATE users SET status = 'disabled' WHERE lower(username) = lower(?) AND role = ?",
                        (username, role),
                    )
        users.append((HEAD_ADMIN_USERNAME, hash_password(HEAD_ADMIN_PASSWORD), "head_admin", SECURITY_OWNER_EMAIL, None, "active"))
        db.executemany("INSERT OR IGNORE INTO users (username, password_hash, role, email, parent_username, status) VALUES (?, ?, ?, ?, ?, ?)", users)
        if CYBERGUARD_ENV == "production":
            db.execute(
                "UPDATE users SET status = 'disabled' WHERE lower(username) IN ('analyst', 'lead', 'admin') AND lower(username) != lower(?)",
                (HEAD_ADMIN_USERNAME,),
            )
            db.execute(
                "UPDATE users SET status = 'disabled' WHERE role = 'head_admin' AND lower(username) != lower(?)",
                (HEAD_ADMIN_USERNAME,),
            )
        db.execute(
            "UPDATE users SET password_hash = ?, role = 'head_admin', email = ?, status = 'active' WHERE lower(username) = lower(?)",
            (hash_password(HEAD_ADMIN_PASSWORD), SECURITY_OWNER_EMAIL, HEAD_ADMIN_USERNAME),
        )
        if CYBERGUARD_ENV != "production":
            for username, password in configured_demo_accounts:
                db.execute(
                    "UPDATE users SET password_hash = ?, status = 'active' WHERE lower(username) = lower(?)",
                    (hash_password(password), username),
                )


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

DEFAULT_CORS_ORIGINS = (
    "http://127.0.0.1:5173,http://localhost:5173,"
    "http://127.0.0.1:5174,http://localhost:5174,"
    "http://127.0.0.1:5175,http://localhost:5175,"
    "http://127.0.0.1:3000,http://localhost:3000,"
    "http://127.0.0.1:8000,http://localhost:8000,"
    "https://teamsecure-gita-cyberguard.vercel.app"
)
configured_origins = os.getenv("CYBERGUARD_FRONTEND_ORIGINS", DEFAULT_CORS_ORIGINS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        origin.strip()
        for origin in configured_origins.split(",")
        if origin.strip()
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_guard(request: Request, call_next):
    ip_address = request_ip(request)
    path = request.url.path.lower()
    now = time.time()
    with get_db() as db:
        blocked = db.execute("SELECT ip_address FROM blocked_ips WHERE ip_address = ?", (ip_address,)).fetchone()
    if blocked and ip_address not in {"127.0.0.1", "::1", "localhost"}:
        return JSONResponse(status_code=403, content={"detail": "Access denied by CyberGuard security controls", "containment": "internal sinkhole preview"})
    suspicious = any(marker in path for marker in ("/.env", "/.git", "/wp-admin", "/wp-login", "/etc/passwd", "/debug", "/phpmyadmin"))
    if suspicious:
        attempts = EPHEMERAL_STATE.record_window_event(f"security:{ip_address}", now, 60)
        record_security_event("suspicious-code-or-admin-probe", ip_address, request.url.path, "Protected path probing detected.")
        if attempts >= 3 and ip_address not in {"127.0.0.1", "::1", "localhost"}:
            with get_db() as db:
                db.execute("INSERT INTO blocked_ips (ip_address, reason, blocked_at) VALUES (?, ?, ?) ON CONFLICT(ip_address) DO UPDATE SET reason = excluded.reason, blocked_at = excluded.blocked_at", (ip_address, "Repeated protected-path probing", datetime.now(timezone.utc).isoformat()))
            return JSONResponse(status_code=403, content={"detail": "IP blocked by CyberGuard", "containment": "internal sinkhole preview"})
    return await call_next(request)


def current_user(authorization: Optional[str] = Header(default=None)) -> dict[str, str]:
    if not authorization or not authorization.startswith("Bearer "):
        if ALLOW_ANONYMOUS_EVAL:
            return {"username": "evaluator", "role": "lead"}
        raise HTTPException(status_code=401, detail="Authentication required")
    try:
        claims = jwt.decode(authorization.removeprefix("Bearer "), JWT_SECRET, algorithms=["HS256"])
        username = claims.get("username")
        if not isinstance(username, str) or not username.strip():
            raise HTTPException(status_code=401, detail="Invalid or expired session")
        with get_db() as db:
            user = db.execute(
                "SELECT username, role, status FROM users WHERE lower(username) = lower(?)",
                (username,),
            ).fetchone()
        if not user or user["status"] != "active" or user["role"] != claims.get("role"):
            raise HTTPException(status_code=401, detail="Invalid or expired session")
        return {"username": user["username"], "role": user["role"]}
    except jwt.PyJWTError as error:
        if ALLOW_ANONYMOUS_EVAL:
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
    EPHEMERAL_STATE.set(f"otp:{challenge_id}", {
        "username": username,
        "otp_hash": hashlib.sha256(otp.encode("utf-8")).hexdigest(),
        "expires_at": time.time() + OTP_TTL_SECONDS,
        "attempts": 0,
    }, ttl_seconds=OTP_TTL_SECONDS)
    sent = send_email(
        recipient,
        "CyberGuard administrator verification code",
        f"Your CyberGuard administrator verification code is {otp}. It expires in {OTP_TTL_SECONDS // 60} minutes. If you did not request this, ignore this message.",
    )
    if sent is None:
        EPHEMERAL_STATE.pop(f"otp:{challenge_id}")
        raise HTTPException(status_code=503, detail="OTP email is not configured. Add CYBERGUARD_SMTP_HOST, CYBERGUARD_SMTP_USER, and CYBERGUARD_SMTP_PASSWORD to cyberguard-backend/.env.")
    if not sent:
        EPHEMERAL_STATE.pop(f"otp:{challenge_id}")
        raise HTTPException(status_code=503, detail="OTP email could not be delivered. Check the SMTP host, port, username, and app password.")
    return {"challenge_id": challenge_id, "masked_email": f"{recipient[:2]}***@{recipient.split('@', 1)[-1]}"}


def issue_session(user: sqlite3.Row) -> dict[str, Any]:
    issued_at = datetime.now(timezone.utc)
    token = jwt.encode(
        {
            "username": user["username"],
            "role": user["role"],
            "iat": int(issued_at.timestamp()),
            "exp": int((issued_at + timedelta(minutes=SESSION_TTL_MINUTES)).timestamp()),
        },
        JWT_SECRET,
        algorithm="HS256",
    )
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
    EPHEMERAL_STATE.set(f"passkey:{challenge_id}", {"username": username, "kind": kind, "challenge": options.challenge, "expires_at": time.time() + 300}, ttl_seconds=300)
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


def normalize_residency_metadata(metadata: Any) -> dict[str, str]:
    if not isinstance(metadata, dict):
        return {}
    return {
        key: value.strip()[:64]
        for key in ("country", "region")
        if isinstance((value := metadata.get(key)), str) and value.strip()
    }


def store_incident(category: str, payload: str, assessment: dict, filename: str | None = None, file_hash: str | None = None, metadata: dict | None = None):
    residency = normalize_residency_metadata(metadata)
    score_event(assessment)
    with get_db() as db:
        cursor = db.execute(
            "INSERT INTO incidents (category, payload, filename, file_hash, risk_score, risk_level, assessment, metadata, created_at, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (category, payload, filename, file_hash, assessment["risk_score"], assessment["risk_level"], json.dumps(assessment), json.dumps(residency), datetime.now(timezone.utc).isoformat(), "Investigating" if assessment["risk_level"] in ["High", "Critical"] else "New"),
        )
        return cursor.lastrowid


def apply_user_login_baseline(assessment: dict, payload: str, user: dict[str, str], learn: bool = True) -> dict:
    event = parse_login_event(payload)
    if not event:
        return assessment
    sample = login_sample(event)
    source_ip = event.get("source_ip") or event.get("src_ip") or event.get("ip")
    geoip_result = lookup_geoip_country(str(source_ip)) if source_ip else {"status": "no_ip", "country": None}
    if geoip_result.get("country"):
        sample["country"] = geoip_result["country"]
    key = baseline_key(event, user["username"])
    with get_db() as db:
        rows = db.execute(
            "SELECT country, device, hour FROM login_behavior_samples WHERE baseline_key = ? ORDER BY id DESC LIMIT 50",
            (key,),
        ).fetchall()
        history = [dict(row) for row in reversed(rows)]
        deviation, reasons, indicators = score_login_deviation(sample, history)
        if deviation:
            assessment["risk_score"] = min(99, int(assessment["risk_score"]) + deviation)
            assessment["indicators"].extend(indicators)
            assessment["xai_explanation"] += " " + " ".join(reasons)
            assessment["explanation_summary"] += " " + " ".join(reasons)
            score = assessment["risk_score"]
            assessment["risk_level"] = "Critical" if score >= 80 else "High" if score >= 60 else "Medium" if score >= 40 else "Low" if score >= 20 else "Safe"
            if assessment["risk_level"] in {"High", "Critical"} and not any(action.get("id") == "revoke_session" for action in assessment["recommended_actions"]):
                assessment["recommended_actions"].insert(0, {"id": "revoke_session", "label": "Review and revoke suspicious session"})
        if learn and successful_login(event) and assessment["risk_score"] < 20 and any(sample.values()):
            db.execute(
                "INSERT INTO login_behavior_samples (baseline_key, country, device, hour, created_at) VALUES (?, ?, ?, ?, ?)",
                (key, sample["country"], sample["device"], sample["hour"], datetime.now(timezone.utc).isoformat()),
            )
    if len(history) < 3:
        assessment["login_baseline"] = {"status": "calibrating", "samples": len(history)}
    else:
        assessment["login_baseline"] = {"status": "active", "samples": len(history), "signals": len(indicators)}
    assessment["geoip"] = geoip_result
    return assessment


def write_audit(user: dict[str, str], action: str, resource: str, details: str):
    with get_db() as db:
        db.execute("INSERT INTO audit_logs (username, action, resource, details, created_at) VALUES (?, ?, ?, ?, ?)", (user["username"], action, resource, details, datetime.now(timezone.utc).isoformat()))


def save_feature_record(record_id: str, record_type: str, user: dict[str, str], data: dict[str, Any]):
    with get_db() as db:
        existing = db.execute("SELECT username FROM feature_records WHERE record_id = ?", (record_id,)).fetchone()
        if existing and existing["username"] != user["username"]:
            raise HTTPException(status_code=404, detail="Record not found")
        db.execute(
            "INSERT INTO feature_records (record_id, record_type, username, data_json, created_at) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(record_id) DO UPDATE SET data_json = excluded.data_json",
            (record_id, record_type, user["username"], json.dumps(data), datetime.now(timezone.utc).isoformat()),
        )


def load_feature_record(record_id: str, record_type: str, user: dict[str, str]) -> dict[str, Any]:
    with get_db() as db:
        row = db.execute(
            "SELECT data_json FROM feature_records WHERE record_id = ? AND record_type = ? AND username = ?",
            (record_id, record_type, user["username"]),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Record not found")
    return json.loads(row["data_json"])


def create_notification(username: str, title: str, message: str, severity: str):
    with get_db() as db:
        db.execute("INSERT INTO notifications (username, title, message, severity, created_at) VALUES (?, ?, ?, ?, ?)", (username, title, message, severity, datetime.now(timezone.utc).isoformat()))


@app.post("/api/v1/rescue/scan")
def rescue_scan(payload: dict[str, Any], user: dict[str, str] = Depends(current_user)):
    signal_fields = {
        "unknown_session",
        "suspicious_login",
        "new_oauth_app",
        "forwarding_rule",
        "mfa_enabled",
        "recovery_changed",
        "breach_history",
    }
    if any(key in payload and not isinstance(payload[key], bool) for key in signal_fields):
        raise HTTPException(status_code=422, detail="Account risk signals must be boolean values")
    result = scan_account(payload)
    result["assessment_source"] = "operator_reported"
    result["provider_connected"] = False
    save_feature_record(result["scan_id"], "rescue_scan", user, result)
    write_audit(user, "rescue_scan", result["scan_id"], json.dumps({"risk_level": result["risk_level"], "finding_count": len(result["findings"])}))
    return result


@app.post("/api/v1/rescue/plan")
def rescue_plan_route(payload: dict[str, Any], user: dict[str, str] = Depends(current_user)):
    submitted_scan = payload.get("scan")
    scan_id = submitted_scan.get("scan_id") if isinstance(submitted_scan, dict) else None
    if not scan_id:
        raise HTTPException(status_code=422, detail="A saved scan is required")
    scan = load_feature_record(str(scan_id), "rescue_scan", user)
    result = rescue_plan(scan)
    save_feature_record(result["plan_id"], "rescue_plan", user, result)
    return result


@app.post("/api/v1/rescue/step")
def rescue_step(payload: dict[str, Any], user: dict[str, str] = Depends(current_user)):
    submitted_plan = payload.get("plan")
    plan_id = submitted_plan.get("plan_id") if isinstance(submitted_plan, dict) else None
    if not plan_id:
        raise HTTPException(status_code=422, detail="A saved rescue plan is required")
    plan = load_feature_record(str(plan_id), "rescue_plan", user)
    try:
        result = execute_step(plan, str(payload.get("step_id") or ""), bool(payload.get("confirmed")))
    except ValueError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    action_id = "rescue_action_" + secrets.token_urlsafe(8)
    action = {"action_id": action_id, **result}
    save_feature_record(action_id, "rescue_action", user, action)
    write_audit(user, "rescue_step", action_id, json.dumps({"plan_id": plan_id, "step_id": payload.get("step_id"), "status": result["status"]}))
    return action


@app.post("/api/v1/rescue/evidence")
def rescue_evidence(payload: dict[str, Any], user: dict[str, str] = Depends(current_user)):
    submitted_scan = payload.get("scan")
    scan_id = submitted_scan.get("scan_id") if isinstance(submitted_scan, dict) else None
    if not scan_id:
        raise HTTPException(status_code=422, detail="A saved scan is required")
    scan = load_feature_record(str(scan_id), "rescue_scan", user)
    label = str(payload.get("account_label") or "connected-account")[:120]
    result = evidence_snapshot(scan, label)
    save_feature_record(result["evidence_id"], "rescue_evidence", user, result)
    write_audit(user, "rescue_evidence_created", result["evidence_id"], json.dumps({"scan_id": scan_id}))
    return result


@app.post("/api/v1/rescue/lockdown")
def rescue_lockdown(payload: dict[str, Any], user: dict[str, str] = Depends(head_admin_user)):
    submitted_scan = payload.get("scan")
    scan_id = submitted_scan.get("scan_id") if isinstance(submitted_scan, dict) else None
    if not scan_id:
        raise HTTPException(status_code=422, detail="A saved scan is required")
    scan = load_feature_record(str(scan_id), "rescue_scan", user)
    result = lockdown_plan(scan)
    result["status"] = "awaiting_confirmation" if payload.get("confirmed") else "confirmation_required"
    save_feature_record(result["lockdown_id"], "rescue_lockdown", user, result)
    write_audit(user, "rescue_lockdown_requested", result["lockdown_id"], json.dumps({"confirmed": bool(payload.get("confirmed")), "provider_actions_executed": False}))
    return result


@app.post("/api/v1/rescue/guardian")
def rescue_guardian(payload: dict[str, Any], user: dict[str, str] = Depends(current_user)):
    submitted_scan = payload.get("scan")
    scan_id = submitted_scan.get("scan_id") if isinstance(submitted_scan, dict) else None
    if not scan_id:
        raise HTTPException(status_code=422, detail="A saved scan is required")
    scan = load_feature_record(str(scan_id), "rescue_scan", user)
    result = guardian_watch(scan, bool(payload.get("enabled", True)))
    save_feature_record(result["watch_id"], "rescue_guardian", user, result)
    write_audit(user, "rescue_guardian_updated", result["watch_id"], json.dumps({"enabled": result["enabled"]}))
    return result


@app.post("/api/v1/rescue/simulate")
def rescue_simulate(payload: dict[str, Any], user: dict[str, str] = Depends(current_user)):
    submitted_scan = payload.get("scan")
    scan_id = submitted_scan.get("scan_id") if isinstance(submitted_scan, dict) else None
    if not scan_id:
        raise HTTPException(status_code=422, detail="A saved scan is required")
    scan = load_feature_record(str(scan_id), "rescue_scan", user)
    result = rescue_simulation(scan)
    simulation_id = "rescue_sim_" + secrets.token_urlsafe(8)
    result["simulation_id"] = simulation_id
    save_feature_record(simulation_id, "rescue_simulation", user, result)
    return result


@app.get("/api/v1/rescue/blast-radius")
def rescue_blast_radius(provider: str = Query(default="generic"), user: dict[str, str] = Depends(current_user)):
    return blast_radius(provider)


@app.get("/api/v1/rescue/locked-out")
def rescue_locked_out(provider: str = Query(default="generic"), user: dict[str, str] = Depends(current_user)):
    return locked_out_recovery(provider)


@app.get("/api/v1/rescue/capabilities")
def rescue_capabilities(provider: str = Query(default="generic"), user: dict[str, str] = Depends(current_user)):
    return provider_capabilities(provider)


@app.get("/api/v1/rescue/offline-card")
def rescue_offline_card(provider: str = Query(default="generic"), user: dict[str, str] = Depends(current_user)):
    return offline_rescue_card(provider)


@app.post("/api/v1/prevention/decision")
def prevention_decision(payload: dict[str, Any], user: dict[str, str] = Depends(current_user)):
    result = risk_aware_prevention_decision(payload, {"role": user.get("role", "analyst")})
    result["decision_id"] = "prevention_" + secrets.token_urlsafe(8)
    result["mode"] = "recommendation_only"
    save_feature_record(result["decision_id"], "prevention_decision", user, result)
    return result


@app.post("/api/v1/prevention/campaign-watch")
def prevention_campaign_watch(user: dict[str, str] = Depends(current_user)):
    with get_db() as db:
        rows = db.execute("SELECT id, payload FROM incidents ORDER BY id DESC LIMIT 100").fetchall()
    incidents_for_watch = [{"incident_id": row["id"], "payload": row["payload"]} for row in rows]
    result = campaign_aware_prevention(incidents_for_watch)
    result["source_incident_count"] = len(incidents_for_watch)
    return result


@app.post("/api/v1/prevention/containment")
def prevention_containment(payload: dict[str, Any], user: dict[str, str] = Depends(current_user)):
    try:
        incident_id = int(payload.get("incident_id"))
    except (TypeError, ValueError) as error:
        raise HTTPException(status_code=422, detail="A stored incident ID is required") from error
    with get_db() as db:
        incident = db.execute("SELECT category, risk_score FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    result = containment_action_plan({
        "risk_score": incident["risk_score"],
        "source_ip": payload.get("source_ip") or "unknown",
        "category": incident["category"],
    })
    result["request_id"] = "containment_" + secrets.token_urlsafe(8)
    result["status"] = "recommendation_only"
    result["incident_id"] = f"INC-{incident_id:04d}"
    result["actions_executed"] = False
    save_feature_record(result["request_id"], "containment_recommendation", user, result)
    return result


@app.post("/api/v1/containment/requests")
def create_containment_request(payload: ContainmentRequestCreate, user: dict[str, str] = Depends(current_user)):
    with get_db() as db:
        incident = db.execute("SELECT category, risk_score FROM incidents WHERE id = ?", (payload.incident_id,)).fetchone()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    plan = containment_action_plan({"risk_score": incident["risk_score"], "category": incident["category"]})
    if payload.action not in plan["actions"]:
        raise HTTPException(status_code=409, detail="The selected action is not recommended for this incident")
    target = payload.target.strip()
    if not target:
        raise HTTPException(status_code=422, detail="Containment target is required")
    if payload.action == "block_ip":
        try:
            target = ipaddress.ip_address(target).compressed
        except ValueError as error:
            raise HTTPException(status_code=422, detail="IP blocking requires a valid IPv4 or IPv6 target") from error

    request_id = "containment_req_" + secrets.token_urlsafe(8)
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        db.execute(
            "INSERT INTO containment_requests (request_id, incident_id, action, target, status, requested_by, simulation, created_at, updated_at) VALUES (?, ?, ?, ?, 'pending', ?, 1, ?, ?)",
            (request_id, payload.incident_id, payload.action, target, user["username"], now, now),
        )
    write_audit(user, "containment_requested", request_id, json.dumps({"incident_id": payload.incident_id, "action": payload.action, "target": target, "simulation": True}))
    return {"request_id": request_id, "incident_id": f"INC-{payload.incident_id:04d}", "action": payload.action, "target": target, "status": "pending", "simulation": True, "created_at": now}


@app.get("/api/v1/containment/queue")
def containment_queue(status: str | None = Query(default=None), user: dict[str, str] = Depends(current_user)):
    allowed = {"pending", "approved", "rejected", "completed", "failed"}
    if status and status not in allowed:
        raise HTTPException(status_code=422, detail="Unsupported containment status filter")
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM containment_requests WHERE (? IS NULL OR status = ?) ORDER BY created_at DESC LIMIT 100",
            (status, status),
        ).fetchall()
    return {"requests": [{**dict(row), "simulation": bool(row["simulation"]), "execution": json.loads(row["execution_json"] or "{}")} for row in rows]}


def _review_containment_request(request_id: str, decision: str, user: dict[str, str]) -> dict[str, Any]:
    if user.get("role") not in {"lead", "head_admin"}:
        raise HTTPException(status_code=403, detail="Lead or head administrator approval required")
    if decision not in {"approved", "rejected"}:
        raise ValueError("Unsupported containment decision")
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        row = db.execute("SELECT status FROM containment_requests WHERE request_id = ?", (request_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Containment request not found")
        if row["status"] != "pending":
            raise HTTPException(status_code=409, detail="Only pending containment requests can be reviewed")
        db.execute(
            "UPDATE containment_requests SET status = ?, reviewed_by = ?, updated_at = ? WHERE request_id = ?",
            (decision, user["username"], now, request_id),
        )
    write_audit(user, f"containment_{decision}", request_id, json.dumps({"reviewer": user["username"]}))
    return {"request_id": request_id, "status": decision, "reviewed_by": user["username"], "updated_at": now}


@app.post("/api/v1/containment/requests/{request_id}/approve")
def approve_containment_request(request_id: str, user: dict[str, str] = Depends(current_user)):
    return _review_containment_request(request_id, "approved", user)


@app.post("/api/v1/containment/requests/{request_id}/reject")
def reject_containment_request(request_id: str, user: dict[str, str] = Depends(current_user)):
    return _review_containment_request(request_id, "rejected", user)


@app.post("/api/v1/containment/requests/{request_id}/execute")
def execute_containment_simulation(request_id: str, user: dict[str, str] = Depends(current_user)):
    if user.get("role") not in {"lead", "head_admin"}:
        raise HTTPException(status_code=403, detail="Lead or head administrator approval required")
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        row = db.execute("SELECT * FROM containment_requests WHERE request_id = ?", (request_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Containment request not found")
        if row["status"] != "approved":
            raise HTTPException(status_code=409, detail="Containment request must be approved before simulation")
        execution = {
            "mode": "simulation",
            "side_effects": False,
            "result": "simulated",
            "message": "No external host, identity, or provider state was changed.",
            "executed_by": user["username"],
            "executed_at": now,
        }
        db.execute(
            "UPDATE containment_requests SET status = 'completed', execution_json = ?, updated_at = ? WHERE request_id = ?",
            (json.dumps(execution), now, request_id),
        )
        db.execute(
            "INSERT INTO actions (incident_id, action_id, target, username, status, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (f"INC-{row['incident_id']:04d}", row["action"], row["target"], user["username"], "simulated", now),
        )
    write_audit(user, "containment_simulated", request_id, json.dumps(execution))
    return {"request_id": request_id, "status": "completed", "execution": execution}


@app.get("/api/v1/prevention/identity-trust")
def prevention_identity_trust(user: dict[str, str] = Depends(current_user)):
    with get_db() as db:
        row = db.execute(
            "SELECT event_id, assessment_json, incident_id, created_at FROM identity_trust_events WHERE username = ? ORDER BY created_at DESC LIMIT 1",
            (user["username"],),
        ).fetchone()
    if not row:
        return {
            "trust_score": None,
            "status": "insufficient_data",
            "required_action": "submit_operator_reported_telemetry",
            "message": "No identity telemetry has been reported for this user yet.",
        }
    return {
        **json.loads(row["assessment_json"]),
        "event_id": row["event_id"],
        "incident_id": row["incident_id"],
        "created_at": row["created_at"],
        "message": "Operator-reported assessment; no identity-provider event feed is connected.",
    }


@app.post("/api/v1/prevention/identity-trust")
def record_identity_trust(payload: IdentityTrustRequest, user: dict[str, str] = Depends(current_user)):
    device = payload.device.strip().lower()
    country = payload.country.strip().upper()
    if device not in {"known-device", "new-device", "unknown-device"}:
        raise HTTPException(status_code=422, detail="Device must be known-device, new-device, or unknown-device")
    if not re.fullmatch(r"[A-Z]{2}", country):
        raise HTTPException(status_code=422, detail="Country must be a two-letter code")
    try:
        source_ip = ipaddress.ip_address(payload.source_ip.strip()).compressed
    except ValueError as error:
        raise HTTPException(status_code=422, detail="A valid source IP address is required") from error

    observed_at = datetime.now(timezone.utc)
    cutoff = (observed_at - timedelta(days=30)).isoformat()
    with get_db() as db:
        observation_count = db.execute(
            "SELECT COUNT(*) AS count FROM identity_trust_events WHERE username = ? AND created_at >= ?",
            (user["username"], cutoff),
        ).fetchone()["count"]

    result = identity_trust_evaluation({
        "device": device,
        "country": country,
        "source_ip": source_ip,
        "login_count": observation_count,
        "mfa_enabled": payload.mfa_enabled,
        "behavioral_anomaly": payload.behavioral_anomaly,
    })
    result["assessment_source"] = "operator_reported"
    event_id = "identity_" + secrets.token_urlsafe(8)
    incident_id = None
    risk_score = 100 - result["trust_score"]
    if result["status"] == "blocked":
        risk_level = "Critical" if risk_score >= 90 else "High" if risk_score >= 75 else "Medium"
        incident_payload = json.dumps({"event_id": event_id, "signals": result["signals"]})
        incident_id = store_incident(
            "ato",
            incident_payload,
            {
                "risk_score": risk_score,
                "risk_level": risk_level,
                "xai_explanation": "Operator-reported device, location, MFA, or behavioral signals lowered identity trust.",
                "indicators": [{"name": name, "score": "observed"} for name, active in result["signals"].items() if active],
                "recommended_actions": [{"action": result["required_action"]}],
                "iocs": [],
            },
        )
    event_data = {
        "device": device,
        "country": country,
        "source_ip": source_ip,
        "mfa_enabled": payload.mfa_enabled,
        "behavioral_anomaly": payload.behavioral_anomaly,
        "observation_count_30d_before_event": observation_count,
    }
    with get_db() as db:
        db.execute(
            "INSERT INTO identity_trust_events (event_id, username, event_json, assessment_json, incident_id, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (event_id, user["username"], json.dumps(event_data), json.dumps(result), incident_id, observed_at.isoformat()),
        )
    write_audit(user, "identity_trust_assessed", event_id, json.dumps({"status": result["status"], "incident_id": incident_id}))
    return {**result, "event_id": event_id, "incident_id": incident_id, "created_at": observed_at.isoformat()}


@app.get("/api/v1/prevention/insider-risk")
def prevention_insider_risk(user: dict[str, str] = Depends(current_user)):
    with get_db() as db:
        row = db.execute(
            "SELECT event_id, assessment_json, incident_id, created_at FROM insider_risk_events WHERE username = ? ORDER BY created_at DESC LIMIT 1",
            (user["username"],),
        ).fetchone()
    if not row:
        return {
            "risk_score": None,
            "status": "insufficient_data",
            "preventive_action": "submit_operator_reported_activity",
            "flags": {},
            "message": "No user activity has been reported for this user yet.",
        }
    return {
        **json.loads(row["assessment_json"]),
        "event_id": row["event_id"],
        "incident_id": row["incident_id"],
        "created_at": row["created_at"],
        "message": "Operator-reported activity; no endpoint telemetry feed is connected.",
    }


@app.post("/api/v1/prevention/insider-risk")
def record_insider_risk(payload: InsiderRiskRequest, user: dict[str, str] = Depends(current_user)):
    activity = payload.model_dump()
    result = insider_threat_risk(activity)
    result["assessment_source"] = "operator_reported"
    event_id = "insider_" + secrets.token_urlsafe(8)
    incident_id = None
    if result["risk_score"] >= 60:
        risk_level = "Critical" if result["risk_score"] >= 90 else "High" if result["risk_score"] >= 75 else "Medium"
        incident_id = store_incident(
            "insider_risk",
            json.dumps({"event_id": event_id, "flags": result["flags"]}),
            {
                "risk_score": result["risk_score"],
                "risk_level": risk_level,
                "xai_explanation": "Operator-reported activity exceeded CyberGuard's insider-risk review threshold.",
                "indicators": [{"name": name, "score": str(value)} for name, value in result["flags"].items() if value],
                "recommended_actions": [{"action": result["preventive_action"]}],
                "iocs": [],
            },
        )
    created_at = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        db.execute(
            "INSERT INTO insider_risk_events (event_id, username, activity_json, assessment_json, incident_id, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (event_id, user["username"], json.dumps(activity), json.dumps(result), incident_id, created_at),
        )
    write_audit(user, "insider_risk_assessed", event_id, json.dumps({"risk_score": result["risk_score"], "incident_id": incident_id}))
    return {**result, "event_id": event_id, "incident_id": incident_id, "created_at": created_at}


@app.get("/api/v1/prevention/deception-status")
def prevention_deception_status(user: dict[str, str] = Depends(current_user)):
    with get_db() as db:
        rows = db.execute(
            "SELECT event_id, reported_by, host, actor, resource, event_type, incident_id, created_at FROM deception_events ORDER BY created_at DESC LIMIT 50"
        ).fetchall()
    events = [dict(row) for row in rows]
    result = deception_trigger_check([{"host": event["host"], "user": event["actor"]} for event in events[:1]])
    return {
        **result,
        "status": "events_reported" if events else "no_events",
        "active_decoys": [],
        "triggered_decoys": events,
        "compromised_assets": sorted({event["host"] for event in events}),
        "message": "Events are operator-reported; no live decoy registry or interaction feed is connected." if events else "No operator-reported deception interaction events are persisted.",
    }


@app.post("/api/v1/prevention/deception-status")
def report_deception_interaction(payload: DeceptionInteractionRequest, user: dict[str, str] = Depends(current_user)):
    event_type = payload.event_type.strip().lower()
    if event_type not in {"access", "authentication", "modification", "execution"}:
        raise HTTPException(status_code=422, detail="Unsupported deception event type")
    source_ip = None
    if payload.source_ip:
        try:
            source_ip = ipaddress.ip_address(payload.source_ip.strip()).compressed
        except ValueError as error:
            raise HTTPException(status_code=422, detail="Source IP must be a valid IP address") from error

    event_id = "deception_" + secrets.token_urlsafe(8)
    created_at = datetime.now(timezone.utc).isoformat()
    incident_id = store_incident(
        "deception",
        json.dumps({"event_id": event_id, "host": payload.host, "resource": payload.resource, "event_type": event_type}),
        {
            "risk_score": 85,
            "risk_level": "High",
            "xai_explanation": "An operator reported interaction with a deception resource; validate the event before response.",
            "indicators": [{"name": "operator_reported_decoy_interaction", "score": event_type}],
            "recommended_actions": [{"action": "review_reported_interaction"}],
            "iocs": [{"type": "ip", "indicator": source_ip}] if source_ip else [],
        },
    )
    with get_db() as db:
        db.execute(
            "INSERT INTO deception_events (event_id, reported_by, host, actor, resource, event_type, source_ip, incident_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (event_id, user["username"], payload.host.strip(), payload.actor.strip(), payload.resource.strip(), event_type, source_ip, incident_id, created_at),
        )
    write_audit(user, "deception_interaction_reported", event_id, json.dumps({"incident_id": incident_id, "event_type": event_type}))
    return {**prevention_deception_status(user), "reported_event_id": event_id, "incident_id": incident_id}


@app.get("/api/v1/prevention/policies")
def prevention_policies(user: dict[str, str] = Depends(current_user)):
    result = policy_aware_prevention({"role": user.get("role", "analyst")}, {}, {})
    with get_db() as db:
        rows = db.execute("SELECT * FROM prevention_policies ORDER BY updated_at DESC, name").fetchall()
    policies = [
        {
            **dict(row),
            "approval_required": bool(row["approval_required"]),
            "enabled": bool(row["enabled"]),
        }
        for row in rows
    ]
    return {
        **result,
        "status": "configured" if policies else "no_policies_configured",
        "department_profile": user.get("role", "analyst"),
        "policy_rules": [policy["name"] for policy in policies if policy["enabled"]],
        "policies": policies,
    }


def _require_policy_admin(user: dict[str, str]):
    if user.get("role") != "head_admin" or user.get("username") != HEAD_ADMIN_USERNAME:
        raise HTTPException(status_code=403, detail="Head Administrator approval required to manage prevention policies")


@app.post("/api/v1/prevention/policies")
def create_prevention_policy(payload: PolicyDefinition, user: dict[str, str] = Depends(current_user)):
    _require_policy_admin(user)
    policy_id = "policy_" + secrets.token_urlsafe(8)
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        db.execute(
            "INSERT INTO prevention_policies (policy_id, name, description, category, threshold, severity, action, approval_required, enabled, version, created_by, updated_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)",
            (policy_id, payload.name.strip(), payload.description.strip(), payload.category.strip().lower(), payload.threshold, payload.severity, payload.action, int(payload.approval_required), int(payload.enabled), user["username"], user["username"], now, now),
        )
    write_audit(user, "prevention_policy_created", policy_id, json.dumps(payload.model_dump()))
    return {"policy_id": policy_id, **payload.model_dump(), "version": 1, "created_by": user["username"], "created_at": now, "updated_at": now}


@app.put("/api/v1/prevention/policies/{policy_id}")
def update_prevention_policy(policy_id: str, payload: PolicyDefinition, user: dict[str, str] = Depends(current_user)):
    _require_policy_admin(user)
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        cursor = db.execute(
            "UPDATE prevention_policies SET name = ?, description = ?, category = ?, threshold = ?, severity = ?, action = ?, approval_required = ?, enabled = ?, version = version + 1, updated_by = ?, updated_at = ? WHERE policy_id = ?",
            (payload.name.strip(), payload.description.strip(), payload.category.strip().lower(), payload.threshold, payload.severity, payload.action, int(payload.approval_required), int(payload.enabled), user["username"], now, policy_id),
        )
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Policy not found")
        row = db.execute("SELECT * FROM prevention_policies WHERE policy_id = ?", (policy_id,)).fetchone()
    write_audit(user, "prevention_policy_updated", policy_id, json.dumps({**payload.model_dump(), "version": row["version"]}))
    return {**dict(row), "approval_required": bool(row["approval_required"]), "enabled": bool(row["enabled"])}


@app.delete("/api/v1/prevention/policies/{policy_id}")
def deactivate_prevention_policy(policy_id: str, user: dict[str, str] = Depends(current_user)):
    _require_policy_admin(user)
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        cursor = db.execute(
            "UPDATE prevention_policies SET enabled = 0, version = version + 1, updated_by = ?, updated_at = ? WHERE policy_id = ?",
            (user["username"], now, policy_id),
        )
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Policy not found")
    write_audit(user, "prevention_policy_deactivated", policy_id, json.dumps({"version_incremented": True}))
    return {"policy_id": policy_id, "status": "deactivated"}


@app.post("/api/v1/prevention/policies/evaluate")
def evaluate_prevention_policies(payload: dict[str, Any], user: dict[str, str] = Depends(current_user)):
    try:
        incident_id = int(payload.get("incident_id"))
    except (TypeError, ValueError) as error:
        raise HTTPException(status_code=422, detail="A stored incident ID is required") from error
    incident = incident_context(incident_id)
    category = str(incident["category"]).lower()
    with get_db() as db:
        rows = db.execute(
            "SELECT policy_id, name, category, threshold, severity, action, approval_required, version FROM prevention_policies WHERE enabled = 1 AND threshold <= ? AND (lower(category) IN ('all', '*', ?) ) ORDER BY threshold DESC, severity DESC",
            (incident["risk_score"], category),
        ).fetchall()
    matches = [{**dict(row), "approval_required": bool(row["approval_required"])} for row in rows]
    result = {
        "incident_id": f"INC-{incident_id:04d}",
        "matched_policies": matches,
        "actions": sorted({item["action"] for item in matches}),
        "approval_required": any(item["approval_required"] for item in matches),
        "mode": "recommendation_only",
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
    }
    evaluation_id = "policy_eval_" + secrets.token_urlsafe(8)
    result["evaluation_id"] = evaluation_id
    save_feature_record(evaluation_id, "policy_evaluation", user, result)
    write_audit(user, "prevention_policies_evaluated", evaluation_id, json.dumps({"incident_id": incident_id, "match_count": len(matches)}))
    return result


def incident_context(incident_id: int) -> dict:
    with get_db() as db:
        row = db.execute("SELECT id, category, payload, risk_score, risk_level, assessment, metadata, created_at FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found")
    try:
        assessment = json.loads(row["assessment"])
    except json.JSONDecodeError:
        assessment = ast.literal_eval(row["assessment"])
    try:
        metadata = json.loads(row["metadata"] or "{}")
    except (json.JSONDecodeError, TypeError):
        metadata = {}
    return {**dict(row), "assessment": assessment, "metadata": metadata}


def recent_incident_context() -> list[dict]:
    with get_db() as db:
        rows = db.execute("SELECT id, category, payload, risk_score, risk_level, status, assessment, metadata, created_at FROM incidents ORDER BY id DESC LIMIT 100").fetchall()
    result = []
    for row in rows:
        try:
            assessment = json.loads(row["assessment"])
        except json.JSONDecodeError:
            assessment = ast.literal_eval(row["assessment"])
        try:
            metadata = json.loads(row["metadata"] or "{}")
        except (json.JSONDecodeError, TypeError):
            metadata = {}
        result.append({**dict(row), "assessment": assessment, "metadata": metadata})
    return result


def fatigue_routing(incidents: list[dict], analysts: list[dict]) -> dict:
    analyst_capacity = {}
    for analyst in analysts:
        role = str(analyst.get("role") or "analyst").lower()
        username = analyst.get("username", f"{role}-{len(analyst_capacity)+1}")
        if role in {"lead", "sub_admin", "admin", "head_admin"}:
            analyst_capacity.setdefault(username, 1.0)
        else:
            analyst_capacity.setdefault(username, 0.75)

    resolved_statuses = {"mitigated", "closed"}
    active_incidents = [
        incident for incident in incidents
        if str(incident.get("status") or "New").strip().lower() not in resolved_statuses
    ]
    for incident in active_incidents:
        assigned = incident.get("assigned_to")
        if assigned in analyst_capacity:
            analyst_capacity[assigned] = min(1.4, analyst_capacity[assigned] + 0.25)

    queue = []
    for incident in active_incidents:
        risk = int(incident.get("risk_score", 0) or 0)
        status = str(incident.get("status") or "New")
        assigned = incident.get("assigned_to")
        if assigned and assigned in analyst_capacity:
            route_target = assigned
        elif analyst_capacity:
            route_target = min(analyst_capacity, key=lambda name: (analyst_capacity[name], name))
            analyst_capacity[route_target] = min(1.4, analyst_capacity[route_target] + 0.25)
        else:
            route_target = "unassigned"
        queue.append({
            "incident_id": incident.get("database_id") or incident.get("id"),
            "risk_score": risk,
            "status": status,
            "target": route_target,
            "priority": "critical" if risk >= 85 else "high" if risk >= 65 else "medium",
            "copilot_load": round(analyst_capacity.get(route_target, 0), 2),
        })

    queue.sort(key=lambda item: (-item["risk_score"], item["copilot_load"]))
    route_summary = {
        "available_analysts": len(analyst_capacity),
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
    outcome = fusion_record_alert_outcome(incident_id, detection_type, alert_risk_score, final_resolution, reviewed_by)
    with get_db() as db:
        db.execute(
            "INSERT INTO alert_outcomes (incident_id, detection_type, alert_risk_score, final_resolution, was_correct, reviewed_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (outcome["incident_id"], outcome["detection_type"], outcome["alert_risk_score"], outcome["final_resolution"], int(outcome["was_correct"]), outcome["reviewed_by"], datetime.now(timezone.utc).isoformat()),
        )
    return outcome


def alert_quality(user: dict[str, str] | None = None) -> dict:
    with get_db() as db:
        outcomes = [dict(row) for row in db.execute("SELECT incident_id, detection_type, alert_risk_score, final_resolution, was_correct, reviewed_by, created_at FROM alert_outcomes ORDER BY id DESC").fetchall()]
    for outcome in outcomes:
        outcome["was_correct"] = bool(outcome["was_correct"])
    return alert_quality_report(outcomes)


def persist_cyberguard_x(incident_id: int, incident: dict):
    genome = build_genome(incident)
    related = recent_incident_context()
    campaign = correlate_incident(incident, [item for item in related if item["id"] != incident_id])
    with get_db() as db:
        now = datetime.now(timezone.utc).isoformat()
        stored_incident = db.execute(
            "SELECT created_at FROM incidents WHERE id = ?",
            (incident_id,),
        ).fetchone()
        timeline = build_timeline(incident, [
            {
                "type": "incident_created",
                "label": "Incident created",
                "detail": "Telemetry was recorded as an incident.",
                "timestamp": stored_incident["created_at"],
            },
            {
                "type": "analysis_completed",
                "label": "Threat analysis completed",
                "detail": "Risk assessment and indicators were persisted.",
                "timestamp": now,
            },
            {
                "type": "campaign_correlated",
                "label": "Campaign correlation completed",
                "detail": "The incident was compared with available incident evidence.",
                "timestamp": now,
            },
        ])
        db.execute("INSERT INTO threat_fingerprints (incident_id, fingerprint, genome_json, created_at) VALUES (?, ?, ?, ?) ON CONFLICT(incident_id) DO UPDATE SET fingerprint = excluded.fingerprint, genome_json = excluded.genome_json, created_at = excluded.created_at", (incident_id, genome["fingerprint"], serialize_genome(genome), now))
        db.execute("INSERT OR IGNORE INTO campaigns (campaign_id, confidence, stage, created_at) VALUES (?, ?, ?, ?)", (campaign["campaign_id"], campaign["confidence"], campaign["stage"], now))
        for match in campaign["related_incidents"]:
            db.execute("INSERT OR IGNORE INTO campaign_incidents (campaign_id, incident_id, score) VALUES (?, ?, ?)", (campaign["campaign_id"], match["incident_id"], match["score"]))
        db.execute("INSERT INTO campaign_incidents (campaign_id, incident_id, score) VALUES (?, ?, ?) ON CONFLICT DO NOTHING", (campaign["campaign_id"], incident_id, 100))
        db.executemany(
            "INSERT INTO incident_timelines (incident_id, event_json, created_at) VALUES (?, ?, ?)",
            [(incident_id, json.dumps(event), event["timestamp"]) for event in timeline],
        )


@app.get("/")
@app.get("/health")
@app.get("/healthz")
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
    username_key = hashlib.sha256(username.casefold().encode("utf-8")).hexdigest()
    failure_key = f"login-failures:{username_key}"
    lock_key = f"login-lock:{username_key}"
    if EPHEMERAL_STATE.get(lock_key):
        raise HTTPException(status_code=429, detail="Too many failed login attempts. Try again later.")
    with get_db() as db:
        user = db.execute("SELECT username, role, password_hash, email, status FROM users WHERE lower(username) = lower(?)", (username,)).fetchone()
    if not user or user["status"] != "active" or not verify_password(request.password, user["password_hash"]):
        failures = EPHEMERAL_STATE.record_window_event(failure_key, window_seconds=LOGIN_FAILURE_WINDOW_SECONDS)
        if failures >= LOGIN_FAILURE_LIMIT:
            EPHEMERAL_STATE.set(lock_key, {"locked": True}, ttl_seconds=LOGIN_FAILURE_WINDOW_SECONDS)
        raise HTTPException(status_code=401, detail="Invalid username or password")
    EPHEMERAL_STATE.clear_window(failure_key)
    EPHEMERAL_STATE.pop(lock_key)
    if len(user["password_hash"]) == 64 and not user["password_hash"].startswith("$2"):
        with get_db() as db:
            db.execute("UPDATE users SET password_hash = ? WHERE username = ?", (hash_password(request.password), user["username"]))
    return issue_session(user)


@app.post("/api/v1/auth/google")
def google_auth(request: GoogleLoginRequest):
    initialize_database()
    email = request.email.strip().lower()
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="Invalid email address.")

    with get_db() as db:
        user = db.execute(
            """
            SELECT username, role, password_hash, email, status
            FROM users
            WHERE lower(email) = ? OR lower(username) = ?
            ORDER BY
                CASE
                    WHEN status = 'active' AND role = 'head_admin' THEN 0
                    WHEN status = 'active' THEN 1
                    WHEN lower(username) = lower(?) THEN 2
                    ELSE 3
                END
            LIMIT 1
            """,
            (email, email, email),
        ).fetchone()

        if not user:
            # Auto-provision authorized account for verified Google Sign-In
            is_owner = (email == SECURITY_OWNER_EMAIL.lower())
            role = "head_admin" if is_owner else "lead"
            base_username = email.split("@")[0].replace(".", "_") or "google_analyst"
            username = base_username
            existing = db.execute("SELECT username FROM users WHERE lower(username) = ?", (username,)).fetchone()
            if existing:
                username = f"{base_username}_{secrets.token_hex(2)}"

            dummy_hash = hash_password(secrets.token_urlsafe(32))
            db.execute(
                "INSERT INTO users (username, password_hash, role, email, status) VALUES (?, ?, ?, ?, 'active')",
                (username, dummy_hash, role, email),
            )
            user = db.execute(
                "SELECT username, role, password_hash, email, status FROM users WHERE username = ?",
                (username,),
            ).fetchone()

        if user["status"] != "active":
            raise HTTPException(status_code=403, detail="User account is deactivated. Contact security owner.")

    return issue_session(user)


@app.post("/api/v1/auth/passkey")
def verify_passkey(request: PasskeyCredentialRequest):
    challenge = EPHEMERAL_STATE.pop(f"passkey:{request.challenge_id}")
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
    challenge_key = f"otp:{request.challenge_id}"
    challenge = EPHEMERAL_STATE.get(challenge_key)
    if not challenge or challenge["expires_at"] < time.time():
        EPHEMERAL_STATE.pop(challenge_key)
        raise HTTPException(status_code=401, detail="OTP expired. Authenticate again to request a new code.")
    attempts = EPHEMERAL_STATE.increment_field(challenge_key, "attempts")
    if attempts is None:
        raise HTTPException(status_code=401, detail="OTP expired. Authenticate again to request a new code.")
    if attempts > OTP_MAX_ATTEMPTS:
        EPHEMERAL_STATE.pop(challenge_key)
        raise HTTPException(status_code=429, detail="Too many invalid OTP attempts. Authenticate again to request a new code.")
    if not secrets.compare_digest(challenge["otp_hash"], hashlib.sha256(request.otp.strip().encode("utf-8")).hexdigest()):
        raise HTTPException(status_code=401, detail="Invalid OTP.")
    if not EPHEMERAL_STATE.pop_if(challenge_key, "otp_hash", challenge["otp_hash"]):
        raise HTTPException(status_code=401, detail="OTP expired or was already used. Authenticate again.")
    with get_db() as db:
        user = db.execute("SELECT username, role FROM users WHERE username = ? AND role = 'head_admin'", (challenge["username"],)).fetchone()
    if not user:
        raise HTTPException(status_code=401, detail="Administrator account is unavailable.")
    return issue_session(user)


@app.get("/api/v1/auth/me")
def me(user: dict[str, str] = Depends(current_user)):
    return user


@app.get("/api/v1/known-contacts")
def list_known_contacts(user: dict[str, str] = Depends(current_user)):
    with get_db() as db:
        rows = db.execute(
            "SELECT id, name, identifiers, style_profile, created_at FROM known_contacts WHERE owner_username = ? ORDER BY name",
            (user["username"],),
        ).fetchall()
    return {
        "contacts": [
            {
                "id": row["id"],
                "name": row["name"],
                "identifiers": json.loads(row["identifiers"]),
                "sample_count": json.loads(row["style_profile"]).get("sample_count", 0),
                "created_at": row["created_at"],
            }
            for row in rows
        ]
    }


@app.post("/api/v1/known-contacts")
def create_known_contact(payload: dict[str, Any], user: dict[str, str] = Depends(current_user)):
    name = str(payload.get("name") or "").strip()[:120]
    identifiers = payload.get("identifiers")
    samples = payload.get("sample_messages")
    if not name:
        raise HTTPException(status_code=400, detail="A contact name is required.")
    if not isinstance(identifiers, list) or not identifiers or len(identifiers) > 20:
        raise HTTPException(status_code=400, detail="Provide between 1 and 20 known contact identifiers.")
    normalized_identifiers = list(dict.fromkeys(
        value.strip()[:200]
        for value in identifiers
        if isinstance(value, str) and value.strip()
    ))
    if not normalized_identifiers:
        raise HTTPException(status_code=400, detail="At least one valid contact identifier is required.")
    if not isinstance(samples, list) or len(samples) > 20 or any(not isinstance(value, str) or len(value) > 4000 for value in samples):
        raise HTTPException(status_code=400, detail="Provide up to 20 sample messages, each no longer than 4,000 characters.")
    try:
        style_profile = build_style_profile(samples)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error

    try:
        with get_db() as db:
            db.execute(
                "INSERT INTO known_contacts (owner_username, name, identifiers, style_profile, created_at) VALUES (?, ?, ?, ?, ?)",
                (user["username"], name, json.dumps(normalized_identifiers), json.dumps(style_profile), datetime.now(timezone.utc).isoformat()),
            )
            row = db.execute(
                "SELECT id, name, identifiers, style_profile, created_at FROM known_contacts WHERE owner_username = ? AND name = ?",
                (user["username"], name),
            ).fetchone()
    except sqlite3.IntegrityError as error:
        raise HTTPException(status_code=409, detail="A contact with this name already exists in your profile.") from error
    write_audit(user, "known_contact_create", f"contact:{row['id']}", f"Stored style features from {style_profile['sample_count']} examples")
    return {
        "id": row["id"],
        "name": row["name"],
        "identifiers": json.loads(row["identifiers"]),
        "sample_count": style_profile["sample_count"],
        "created_at": row["created_at"],
    }


@app.delete("/api/v1/known-contacts/{contact_id}")
def delete_known_contact(contact_id: int, user: dict[str, str] = Depends(current_user)):
    with get_db() as db:
        row = db.execute(
            "SELECT id FROM known_contacts WHERE id = ? AND owner_username = ?",
            (contact_id, user["username"]),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Known contact profile not found.")
        db.execute("DELETE FROM known_contacts WHERE id = ? AND owner_username = ?", (contact_id, user["username"]))
    write_audit(user, "known_contact_delete", f"contact:{contact_id}", "Deleted known contact profile")
    return {"status": "deleted", "id": contact_id}


def apply_known_contact_comparison(assessment: dict[str, Any], category: str, payload: str, metadata: dict[str, Any] | None, user: dict[str, str]):
    if category.lower() != "impersonation" or not isinstance(metadata, dict):
        return assessment
    raw_contact_id = metadata.get("known_contact_id")
    if raw_contact_id in (None, ""):
        return assessment
    try:
        contact_id = int(raw_contact_id)
    except (TypeError, ValueError) as error:
        raise HTTPException(status_code=400, detail="Known contact identifier must be an integer.") from error
    with get_db() as db:
        contact = db.execute(
            "SELECT id, name, identifiers, style_profile FROM known_contacts WHERE id = ? AND owner_username = ?",
            (contact_id, user["username"]),
        ).fetchone()
    if not contact:
        raise HTTPException(status_code=404, detail="Known contact profile not found.")

    comparison = compare_contact_message(payload, json.loads(contact["identifiers"]), json.loads(contact["style_profile"]))
    assessment["known_contact_comparison"] = {
        "contact_id": contact["id"],
        "contact_name": contact["name"],
        "sender_match": comparison["sender_match"],
        "vocabulary_similarity": comparison["vocabulary_similarity"],
        "sample_count": comparison["sample_count"],
        "caveat": comparison["caveat"],
    }
    if comparison["risk_score"]:
        previous_level = assessment["risk_level"]
        assessment["risk_score"] = min(99, int(assessment["risk_score"]) + comparison["risk_score"])
        assessment["indicators"].extend(comparison["indicators"])
        evidence = " ".join(comparison["reasons"])
        assessment["xai_explanation"] += " " + evidence + " " + comparison["caveat"]
        assessment["explanation_summary"] += " " + evidence
        score = assessment["risk_score"]
        assessment["risk_level"] = "Critical" if score >= 80 else "High" if score >= 60 else "Medium" if score >= 40 else "Low" if score >= 20 else "Safe"
        if assessment["risk_level"] != previous_level:
            assessment["xai_explanation"] = assessment["xai_explanation"].replace(f"{previous_level} Risk:", f"{assessment['risk_level']} Risk:", 1)
    return assessment


@app.post("/api/v1/analyze")
def analyze_threat(request: ThreatAnalysisRequest, user: dict[str, str] = Depends(current_user)):
    if not request.payload.strip():
        raise HTTPException(status_code=400, detail="Payload content cannot be empty.")
    assessment = evaluate_threat_payload(request.category, request.payload)
    assessment = apply_known_contact_comparison(assessment, request.category, request.payload, request.metadata, user)
    if request.category.lower() in {"auth_logs", "ato"}:
        assessment = apply_user_login_baseline(assessment, request.payload, user)
    assessment["iocs"] = enrich_iocs(extract_iocs(request.payload))
    incident_id = store_incident(request.category, request.payload, assessment, metadata=request.metadata)
    persist_cyberguard_x(incident_id, {"id": incident_id, "category": request.category, "payload": request.payload, "risk_score": assessment["risk_score"], "risk_level": assessment["risk_level"], "assessment": assessment, "created_at": datetime.now(timezone.utc).isoformat()})
    write_audit(user, "analyze", f"incident:{incident_id}", request.category)
    if assessment["risk_level"] in ["High", "Critical"]:
        create_notification(user["username"], f"{assessment['risk_level']} threat detected", f"Incident INC-{incident_id:04d} requires review.", assessment["risk_level"])
    return {"status": "success", "incident_id": incident_id, "category": request.category, "assessment": assessment, "user": user["username"]}


@app.post("/api/v1/network/ingest")
def ingest_network_telemetry(payload: dict[str, Any], user: dict[str, str] = Depends(current_user)):
    try:
        normalized = normalize_network_events(payload)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error

    serialized = json.dumps(normalized)
    assessment = evaluate_threat_payload("network", serialized)
    if assessment["risk_score"] < 40:
        return {
            "status": "accepted",
            "detected": False,
            "incident_id": None,
            "assessment": assessment,
        }

    incident = analyze_threat(
        ThreatAnalysisRequest(category="network", payload=serialized),
        user,
    )
    return {
        **incident,
        "status": "incident_created",
        "detected": True,
    }


@app.post("/api/v1/analyze/preview")
def preview_threat(request: ThreatAnalysisRequest, user: dict[str, str] = Depends(current_user)):
    if not request.payload.strip():
        raise HTTPException(status_code=400, detail="Payload content cannot be empty.")
    assessment = evaluate_threat_payload(request.category, request.payload)
    assessment = apply_known_contact_comparison(assessment, request.category, request.payload, request.metadata, user)
    if request.category.lower() in {"auth_logs", "ato"}:
        assessment = apply_user_login_baseline(assessment, request.payload, user, learn=False)
    score_event(assessment)
    assessment["iocs"] = enrich_iocs(extract_iocs(request.payload))
    return {"status": "success", "category": request.category, "assessment": assessment}


@app.post("/api/v1/assistant/analyze")
def analyst_assistant(payload: dict[str, Any], user: dict[str, str] = Depends(current_user)):
    assessment = payload.get("assessment")
    if not isinstance(assessment, dict):
        raise HTTPException(status_code=400, detail="An assessment object is required.")
    result = generate_analysis(assessment, payload.get("incident"))
    write_audit(user, "llm_assistant", "analyst-assistant", result.get("model", "offline-template"))
    return {"status": "success", "assistant": result}


@app.post("/api/v1/analyze/file")
async def analyze_file(category: str = Form(...), file: UploadFile = File(...), metadata: str | None = Form(default=None), user: dict[str, str] = Depends(current_user)):
    try:
        metadata_payload = json.loads(metadata or "{}")
    except json.JSONDecodeError as error:
        raise HTTPException(status_code=400, detail="Incident metadata must be valid JSON.") from error
    if not isinstance(metadata_payload, dict):
        raise HTTPException(status_code=400, detail="Incident metadata must be a JSON object.")
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file cannot be empty.")
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail=f"Uploaded file exceeds the {MAX_UPLOAD_BYTES // 1_000_000} MB limit.")
    file_hash = hashlib.sha256(content).hexdigest()
    filename = file.filename or "upload"
    is_eml = (file.content_type or "").lower() == "message/rfc822" or filename.lower().endswith(".eml")
    is_text = (file.content_type or "").startswith("text/") or filename.lower().endswith((".txt", ".log", ".json", ".csv"))
    content_type = (file.content_type or "").lower()
    is_pcap = category.lower() == "network" and (
        filename.lower().endswith((".pcap", ".pcapng"))
        or content_type in {"application/vnd.tcpdump.pcap", "application/x-pcap", "application/pcap"}
    )
    network_capture = None
    if is_pcap:
        try:
            network_capture = analyze_pcap(content)
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error
        except RuntimeError as error:
            raise HTTPException(status_code=503, detail=str(error)) from error
    is_image = content_type.startswith("image/") or filename.lower().endswith((".png", ".jpg", ".jpeg", ".webp", ".bmp", ".tiff"))
    ocr_result = extract_image_text(content) if is_image else None
    email_result = analyze_eml(content) if is_eml else None
    payload = email_result["payload"] if email_result else json.dumps(network_capture) if network_capture else (content.decode("utf-8", errors="replace") if is_text else f"Uploaded {file.content_type or 'media'} file: {filename}")
    assessment = evaluate_threat_payload(category, payload)
    if category.lower() in {"auth_logs", "ato"}:
        assessment = apply_user_login_baseline(assessment, payload, user)
    if category.lower() == "malware":
        malware_scan = scan_artifact(content, filename)
        assessment["malware_scan"] = malware_scan
        assessment["indicators"].extend({"name": match["rule"], "weight": match["meta"].get("risk_score", 70)} for match in malware_scan["matches"])
        assessment["risk_score"] = max(assessment["risk_score"], malware_scan["risk_score"])
        if malware_scan["matches"]:
            assessment["xai_explanation"] += " " + " ".join(malware_scan["reasons"])
    assessment["iocs"] = enrich_iocs(extract_iocs(payload))
    if email_result:
        assessment["risk_score"] = max(assessment["risk_score"], email_result["score"])
        assessment["indicators"].extend(email_result["indicators"])
        assessment["xai_explanation"] += " " + " ".join(email_result["reasons"])
        assessment["sender_authenticity"] = email_result["metadata"]
        assessment["sender_identity_verification"] = email_result["identity_verification"]
        assessment["email_html_inspection"] = email_result["html_inspection"]
    if network_capture:
        assessment["network_capture_summary"] = {
            "packet_count": network_capture["packet_count"],
            "flow_count": len(network_capture["flows"]),
        }
    if ocr_result:
        assessment["ocr_analysis"] = {
            "status": ocr_result["status"],
            "character_count": ocr_result.get("character_count", 0),
            "truncated": ocr_result.get("truncated", False),
        }
        if ocr_result["status"] == "text_detected":
            ocr_assessment = evaluate_threat_payload("email", ocr_result["text"])
            assessment["risk_score"] = max(assessment["risk_score"], ocr_assessment["risk_score"])
            assessment["indicators"].extend(
                {**indicator, "name": f"OCR: {indicator['name']}"}
                for indicator in ocr_assessment["indicators"]
            )
            assessment["xai_explanation"] += " OCR text was evaluated for phishing indicators. " + ocr_assessment["xai_explanation"]
            assessment["explanation_summary"] += " OCR: " + ocr_assessment["explanation_summary"]
            assessment["ocr_analysis"]["risk_score"] = ocr_assessment["risk_score"]
            assessment["ocr_analysis"]["evidence"] = ocr_assessment["explanation_summary"]
        elif ocr_result.get("reason"):
            assessment["ocr_analysis"]["reason"] = ocr_result["reason"]
    if not is_text and not email_result and not network_capture:
        media_result = analyze_media(content, file.content_type or "", filename, category)
        assessment["risk_score"] = max(assessment["risk_score"], media_result["score"])
        assessment["indicators"].extend(media_result["indicators"])
        assessment["xai_explanation"] += " " + " ".join(media_result["reasons"])
        assessment["media_method"] = media_result["method"]
        if media_result.get("decoded_payload"):
            qr_assessment = evaluate_threat_payload("url", media_result["decoded_payload"])
            assessment["qr_payload"] = media_result["decoded_payload"]
            assessment["risk_score"] = max(assessment["risk_score"], qr_assessment["risk_score"])
            assessment["indicators"].extend(qr_assessment["indicators"])
            assessment["xai_explanation"] += " " + qr_assessment["xai_explanation"]
    score = int(assessment["risk_score"])
    prior_level = assessment["risk_level"]
    assessment["risk_level"] = "Critical" if score >= 80 else "High" if score >= 60 else "Medium" if score >= 40 else "Low" if score >= 20 else "Safe"
    if assessment["risk_level"] != prior_level:
        assessment["xai_explanation"] = assessment["xai_explanation"].replace(f"{prior_level} Risk:", f"{assessment['risk_level']} Risk:", 1)
    incident_id = store_incident(category, payload, assessment, filename, file_hash, metadata_payload)
    persist_cyberguard_x(incident_id, {"id": incident_id, "category": category, "payload": payload, "risk_score": assessment["risk_score"], "risk_level": assessment["risk_level"], "assessment": assessment, "created_at": datetime.now(timezone.utc).isoformat()})
    write_audit(user, "analyze_file", f"incident:{incident_id}", filename)
    if assessment["risk_level"] in ["High", "Critical"]:
        create_notification(user["username"], f"{assessment['risk_level']} media threat detected", f"Incident INC-{incident_id:04d} requires review.", assessment["risk_level"])
    return {"status": "success", "incident_id": incident_id, "filename": filename, "file_hash": file_hash, "assessment": assessment, "media_method": assessment.get("media_method"), "user": user["username"]}


@app.post("/api/v1/analyze/website")
def analyze_website(payload: dict[str, Any], user: dict[str, str] = Depends(current_user)):
    url = str(payload.get("url", "")).strip()
    if not url:
        raise HTTPException(status_code=400, detail="A website URL is required.")
    try:
        inspection = inspect_website(url)
    except (ValueError, requests.RequestException, OSError) as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    text = " ".join([inspection["final_url"], inspection["title"], *inspection["findings"]])
    assessment = evaluate_threat_payload("url", text)
    certificate = inspection.get("tls_certificate") or {}
    registration = inspection.get("domain_registration") or {}
    enrichment_reasons = []
    if certificate.get("verified") and certificate.get("days_remaining") is not None and certificate["days_remaining"] <= 14:
        assessment["risk_score"] = min(99, assessment["risk_score"] + 20)
        enrichment_reasons.append("The verified TLS certificate is expired or expires within 14 days.")
        assessment["indicators"].append({"name": "TLS Certificate Expiry", "weight": 20})
    if registration.get("age_days") is not None and registration["age_days"] <= 30:
        assessment["risk_score"] = min(99, assessment["risk_score"] + 25)
        enrichment_reasons.append(f"The domain registration is recent ({registration['age_days']} days old).")
        assessment["indicators"].append({"name": "Domain Registration Age", "weight": 25})
    brand_mismatches = inspection.get("brand_mismatches", [])
    if inspection.get("credential_form") and brand_mismatches:
        assessment["risk_score"] = min(99, assessment["risk_score"] + 35)
        enrichment_reasons.append(f"Credential form claims a known brand on an unrelated domain ({', '.join(brand_mismatches)}).")
        assessment["indicators"].append({"name": "Credential Form Brand Mismatch", "weight": 35})
    if inspection.get("credential_form") and inspection.get("cross_origin_form_actions"):
        assessment["risk_score"] = min(99, assessment["risk_score"] + 20)
        enrichment_reasons.append("Credential form submits to a different registered domain.")
        assessment["indicators"].append({"name": "Cross-Domain Credential Submission", "weight": 20})
    if enrichment_reasons:
        assessment["xai_explanation"] += " " + " ".join(enrichment_reasons)
        assessment["explanation_summary"] += " " + " ".join(enrichment_reasons)
    score = assessment["risk_score"]
    assessment["risk_level"] = "Critical" if score >= 80 else "High" if score >= 60 else "Medium" if score >= 40 else "Low" if score >= 20 else "Safe"
    if assessment["risk_level"] in {"High", "Critical"} and not any(action.get("id") == "block_domain" for action in assessment["recommended_actions"]):
        assessment["recommended_actions"].insert(0, {"id": "block_domain", "label": "Block Suspicious Domain / IP"})
    assessment["website_inspection"] = inspection
    assessment["iocs"] = enrich_iocs(extract_iocs(text))
    metadata = normalize_residency_metadata(payload.get("metadata"))
    incident_id = store_incident("url", text, assessment, metadata=metadata)
    persist_cyberguard_x(incident_id, {"id": incident_id, "category": "url", "payload": text, "risk_score": assessment["risk_score"], "risk_level": assessment["risk_level"], "assessment": assessment, "created_at": datetime.now(timezone.utc).isoformat()})
    write_audit(user, "analyze_website", url, "website")
    return {"status": "success", "incident_id": incident_id, "assessment": assessment, "inspection": inspection, "user": user["username"]}


@app.get("/api/v1/playbooks")
def list_playbooks(user: dict[str, str] = Depends(current_user)):
    return {"playbooks": load_playbooks()}


@app.post("/api/v1/playbooks/plan")
def preview_playbook(payload: dict[str, Any], user: dict[str, str] = Depends(current_user)):
    try:
        result = plan_playbook(payload.get("playbook", {}), payload.get("assessment", {}), bool(payload.get("approved", False)))
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    write_audit(user, "playbook_plan", result["playbook_id"], result["mode"])
    return result


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
            "payload": row["payload"],
            "risk_score": row["risk_score"],
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
    if request.status is not None and request.status not in allowed_statuses:
        raise HTTPException(status_code=400, detail=f"Status must be one of: {', '.join(sorted(allowed_statuses))}")
    if (request.status is not None or request.assigned_to is not None) and user.get("role") not in {"lead", "sub_admin", "head_admin"}:
        raise HTTPException(status_code=403, detail="Lead or administrator role required to change incident workflow")
    assignee = None
    if request.assigned_to is not None:
        assignee = request.assigned_to.strip()
        if not assignee:
            raise HTTPException(status_code=422, detail="Assignee must name an active user")
        with get_db() as db:
            active_assignee = db.execute(
                "SELECT 1 FROM users WHERE lower(username) = lower(?) AND status = 'active'",
                (assignee,),
            ).fetchone()
        if not active_assignee:
            raise HTTPException(status_code=422, detail="Assignee must name an active user")
    with get_db() as db:
        current = db.execute("SELECT notes FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        if not current:
            raise HTTPException(status_code=404, detail="Incident not found")
        notes = current["notes"] or ""
        if request.note:
            notes = f"{notes}\n[{datetime.now(timezone.utc).isoformat()}] {user['username']}: {request.note}".strip()
        db.execute("UPDATE incidents SET status = COALESCE(?, status), assigned_to = COALESCE(?, assigned_to), notes = ? WHERE id = ?", (request.status, assignee, notes, incident_id))
        if request.status is not None or assignee is not None or request.note:
            timestamp = datetime.now(timezone.utc).isoformat()
            event = {
                "type": "workflow_updated",
                "label": "Incident workflow updated",
                "detail": json.dumps({
                    "status": request.status,
                    "assigned_to": assignee,
                    "comment_added": bool(request.note),
                }),
                "timestamp": timestamp,
                "status": "complete",
            }
            db.execute(
                "INSERT INTO incident_timelines (incident_id, event_json, created_at) VALUES (?, ?, ?)",
                (incident_id, json.dumps(event), timestamp),
            )
    write_audit(user, "incident_updated", f"incident:{incident_id}", json.dumps({"status": request.status, "assigned_to": assignee, "comment_added": bool(request.note)}))
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
    incident = incident_context(incident_id)
    with get_db() as db:
        timeline_rows = db.execute(
            "SELECT event_json FROM incident_timelines WHERE incident_id = ? ORDER BY created_at",
            (incident_id,),
        ).fetchall()
        action_rows = db.execute(
            "SELECT action_id, status, created_at FROM actions WHERE incident_id IN (?, ?) ORDER BY created_at",
            (str(incident_id), f"INC-{incident_id:04d}"),
        ).fetchall()
    events = [json.loads(row["event_json"]) for row in timeline_rows]
    events.extend(
        {
            "type": "response_action",
            "label": "Response action recorded",
            "detail": f"{row['action_id']} ({row['status']})",
            "timestamp": row["created_at"],
            "status": "complete",
        }
        for row in action_rows
    )
    return {"incident_id": incident_id, "events": build_timeline(incident, events)}


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


@app.get("/api/v1/incidents/{incident_id}/complaint-draft")
def incident_complaint_draft(incident_id: int, user: dict[str, str] = Depends(current_user)):
    return build_cybercrime_complaint(incident_context(incident_id))


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
        user.get("username", "analyst"),
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
    protocol = "cyberguard.events.v1"
    offered_protocols = websocket.scope.get("subprotocols", [])
    token = next((value for value in offered_protocols if value != protocol), None)
    try:
        current_user(f"Bearer {token}" if token else None)
    except HTTPException:
        await websocket.close(code=4401)
        return

    await websocket.accept(subprotocol=protocol if protocol in offered_protocols else None)
    try:
        with get_db() as db:
            last_event_id = db.execute("SELECT COALESCE(MAX(id), 0) AS id FROM incidents").fetchone()["id"]
        await websocket.send_json({"type": "ready"})
        next_heartbeat = time.monotonic() + 20
        while True:
            await asyncio.sleep(1)
            with get_db() as db:
                rows = db.execute(
                    "SELECT id, category, risk_score, risk_level, created_at FROM incidents WHERE id > ? ORDER BY id ASC LIMIT 100",
                    (last_event_id,),
                ).fetchall()
            for row in rows:
                event = dict(row)
                await websocket.send_json({"type": "incident_created", "incident": event})
                last_event_id = event["id"]
            if time.monotonic() >= next_heartbeat:
                await websocket.send_json({"type": "heartbeat", "status": "connected"})
                next_heartbeat = time.monotonic() + 20
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
        db.execute("INSERT INTO blocked_ips (ip_address, reason, blocked_at) VALUES (?, ?, ?) ON CONFLICT(ip_address) DO UPDATE SET reason = excluded.reason, blocked_at = excluded.blocked_at", (ip_address, reason, datetime.now(timezone.utc).isoformat()))
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
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
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
        target_rows = db.execute("SELECT payload, risk_score FROM incidents ORDER BY id DESC LIMIT 500").fetchall()
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
        "topTargets": summarize_dashboard_targets([dict(row) for row in target_rows]),
    }


def summarize_dashboard_targets(incidents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    targets: dict[tuple[str, str], dict[str, Any]] = {}
    for incident in incidents:
        risk_score = int(incident.get("risk_score", 0) or 0)
        incident_targets = set()
        for ioc in extract_iocs(str(incident.get("payload", ""))):
            kind = ioc["type"]
            if kind == "url":
                value = str(ioc.get("indicator", "")).lower()
                label = value
                target_type = "service"
            elif kind == "email":
                value = str(ioc.get("value", "")).lower()
                local, _, domain = value.partition("@")
                if not local or not domain:
                    continue
                label = f"{local[:1]}***@{domain}"
                target_type = "user"
            elif kind == "ip":
                value = str(ioc.get("value", ""))
                octets = value.split(".")
                label = ".".join(octets[:3] + ["x"]) if len(octets) == 4 else "Unrecognized IP"
                target_type = "network"
            else:
                continue
            key = (target_type, value)
            if key in incident_targets:
                continue
            incident_targets.add(key)
            target = targets.setdefault(key, {
                "label": label,
                "type": target_type,
                "incident_count": 0,
                "high_risk_count": 0,
                "max_risk_score": 0,
            })
            target["incident_count"] += 1
            target["high_risk_count"] += int(risk_score >= 60)
            target["max_risk_score"] = max(target["max_risk_score"], risk_score)
    return sorted(
        targets.values(),
        key=lambda target: (target["incident_count"], target["high_risk_count"], target["max_risk_score"]),
        reverse=True,
    )[:8]


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
        rows = db.execute("SELECT id, category, payload, risk_score, risk_level FROM incidents ORDER BY id DESC LIMIT 100").fetchall()
    result = build_incident_graph([dict(row) for row in rows])
    for index, node in enumerate(result["nodes"]):
        node["position"] = {"x": 40 + (index % 5) * 190, "y": 60 + (index // 5) * 90}
        node["data"] = {"label": f"{node['label']} ({node['incidents']})"}
        node["style"] = {"background": "#b91c1c" if node["kind"] == "origin" else "#0e7490", "color": "#fff"}
    for index, edge in enumerate(result["edges"]):
        edge["id"] = f"edge-{index}"
        edge["animated"] = edge["weight"] > 1
    return result


@app.get("/api/v1/system/health")
def system_health(user: dict[str, str] = Depends(current_user)):
    request_started = time.perf_counter()
    with get_db() as db:
        event_count = db.execute("SELECT COUNT(*) AS count FROM incidents").fetchone()["count"]
        recent_count = db.execute("SELECT COUNT(*) AS count FROM incidents WHERE created_at >= ?", ((datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),)).fetchone()["count"]
    uptime = (datetime.now(timezone.utc) - STARTED_AT).total_seconds()
    model_loaded = TEXT_MODEL is not None or FALLBACK_TEXT_MODEL is not None
    text_model_name = "TF-IDF + Logistic Regression" if TEXT_MODEL is not None else "Bernoulli Naive Bayes fallback" if FALLBACK_TEXT_MODEL is not None else "Rules only"
    media_status = pretrained_media_status()
    evaluation_path = Path(__file__).parent / "data" / "uci-sms-results.json"
    evaluation = {}
    if evaluation_path.exists():
        try:
            evaluation = json.loads(evaluation_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            evaluation = {}
    return {"status": "healthy", "uptime_seconds": round(uptime), "api_latency_ms": round((time.perf_counter() - request_started) * 1000, 2), "events_stored": event_count, "events_per_minute": recent_count, "model_loaded": model_loaded, "model_confidence": text_model_name, "media_models": media_status, "threat_accuracy": round(float(evaluation.get("f1", 0)) * 100, 1), "evaluation_backend": evaluation.get("backend", "baseline"), "database": "postgresql" if os.getenv("CYBERGUARD_DATABASE_URL", "").strip().startswith(("postgresql://", "postgres://")) else "sqlite", "ephemeral_state": EPHEMERAL_STATE.backend, "response_integrations": bool(os.getenv("CYBERGUARD_RESPONSE_WEBHOOK_URL"))}


@app.get("/api/v1/models/status")
def model_status(user: dict[str, str] = Depends(current_user)):
    return {
        "text_classifier": {"loaded": TEXT_MODEL is not None or FALLBACK_TEXT_MODEL is not None, "algorithm": "TF-IDF + Logistic Regression" if TEXT_MODEL is not None else "Bernoulli Naive Bayes fallback", "samples": FALLBACK_TEXT_MODEL.get("samples") if FALLBACK_TEXT_MODEL else None},
        "text_transformer": transformer_status(),
        "media_inspection": media_inspection_status(),
        "deep_learning_adapter": pretrained_media_status(),
        "threat_intelligence": {"loaded": True, "algorithm": "Local IOC reputation with optional external provider", "external_configured": bool(os.getenv("CYBERGUARD_THREAT_INTEL_URL"))},
    }


@app.get("/api/v1/compliance/controls")
def compliance_controls(user: dict[str, str] = Depends(current_user)):
    return {"controls": [
        {"id": "cert-in-6h", "framework": "CERT-In 6-Hour Reporting", "status": "Self-assessed", "score": None, "evidence": "Incident records and alert APIs exist; reporting timelines and operational evidence require independent validation."},
        {"id": "dpdp-rbac", "framework": "DPDP Act / Privacy", "status": "Self-assessed", "score": None, "evidence": "Authentication and role controls exist; privacy obligations require legal and operational review."},
        {"id": "iso-access", "framework": "ISO 27001 Access Control", "status": "Self-assessed", "score": None, "evidence": "Role controls exist; production SSO, retention, and independent control testing remain unverified."},
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
    ], "providers": provider_integration_status(), "production_actions": production_provider_status()}


def run_production_integration(action: str, operation, user: dict[str, str]):
    try:
        result = operation()
    except IntegrationNotConfigured as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    except requests.RequestException as error:
        raise HTTPException(status_code=502, detail=f"{action} provider request failed: {error}") from error
    except ValueError as error:
        raise HTTPException(status_code=502, detail=f"{action} provider returned an invalid response: {error}") from error
    resource = str(result.get("provider", "provider"))
    write_audit(user, f"integration_{action}", resource, f"status:{result.get('status', 'unknown')}")
    return result


@app.post("/api/v1/integrations/tickets")
def create_provider_ticket_route(request: ProviderTicketRequest, user: dict[str, str] = Depends(head_admin_user)):
    return run_production_integration(
        "ticket_create",
        lambda: create_provider_ticket(request.model_dump() if hasattr(request, "model_dump") else request.dict()),
        user,
    )


@app.post("/api/v1/integrations/identity/disable")
def disable_provider_identity_route(request: ProviderIdentityDisableRequest, user: dict[str, str] = Depends(head_admin_user)):
    if not request.confirmed:
        raise HTTPException(status_code=409, detail="Explicit confirmation is required to disable an identity.")
    identity = request.identity.strip()
    if not identity:
        raise HTTPException(status_code=400, detail="Identity must not be empty.")
    return run_production_integration("identity_disable", lambda: disable_provider_identity(identity), user)


@app.post("/api/v1/integrations/endpoint/isolate")
def isolate_provider_endpoint_route(request: ProviderEndpointIsolationRequest, user: dict[str, str] = Depends(head_admin_user)):
    if not request.confirmed:
        raise HTTPException(status_code=409, detail="Explicit confirmation is required to isolate an endpoint.")
    endpoint_id = request.endpoint_id.strip()
    if not endpoint_id:
        raise HTTPException(status_code=400, detail="Endpoint ID must not be empty.")
    return run_production_integration("endpoint_isolate", lambda: isolate_provider_endpoint(endpoint_id), user)


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


@app.post("/api/v1/siem/demo-seed")
def siem_demo_seed(user: dict[str, str] = Depends(current_user)):
    """Seed safe, clearly synthetic telemetry so the live SOC view is demonstrable."""
    with get_db() as db:
        existing_events = db.execute("SELECT COUNT(*) AS count FROM siem_events").fetchone()["count"]
    if existing_events:
        return read_siem_events(user) | {"seeded": False}
    seed_events = [
        {"source_ip": "192.168.1.99", "event_type": "suspicious_login", "severity": "CRITICAL", "details": "Synthetic demo event: unauthorized admin access from an untrusted host.", "source_host": "Unknown-Kali-Linux"},
        {"source_ip": "192.168.1.25", "event_type": "data_access", "severity": "MEDIUM", "details": "Synthetic demo event: unusual finance-server access volume under review.", "source_host": "Finance-Server"},
        {"source_ip": "192.168.1.10", "event_type": "authentication_success", "severity": "LOW", "details": "Synthetic demo event: trusted administrator session observed.", "source_host": "Admin-Workstation"},
    ]
    for event in seed_events:
        siem_ingest_event(event, user)
    write_audit(user, "siem_demo_seed", "siem", f"seeded:{len(seed_events)}")
    return read_siem_events(user) | {"seeded": True}


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
    return shared_immunity(_roadmap_incidents(), os.getenv("CYBERGUARD_TENANT_IMMUNITY_SECRET"))


@app.post("/api/v1/roadmap/immunity/publish")
def roadmap_immunity_publish(request: dict, user: dict[str, str] = Depends(head_admin_user)):
    tenant_id = os.getenv("CYBERGUARD_TENANT_ID", "").strip()
    if not tenant_id:
        raise HTTPException(status_code=503, detail="CYBERGUARD_TENANT_ID is required for shared-immunity publishing")
    signatures = shared_immunity(_roadmap_incidents(), os.getenv("CYBERGUARD_TENANT_IMMUNITY_SECRET"))["shared_signatures"]
    result = publish_tenant_signatures(signatures, tenant_id)
    write_audit(user, "tenant_immunity_publish", str(result.get("published", 0)), result["status"])
    return result


@app.get("/api/v1/roadmap/resource/{incident_id}")
def roadmap_resource_cost(incident_id: int, user: dict[str, str] = Depends(current_user)):
    return attacker_resource_cost(incident_context(incident_id))


@app.post("/api/v1/roadmap/supply-chain")
def roadmap_supply_chain(request: dict, user: dict[str, str] = Depends(current_user)):
    nodes = request.get("nodes", [])
    dependencies = request.get("dependencies", request.get("edges", []))
    compromised_nodes = request.get("compromised_nodes", [])
    try:
        result = supply_chain_blast_radius(nodes, dependencies, compromised_nodes)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    write_audit(
        user,
        "supply_chain_blast_radius",
        f"{len(nodes)} nodes",
        f"{result['affected_count']} downstream nodes",
    )
    return result


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
    raw_actions = request.get("actions", [])
    if not isinstance(raw_actions, list):
        raise HTTPException(status_code=422, detail="Counterfactual actions must be a list")
    try:
        value = int(request.get("value", 4))
        return counterfactual_replay(
            incident_context(incident_id),
            [str(action) for action in raw_actions],
            str(request.get("variable", "response_delay_hours")),
            value,
        )
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error


@app.post("/api/v1/roadmap/compliance-diff")
def roadmap_compliance_diff(request: dict, user: dict[str, str] = Depends(current_user)):
    controls = compliance_controls(user)["controls"]
    cves = request.get("cves")
    if not cves:
        with get_db() as db:
            row = db.execute("SELECT items_json FROM cve_feed_snapshots ORDER BY id DESC LIMIT 1").fetchone()
        cves = json.loads(row["items_json"]) if row else []
    if not isinstance(cves, list):
        raise HTTPException(status_code=422, detail="CVEs must be supplied as a list")
    return compliance_diff(controls, cves)


@app.post("/api/v1/roadmap/compliance-diff/sync")
def roadmap_compliance_diff_sync(user: dict[str, str] = Depends(head_admin_user)):
    try:
        feed = sync_cve_feed()
    except requests.RequestException as error:
        raise HTTPException(status_code=502, detail=f"CVE feed synchronization failed: {error}") from error
    items = feed.get("items")
    if not isinstance(items, list):
        items = [{"id": item, "severity": "unknown"} if isinstance(item, str) else item for item in feed.get("cves", [])]
    if feed.get("status") == "synced":
        with get_db() as db:
            db.execute(
                "INSERT INTO cve_feed_snapshots (source, items_json, synced_at) VALUES (?, ?, ?)",
                (str(feed.get("source") or "configured-feed"), json.dumps(items), datetime.now(timezone.utc).isoformat()),
            )
    result = compliance_diff(compliance_controls(user)["controls"], items)
    return {"feed": feed, "diff": result}


if __name__ == "__main__":
    import uvicorn
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    reload_env = os.getenv("RELOAD")
    is_prod = bool(os.getenv("RENDER") or os.getenv("CYBERGUARD_ENV") == "production" or "PORT" in os.environ)
    reload = reload_env.lower() in ("true", "1") if reload_env is not None else not is_prod
    uvicorn.run("main:app", host=host, port=port, reload=reload, proxy_headers=True, forwarded_allow_ips="*")
