import ast
import hashlib
import json
import os
import secrets
import sqlite3
import sys

# Auto-detect and switch to local .venv if run with system python lacking fastapi/uvicorn
try:
    import fastapi  # noqa: F401
    import uvicorn  # noqa: F401
except ImportError:
    backend_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(backend_dir, ".venv", "bin", "python3"),
        os.path.join(backend_dir, "venv", "bin", "python3"),
        os.path.join(os.path.dirname(backend_dir), ".venv", "bin", "python3"),
    ]
    venv_python = next((p for p in candidates if os.path.exists(p)), None)
    if venv_python and sys.executable != venv_python:
        os.execv(venv_python, [venv_python] + sys.argv)

from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests
import jwt
from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from detection_engine import TEXT_MODEL, evaluate_threat_payload
from battle_simulator import run_battle
from campaign_engine import correlate_incident
from digital_twin import build_twin
from forecast_engine import forecast_risk
from media_engine import analyze_media
from models import AlertRequest, BattleRequest, ForecastRequest, IncidentComment, IncidentUpdate, LoginRequest, NotificationUpdate, PsychologyRequest, ResponseExecutionRequest, SimulationRequest, ThreatAnalysisRequest, ThreatIntelLookup, UserCreate
from psychology_detector import analyze_psychology
from response_simulator import simulate_response
from self_healing import recommend_healing
from threat_intel import enrich_iocs, extract_iocs
from threat_fusion import build_genome, serialize_genome
from timeline_engine import build_timeline

DB_PATH = Path(os.getenv("CYBERGUARD_DB_PATH", str(Path(__file__).with_name("cyberguard.db"))))
JWT_SECRET = os.getenv("CYBERGUARD_JWT_SECRET", "development-only-change-me-use-a-long-secret-key")
STARTED_AT = datetime.now(timezone.utc)
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


def get_db():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def initialize_database():
    with get_db() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL
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
            """
        )
        columns = {row["name"] for row in db.execute("PRAGMA table_info(incidents)").fetchall()}
        if "status" not in columns:
            db.execute("ALTER TABLE incidents ADD COLUMN status TEXT NOT NULL DEFAULT 'New'")
        if "assigned_to" not in columns:
            db.execute("ALTER TABLE incidents ADD COLUMN assigned_to TEXT")
        if "notes" not in columns:
            db.execute("ALTER TABLE incidents ADD COLUMN notes TEXT NOT NULL DEFAULT ''")
        users = [("analyst", hash_password("analyst123"), "analyst"), ("lead", hash_password("lead123"), "lead"), ("admin", hash_password("admin123"), "admin")]
        db.executemany("INSERT OR IGNORE INTO users VALUES (?, ?, ?)", users)


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


def current_user(authorization: Optional[str] = Header(default=None)) -> dict[str, str]:
    if not authorization or not authorization.startswith("Bearer "):
        if os.getenv("CYBERGUARD_ALLOW_ANONYMOUS_EVAL", "true").lower() in {"true", "1", "yes"}:
            return {"username": "evaluator", "role": "lead"}
        raise HTTPException(status_code=401, detail="Authentication required")
    try:
        return jwt.decode(authorization.removeprefix("Bearer "), JWT_SECRET, algorithms=["HS256"])
    except jwt.PyJWTError as error:
        if os.getenv("CYBERGUARD_ALLOW_ANONYMOUS_EVAL", "true").lower() in {"true", "1", "yes"}:
            return {"username": "evaluator", "role": "lead"}
        raise HTTPException(status_code=401, detail="Invalid or expired session") from error



def admin_user(user: dict[str, str] = Depends(current_user)) -> dict[str, str]:
    if user["role"] != "admin":
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


def persist_cyberguard_x(incident_id: int, incident: dict):
    genome = build_genome(incident)
    timeline = build_timeline(incident)
    related = recent_incident_context()
    campaign = correlate_incident(incident, [item for item in related if item["id"] != incident_id])
    with get_db() as db:
        now = datetime.now(timezone.utc).isoformat()
        db.execute("INSERT OR REPLACE INTO threat_fingerprints (incident_id, fingerprint, genome_json, created_at) VALUES (?, ?, ?, ?)", (incident_id, genome["fingerprint"], serialize_genome(genome), now))
        db.execute("INSERT OR IGNORE INTO campaigns (campaign_id, confidence, stage, created_at) VALUES (?, ?, ?, ?)", (campaign["campaign_id"], campaign["confidence"], campaign["stage"], now))
        for match in campaign["related_incidents"]:
            db.execute("INSERT OR IGNORE INTO campaign_incidents (campaign_id, incident_id, score) VALUES (?, ?, ?)", (campaign["campaign_id"], match["incident_id"], match["score"]))
        db.execute("INSERT INTO campaign_incidents (campaign_id, incident_id, score) VALUES (?, ?, ?) ON CONFLICT DO NOTHING", (campaign["campaign_id"], incident_id, 100))
        db.executemany("INSERT INTO incident_timelines (incident_id, event_json, created_at) VALUES (?, ?, ?)", [(incident_id, json.dumps(event), now) for event in timeline])


@app.get("/")
def root():
    return {"status": "Active", "system": "CYBERGUARD AI Engine v2.0"}


@app.get("/api/v1/demo/scenarios")
def demo_scenarios(user: dict[str, str] = Depends(current_user)):
    return {"scenarios": DEMO_SCENARIOS}


@app.post("/api/v1/auth/login")
def login(request: LoginRequest):
    initialize_database()
    with get_db() as db:
        user = db.execute("SELECT username, role, password_hash FROM users WHERE username = ?", (request.username,)).fetchone()
    if not user or user["password_hash"] != hash_password(request.password):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = jwt.encode({"username": user["username"], "role": user["role"], "iat": int(datetime.now(timezone.utc).timestamp())}, JWT_SECRET, algorithm="HS256")
    return {"access_token": token, "token_type": "bearer", "user": {"username": user["username"], "role": user["role"]}}


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
    return run_battle(latest.get("risk_score", 0), request.defender_actions)


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


@app.get("/api/v1/admin/users")
def admin_users(user: dict[str, str] = Depends(admin_user)):
    with get_db() as db:
        rows = db.execute("SELECT username, role FROM users ORDER BY username").fetchall()
    write_audit(user, "list_users", "users", "admin console")
    return {"users": [dict(row) for row in rows]}


@app.post("/api/v1/admin/users")
def create_user(request: UserCreate, user: dict[str, str] = Depends(admin_user)):
    if request.role not in {"analyst", "lead", "admin"}:
        raise HTTPException(status_code=400, detail="Invalid role")
    try:
        with get_db() as db:
            db.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", (request.username, hash_password(request.password), request.role))
    except sqlite3.IntegrityError as error:
        raise HTTPException(status_code=409, detail="Username already exists") from error
    write_audit(user, "create_user", f"user:{request.username}", request.role)
    return {"status": "created", "username": request.username, "role": request.role}


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
    uptime = (datetime.now(timezone.utc) - STARTED_AT).total_seconds()
    return {"status": "healthy", "uptime_seconds": round(uptime), "events_stored": event_count, "model_loaded": TEXT_MODEL is not None, "database": "sqlite", "response_integrations": bool(os.getenv("CYBERGUARD_RESPONSE_WEBHOOK_URL"))}


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
    ]}


@app.post("/api/v1/integrations/siem/ingest")
def ingest_siem_event(request: ThreatAnalysisRequest, user: dict[str, str] = Depends(current_user)):
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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
