import sqlite3

import pytest
from fastapi.testclient import TestClient

import main
from database import connect_database
from ephemeral_store import EphemeralStore


def test_rescue_prevention_api_routes_persist_owner_scoped_records(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "rescue-prevention.sqlite")
    main.initialize_database()
    expected = {
        ("/api/v1/rescue/scan", "POST"),
        ("/api/v1/rescue/plan", "POST"),
        ("/api/v1/rescue/step", "POST"),
        ("/api/v1/rescue/lockdown", "POST"),
        ("/api/v1/rescue/guardian", "POST"),
        ("/api/v1/rescue/evidence", "POST"),
        ("/api/v1/rescue/simulate", "POST"),
        ("/api/v1/rescue/capabilities", "GET"),
        ("/api/v1/rescue/blast-radius", "GET"),
        ("/api/v1/rescue/locked-out", "GET"),
        ("/api/v1/rescue/offline-card", "GET"),
        ("/api/v1/prevention/decision", "POST"),
        ("/api/v1/prevention/campaign-watch", "POST"),
        ("/api/v1/prevention/containment", "POST"),
        ("/api/v1/prevention/identity-trust", "GET"),
        ("/api/v1/prevention/identity-trust", "POST"),
        ("/api/v1/prevention/insider-risk", "GET"),
        ("/api/v1/prevention/insider-risk", "POST"),
        ("/api/v1/prevention/deception-status", "GET"),
        ("/api/v1/prevention/deception-status", "POST"),
        ("/api/v1/prevention/policies", "GET"),
        ("/api/v1/prevention/policies", "POST"),
        ("/api/v1/prevention/policies/{policy_id}", "PUT"),
        ("/api/v1/prevention/policies/{policy_id}", "DELETE"),
        ("/api/v1/prevention/policies/evaluate", "POST"),
        ("/api/v1/containment/requests", "POST"),
        ("/api/v1/containment/queue", "GET"),
        ("/api/v1/containment/requests/{request_id}/approve", "POST"),
        ("/api/v1/containment/requests/{request_id}/reject", "POST"),
        ("/api/v1/containment/requests/{request_id}/execute", "POST"),
    }
    registered = {
        (route.path, method)
        for route in main.app.routes
        for method in getattr(route, "methods", set())
    }
    assert expected <= registered

    user = {"username": "rescue-analyst", "role": "lead"}
    baseline = main.rescue_scan({}, user)
    assert baseline["score"] == 0
    assert baseline["findings"] == []
    scan = main.rescue_scan({"unknown_session": True}, user)
    assert scan["assessment_source"] == "operator_reported"
    assert scan["provider_connected"] is False
    plan = main.rescue_plan_route({"scan": scan}, user)
    evidence = main.rescue_evidence({"scan": scan}, user)
    simulation = main.rescue_simulate({"scan": scan}, user)

    assert plan["scan_id"] == scan["scan_id"]
    assert evidence["scan"]["scan_id"] == scan["scan_id"]
    assert simulation["mode"] == "synthetic_only"
    with pytest.raises(main.HTTPException) as error:
        main.rescue_plan_route({"scan": scan}, {"username": "different-user", "role": "lead"})
    assert error.value.status_code == 404

    decision = main.prevention_decision({"risk_score": 92, "category": "email"}, user)
    assert decision["mode"] == "recommendation_only"
    assert main.prevention_identity_trust(user)["status"] == "insufficient_data"
    assert main.prevention_insider_risk(user)["status"] == "insufficient_data"

    incident_id = main.store_incident(
        "email",
        "stored suspicious message",
        {"risk_score": 91, "risk_level": "High"},
    )
    containment = main.prevention_containment(
        {"incident_id": incident_id, "risk_score": 0, "category": "benign"},
        user,
    )
    listed_incident = main.incidents(search=None, status=None, user=user)["incidents"][0]
    assert containment["risk_score"] == 91
    assert containment["actions_executed"] is False
    assert listed_incident["payload"] == "stored suspicious message"
    assert listed_incident["risk_score"] == 91


def test_sqlite_connection_context_closes_connection(tmp_path):
    with connect_database(tmp_path / "closed.sqlite") as connection:
        connection.execute("SELECT 1")

    with pytest.raises(sqlite3.ProgrammingError):
        connection.execute("SELECT 1")


def test_session_tokens_expire_and_expired_tokens_are_rejected(monkeypatch):
    monkeypatch.setattr(main, "SESSION_TTL_MINUTES", 5)
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    user = connection.execute("SELECT 'session-user' AS username, 'analyst' AS role").fetchone()
    session = main.issue_session(user)
    claims = main.jwt.decode(session["access_token"], main.JWT_SECRET, algorithms=["HS256"])

    assert claims["exp"] - claims["iat"] == 5 * 60
    expired = main.jwt.encode(
        {"username": "expired-user", "role": "analyst", "exp": 1},
        main.JWT_SECRET,
        algorithm="HS256",
    )
    with pytest.raises(main.HTTPException) as error:
        main.current_user(f"Bearer {expired}")
    assert error.value.status_code == 401


def test_password_hash_fallback_uses_scrypt_and_migrates_legacy_hash(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "passwords.sqlite")
    monkeypatch.setattr(main, "bcrypt", None)
    main.initialize_database()
    legacy_hash = main.hashlib.sha256(b"lead123").hexdigest()
    with main.get_db() as db:
        db.execute("UPDATE users SET password_hash = ? WHERE username = ?", (legacy_hash, "lead"))

    session = main.login(main.LoginRequest(username="lead", password="lead123"))
    assert session["access_token"]
    with main.get_db() as db:
        upgraded_hash = db.execute("SELECT password_hash FROM users WHERE username = ?", ("lead",)).fetchone()["password_hash"]

    assert upgraded_hash.startswith("scrypt$")
    assert main.verify_password("lead123", upgraded_hash)
    assert not main.verify_password("incorrect", upgraded_hash)


def test_production_database_seeds_only_configured_head_admin(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "production-users.sqlite")
    monkeypatch.setattr(main, "CYBERGUARD_ENV", "development")
    monkeypatch.setattr(main, "HEAD_ADMIN_USERNAME", "configured-owner")
    monkeypatch.setattr(main, "HEAD_ADMIN_PASSWORD", "a-long-production-password")
    main.initialize_database()
    monkeypatch.setattr(main, "CYBERGUARD_ENV", "production")
    main.initialize_database()

    with main.get_db() as db:
        users = {row["username"]: row["status"] for row in db.execute("SELECT username, status FROM users").fetchall()}

    assert users["configured-owner"] == "active"
    assert users["analyst"] == users["lead"] == users["admin"] == "disabled"
    with pytest.raises(main.HTTPException) as error:
        main.login(main.LoginRequest(username="lead", password="lead123"))
    assert error.value.status_code == 401


def test_development_database_does_not_seed_unconfigured_demo_users(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "no-demo-users.sqlite")
    monkeypatch.setattr(main, "CYBERGUARD_ENV", "development")
    monkeypatch.setattr(main, "HEAD_ADMIN_USERNAME", "configured-owner")
    monkeypatch.setattr(main, "HEAD_ADMIN_PASSWORD", "a-long-development-password")
    for key in (
        "CYBERGUARD_DEMO_ANALYST_PASSWORD",
        "CYBERGUARD_DEMO_LEAD_PASSWORD",
        "CYBERGUARD_DEMO_ADMIN_PASSWORD",
    ):
        monkeypatch.delenv(key, raising=False)

    main.initialize_database()

    with main.get_db() as db:
        usernames = {row["username"] for row in db.execute("SELECT username FROM users").fetchall()}

    assert usernames == {"configured-owner"}


def test_auth_configuration_requires_explicit_admin_credentials_in_development():
    with pytest.raises(RuntimeError, match="CYBERGUARD_HEAD_ADMIN_USERNAME"):
        main.validate_auth_configuration("development", "", False, "", "")


def test_production_deployment_configuration_requires_live_https_origins():
    main.validate_public_deployment_configuration(
        "production",
        "https://app.example.com,https://preview.example.com",
        "https://app.example.com",
    )


@pytest.mark.parametrize(
    ("origins", "public_app_url"),
    [
        ("", ""),
        ("http://app.example.com", "https://app.example.com"),
        ("https://app.example.com/path", "https://app.example.com"),
        ("https://app.example.com", "http://app.example.com"),
        ("https://user:password@app.example.com", "https://app.example.com"),
    ],
)
def test_production_deployment_configuration_rejects_invalid_origins(origins, public_app_url):
    with pytest.raises(RuntimeError, match="CYBERGUARD_|public HTTPS origins"):
        main.validate_public_deployment_configuration("production", origins, public_app_url)


def test_production_disables_demo_identity_provider(monkeypatch):
    monkeypatch.setattr(main, "CYBERGUARD_ENV", "production")

    with pytest.raises(main.HTTPException) as error:
        main.idp_authenticate_user(
            {"username": "user_admin", "password": "admin123"},
            {"username": "analyst", "role": "analyst"},
        )

    assert error.value.status_code == 503


@pytest.mark.parametrize(
    ("jwt_secret", "username", "password", "anonymous", "message"),
    [
        ("", "", "", False, "CYBERGUARD_JWT_SECRET must be set"),
        ("short", "owner", "long-enough-production-password", False, "at least 32 characters"),
        ("x" * 40, "", "long-enough-production-password", False, "CYBERGUARD_HEAD_ADMIN_USERNAME"),
        ("x" * 40, "owner", "too-short", False, "at least 16 characters"),
        ("x" * 40, "owner", "long-enough-production-password", True, "cannot be enabled"),
    ],
)
def test_production_auth_config_fails_closed(jwt_secret, username, password, anonymous, message):
    with pytest.raises(RuntimeError, match=message):
        main.validate_auth_configuration("production", jwt_secret, anonymous, username, password)


def test_existing_sessions_are_revoked_when_user_is_disabled_or_demoted(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "session-revocation.sqlite")
    main.initialize_database()
    with main.get_db() as db:
        lead = db.execute("SELECT username, role FROM users WHERE username = ?", ("lead",)).fetchone()
    token = main.issue_session(lead)["access_token"]
    assert main.current_user(f"Bearer {token}")["role"] == "lead"

    with main.get_db() as db:
        db.execute("UPDATE users SET status = 'disabled' WHERE username = ?", ("lead",))
    with pytest.raises(main.HTTPException) as disabled_error:
        main.current_user(f"Bearer {token}")
    assert disabled_error.value.status_code == 401

    with main.get_db() as db:
        db.execute("UPDATE users SET status = 'active', role = 'analyst' WHERE username = ?", ("lead",))
    with pytest.raises(main.HTTPException) as demoted_error:
        main.current_user(f"Bearer {token}")
    assert demoted_error.value.status_code == 401


def test_incident_workflow_changes_require_privileged_role_and_valid_assignee(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "incident-workflow.sqlite")
    main.initialize_database()
    incident_id = main.store_incident("email", "workflow test", {"risk_score": 25, "risk_level": "Low"})

    with pytest.raises(main.HTTPException) as role_error:
        main.update_incident(
            incident_id,
            main.IncidentUpdate(status="Closed"),
            {"username": "analyst", "role": "analyst"},
        )
    assert role_error.value.status_code == 403

    with pytest.raises(main.HTTPException) as assignee_error:
        main.update_incident(
            incident_id,
            main.IncidentUpdate(assigned_to="missing-user"),
            {"username": "lead", "role": "lead"},
        )
    assert assignee_error.value.status_code == 422

    result = main.update_incident(
        incident_id,
        main.IncidentUpdate(status="Closed", assigned_to=" analyst "),
        {"username": "lead", "role": "lead"},
    )
    assert result["status"] == "updated"
    comment = main.comment_incident(
        incident_id,
        main.IncidentComment(comment="Analyst review note"),
        {"username": "analyst", "role": "analyst"},
    )
    assert comment["status"] == "updated"
    with main.get_db() as db:
        row = db.execute("SELECT assigned_to, notes FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    assert row["assigned_to"] == "analyst"
    assert "Analyst review note" in row["notes"]


def test_login_failure_window_locks_repeated_failures_and_resets_on_success(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "login-limit.sqlite")
    monkeypatch.setattr(main, "EPHEMERAL_STATE", EphemeralStore())
    monkeypatch.setattr(main, "LOGIN_FAILURE_LIMIT", 3)
    main.initialize_database()

    for _ in range(2):
        with pytest.raises(main.HTTPException) as error:
            main.login(main.LoginRequest(username="lead", password="wrong-password"))
        assert error.value.status_code == 401

    assert main.login(main.LoginRequest(username="lead", password="lead123"))["access_token"]
    failure_key = "login-failures:" + main.hashlib.sha256(b"lead").hexdigest()
    attempts_after_success = main.EPHEMERAL_STATE.record_window_event(failure_key, window_seconds=300)
    assert attempts_after_success == 1
    main.EPHEMERAL_STATE.clear_window(failure_key)

    for _ in range(3):
        with pytest.raises(main.HTTPException) as error:
            main.login(main.LoginRequest(username="lead", password="wrong-password"))
        assert error.value.status_code == 401
    with pytest.raises(main.HTTPException) as locked_error:
        main.login(main.LoginRequest(username="lead", password="lead123"))
    assert locked_error.value.status_code == 429


def test_identity_trust_reports_persist_per_user_and_create_ato_incident(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "identity-trust.sqlite")
    main.initialize_database()
    lead = {"username": "lead", "role": "lead"}
    analyst = {"username": "analyst", "role": "analyst"}

    assert main.prevention_identity_trust(lead)["status"] == "insufficient_data"
    report = main.record_identity_trust(
        main.IdentityTrustRequest(
            device="unknown-device",
            country="CA",
            source_ip="203.0.113.25",
            mfa_enabled=False,
            behavioral_anomaly=True,
        ),
        lead,
    )

    assert report["assessment_source"] == "operator_reported"
    assert report["status"] == "blocked"
    assert report["incident_id"] is not None
    saved = main.prevention_identity_trust(lead)
    assert saved["event_id"] == report["event_id"]
    assert saved["incident_id"] == report["incident_id"]
    assert main.prevention_identity_trust(analyst)["status"] == "insufficient_data"

    with pytest.raises(main.HTTPException) as invalid_ip:
        main.record_identity_trust(
            main.IdentityTrustRequest(device="known-device", country="US", source_ip="not-an-ip", mfa_enabled=True),
            lead,
        )
    assert invalid_ip.value.status_code == 422


def test_insider_risk_reports_persist_per_user_and_create_incidents(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "insider-risk.sqlite")
    main.initialize_database()
    lead = {"username": "lead", "role": "lead"}
    analyst = {"username": "analyst", "role": "analyst"}
    assert main.prevention_insider_risk(lead)["status"] == "insufficient_data"

    report = main.record_insider_risk(
        main.InsiderRiskRequest(downloads=8, off_hours=True, privilege_change=True, sensitive_access=5),
        lead,
    )
    assert report["assessment_source"] == "operator_reported"
    assert report["risk_score"] >= 60
    assert report["incident_id"] is not None
    assert main.prevention_insider_risk(lead)["event_id"] == report["event_id"]
    assert main.prevention_insider_risk(analyst)["status"] == "insufficient_data"

    with pytest.raises(ValueError):
        main.record_insider_risk(
            main.InsiderRiskRequest(downloads=-1),
            lead,
        )


def test_deception_interactions_persist_and_link_to_incidents(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "deception.sqlite")
    main.initialize_database()
    user = {"username": "lead", "role": "lead"}

    initial = main.prevention_deception_status(user)
    assert initial["status"] == "no_events"
    assert initial["active_decoys"] == []
    report = main.report_deception_interaction(
        main.DeceptionInteractionRequest(
            host="finance-workstation",
            actor="analyst-1",
            resource="honeytoken-spreadsheet",
            event_type="access",
            source_ip="203.0.113.7",
        ),
        user,
    )
    assert report["status"] == "events_reported"
    assert report["reported_event_id"] in {event["event_id"] for event in report["triggered_decoys"]}
    assert report["incident_id"] is not None
    assert report["compromised_assets"] == ["finance-workstation"]
    iocs = main.incident_context(report["incident_id"])["assessment"]["iocs"]
    assert iocs == [{"type": "ip", "indicator": "203.0.113.7"}]

    follow_up_id = main.store_incident(
        "email",
        "follow-up phishing message",
        {"risk_score": 75, "risk_level": "High", "iocs": [], "mitre_techniques": []},
    )
    follow_up = main.incident_context(follow_up_id)
    main.persist_cyberguard_x(follow_up_id, follow_up)
    with main.get_db() as db:
        fingerprint = db.execute("SELECT fingerprint FROM threat_fingerprints WHERE incident_id = ?", (follow_up_id,)).fetchone()
    assert fingerprint is not None

    with pytest.raises(main.HTTPException) as invalid_event:
        main.report_deception_interaction(
            main.DeceptionInteractionRequest(host="host", actor="user", resource="decoy", event_type="unknown"),
            user,
        )
    assert invalid_event.value.status_code == 422


def test_policy_crud_versioning_evaluation_and_admin_gate(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "policies.sqlite")
    main.initialize_database()
    admin = {"username": main.HEAD_ADMIN_USERNAME, "role": "head_admin"}
    lead = {"username": "lead", "role": "lead"}
    definition = main.PolicyDefinition(
        name="High risk email",
        description="Require analyst review for elevated email incidents.",
        category="email",
        threshold=70,
        severity="HIGH",
        action="require_mfa",
        approval_required=True,
    )

    with pytest.raises(main.HTTPException) as forbidden:
        main.create_prevention_policy(definition, lead)
    assert forbidden.value.status_code == 403

    created = main.create_prevention_policy(definition, admin)
    assert created["version"] == 1
    incident_id = main.store_incident("email", "policy test", {"risk_score": 85, "risk_level": "High"})
    evaluated = main.evaluate_prevention_policies({"incident_id": incident_id}, lead)
    assert evaluated["mode"] == "recommendation_only"
    assert evaluated["matched_policies"][0]["policy_id"] == created["policy_id"]
    assert evaluated["approval_required"] is True

    updated = main.update_prevention_policy(
        created["policy_id"],
        definition.model_copy(update={"action": "isolate"}),
        admin,
    )
    assert updated["version"] == 2
    assert updated["action"] == "isolate"
    assert main.deactivate_prevention_policy(created["policy_id"], admin)["status"] == "deactivated"
    assert main.evaluate_prevention_policies({"incident_id": incident_id}, lead)["matched_policies"] == []


def test_policy_http_crud_requires_head_admin_and_evaluates_incident(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "policy-http.sqlite")
    main.initialize_database()
    incident_id = main.store_incident("email", "stored policy test", {"risk_score": 88, "risk_level": "High"})
    admin_token = main.jwt.encode(
        {"username": main.HEAD_ADMIN_USERNAME, "role": "head_admin"},
        main.JWT_SECRET,
        algorithm="HS256",
    )
    analyst_token = main.jwt.encode(
        {"username": "analyst", "role": "analyst"},
        main.JWT_SECRET,
        algorithm="HS256",
    )
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    analyst_headers = {"Authorization": f"Bearer {analyst_token}"}
    payload = {
        "name": "Email high-risk gate",
        "description": "Require MFA for high-risk email incidents.",
        "category": "email",
        "threshold": 70,
        "severity": "HIGH",
        "action": "require_mfa",
        "approval_required": True,
        "enabled": True,
    }

    with TestClient(main.app) as client:
        assert client.post("/api/v1/prevention/policies", json=payload, headers=analyst_headers).status_code == 403
        created = client.post("/api/v1/prevention/policies", json=payload, headers=admin_headers)
        assert created.status_code == 200, created.text
        policy_id = created.json()["policy_id"]
        evaluated = client.post(
            "/api/v1/prevention/policies/evaluate",
            json={"incident_id": incident_id},
            headers=analyst_headers,
        )
        assert evaluated.status_code == 200
        assert evaluated.json()["matched_policies"][0]["policy_id"] == policy_id
        updated = client.put(
            f"/api/v1/prevention/policies/{policy_id}",
            json={**payload, "action": "isolate"},
            headers=admin_headers,
        )
        assert updated.status_code == 200
        assert updated.json()["version"] == 2
        deactivated = client.delete(f"/api/v1/prevention/policies/{policy_id}", headers=admin_headers)
        assert deactivated.status_code == 200
        listed = client.get("/api/v1/prevention/policies", headers=analyst_headers)
        assert listed.status_code == 200
        assert next(item for item in listed.json()["policies"] if item["policy_id"] == policy_id)["enabled"] is False


def test_containment_request_approval_rejection_simulation_and_queue(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "containment-lifecycle.sqlite")
    main.initialize_database()
    incident_id = main.store_incident("email", "containment test", {"risk_score": 92, "risk_level": "Critical"})
    analyst = {"username": "analyst", "role": "analyst"}
    lead = {"username": "lead", "role": "lead"}

    request = main.create_containment_request(
        main.ContainmentRequestCreate(incident_id=incident_id, action="isolate_host", target="finance-workstation"),
        analyst,
    )
    assert request["status"] == "pending"
    assert request["simulation"] is True
    with pytest.raises(main.HTTPException) as analyst_approval:
        main.approve_containment_request(request["request_id"], analyst)
    assert analyst_approval.value.status_code == 403

    approved = main.approve_containment_request(request["request_id"], lead)
    assert approved["status"] == "approved"
    execution = main.execute_containment_simulation(request["request_id"], lead)
    assert execution["status"] == "completed"
    assert execution["execution"]["side_effects"] is False
    queue = main.containment_queue(status=None, user=lead)["requests"]
    stored = next(item for item in queue if item["request_id"] == request["request_id"])
    assert stored["status"] == "completed"
    assert stored["execution"]["mode"] == "simulation"

    rejected_request = main.create_containment_request(
        main.ContainmentRequestCreate(incident_id=incident_id, action="revoke_session", target="user-1"),
        analyst,
    )
    rejected = main.reject_containment_request(rejected_request["request_id"], lead)
    assert rejected["status"] == "rejected"
    with pytest.raises(main.HTTPException) as execute_rejected:
        main.execute_containment_simulation(rejected_request["request_id"], lead)
    assert execute_rejected.value.status_code == 409


def test_rescue_http_flow_requires_auth_and_gates_lockdown(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "rescue-http.sqlite")
    token = main.jwt.encode(
        {"username": "lead", "role": "lead"},
        main.JWT_SECRET,
        algorithm="HS256",
    )
    headers = {"Authorization": f"Bearer {token}"}

    with TestClient(main.app) as client:
        assert client.get("/api/v1/rescue/capabilities").status_code == 401
        scan_response = client.post(
            "/api/v1/rescue/scan",
            json={"provider": "generic", "unknown_session": True},
            headers=headers,
        )
        assert scan_response.status_code == 200
        scan = scan_response.json()
        invalid_scan = client.post(
            "/api/v1/rescue/scan",
            json={"unknown_session": "yes"},
            headers=headers,
        )
        assert invalid_scan.status_code == 422
        plan_response = client.post("/api/v1/rescue/plan", json={"scan": scan}, headers=headers)
        assert plan_response.status_code == 200
        assert plan_response.json()["scan_id"] == scan["scan_id"]
        identity_response = client.post(
            "/api/v1/prevention/identity-trust",
            json={
                "device": "unknown-device",
                "country": "CA",
                "source_ip": "203.0.113.25",
                "mfa_enabled": False,
                "behavioral_anomaly": True,
            },
            headers=headers,
        )
        assert identity_response.status_code == 200
        identity_result = identity_response.json()
        assert identity_result["assessment_source"] == "operator_reported"
        assert identity_result["incident_id"] is not None
        stored_identity = client.get("/api/v1/prevention/identity-trust", headers=headers)
        assert stored_identity.status_code == 200
        assert stored_identity.json()["event_id"] == identity_result["event_id"]
        deception_response = client.post(
            "/api/v1/prevention/deception-status",
            json={
                "host": "finance-workstation",
                "actor": "analyst-1",
                "resource": "honeytoken-spreadsheet",
                "event_type": "access",
                "source_ip": "203.0.113.7",
            },
            headers=headers,
        )
        assert deception_response.status_code == 200
        deception_result = deception_response.json()
        assert deception_result["reported_event_id"] in {event["event_id"] for event in deception_result["triggered_decoys"]}
        assert deception_result["incident_id"] is not None
        assert deception_result["active_decoys"] == []
        containment_incident_id = main.store_incident(
            "email",
            "high-risk containment test",
            {"risk_score": 92, "risk_level": "Critical"},
        )
        containment_request = client.post(
            "/api/v1/containment/requests",
            json={"incident_id": containment_incident_id, "action": "isolate_host", "target": "finance-workstation"},
            headers=headers,
        )
        assert containment_request.status_code == 200
        request_id = containment_request.json()["request_id"]
        assert containment_request.json()["status"] == "pending"
        assert client.post(f"/api/v1/containment/requests/{request_id}/approve", json={}, headers=headers).status_code == 200
        execution = client.post(f"/api/v1/containment/requests/{request_id}/execute", json={}, headers=headers)
        assert execution.status_code == 200
        assert execution.json()["execution"]["side_effects"] is False
        queue = client.get("/api/v1/containment/queue", headers=headers)
        assert queue.status_code == 200
        assert next(item for item in queue.json()["requests"] if item["request_id"] == request_id)["status"] == "completed"
        assert client.post(
            "/api/v1/rescue/lockdown",
            json={"scan": scan, "confirmed": True},
            headers=headers,
        ).status_code == 403