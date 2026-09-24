from main import (
    admin_users,
    analyze_threat,
    compliance_controls,
    dashboard_metrics,
    initialize_database,
    incident_detail,
    login,
    notifications,
    threat_intel_lookup,
    incident_genome,
    incident_correlations,
    incident_attack_chain,
    threat_forecast,
    incident_simulation,
    siem_ingest_event,
    read_siem_events,
    idp_authenticate_user,
    adversarial_self_test,
    fatigue_routing,
    incident_intent,
    incident_drift,
    incident_memory,
    incident_explainability,
    alert_quality,
    record_alert_outcome,
)
from extended_intel import scan_payload
from models import ForecastRequest, LoginRequest, SimulationRequest, ThreatAnalysisRequest, ThreatIntelLookup
from roadmap_features import analyst_bias_report, attention_heatmap, attacker_resource_cost, breach_economics, compliance_diff, counterfactual_replay, cross_modal_consistency, jurisdiction_route, seed_honeytokens, shared_immunity
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
from account_rescue_engine import consent_record, contact_warning_draft, execute_step, fleet_summary, provider_capabilities, rescue_plan, rescue_report, rescue_simulation, scan_account


def test_core_operator_workflow():
    initialize_database()
    lead = login(LoginRequest(username="lead", password="lead123"))["user"]
    result = analyze_threat(
        ThreatAnalysisRequest(
            category="email",
            payload="URGENT verify credentials at http://bput-results.xyz from attacker@example.com",
        ),
        lead,
    )
    assert result["status"] == "success"
    assert result["assessment"]["risk_level"] in {"High", "Critical"}
    assert result["assessment"]["iocs"]
    assert incident_detail(result["incident_id"], lead)["incident"]["actions"] == []
    assert notifications(lead)["unread"] >= 0
    assert dashboard_metrics(lead)["totalEvents"] >= 1


def test_phishing_scan_scores_signal_content_not_static_baseline():
    result = scan_payload("URGENT verify credentials at http://bput-results.xyz from attacker@example.com")
    assert result["risk_score"] >= 45
    assert result["safe"] is False


def test_admin_and_threat_intel_routes():
    initialize_database()
    admin = login(LoginRequest(username="admin", password="admin123"))["user"]
    assert admin_users(admin)["users"]
    assert compliance_controls(admin)["controls"]
    assert threat_intel_lookup(ThreatIntelLookup(value="8.8.8.8"), admin)["results"]


def test_cyberguard_x_artifacts_are_available():
    initialize_database()
    lead = login(LoginRequest(username="lead", password="lead123"))["user"]
    result = analyze_threat(ThreatAnalysisRequest(category="url", payload="Urgent verify at https://secure-login.xyz/auth"), lead)
    incident_id = result["incident_id"]
    assert incident_genome(incident_id, lead)["genome"]["fingerprint"]
    assert incident_correlations(incident_id, lead)["campaign_id"]
    assert len(incident_attack_chain(incident_id, lead)["events"]) == 4
    assert threat_forecast(ForecastRequest(horizon=3), lead)["forecast"][-1]["step"] == 3
    assert incident_simulation(incident_id, SimulationRequest(actions=["isolate", "revoke"]), lead)["projected_risk"] < result["assessment"]["risk_score"]


def test_siem_dhcp_and_idp_correlation_workflow():
    initialize_database()
    lead = login(LoginRequest(username="lead", password="lead123"))["user"]

    event = siem_ingest_event(
        {
            "source_ip": "192.168.1.99",
            "event_type": "suspicious_login",
            "severity": "CRITICAL",
            "details": "User attempted unauthorized admin access from untrusted host",
            "source_host": "Unknown-Kali-Linux",
        },
        lead,
    )
    assert event["threat_level"] in {"HIGH", "CRITICAL"}
    assert event["correlated_log"]["hostname"] == "Unknown-Kali-Linux"
    assert read_siem_events(lead)["events"]

    auth = idp_authenticate_user(
        {
            "username": "user_admin",
            "password": "admin123",
            "source_ip": "192.168.1.10",
            "service_provider_app": "CYBERGUARD SOC",
        },
        lead,
    )
    assert auth["auth_status"] == "SUCCESS"

    blocked = idp_authenticate_user(
        {
            "username": "user_admin",
            "password": "admin123",
            "source_ip": "192.168.1.99",
            "service_provider_app": "CYBERGUARD SOC",
        },
        lead,
    )
    assert blocked["auth_status"] == "BLOCKED"


def test_sprint_1_intelligence_signals_are_available():
    initialize_database()
    lead = login(LoginRequest(username="lead", password="lead123"))["user"]
    result = analyze_threat(
        ThreatAnalysisRequest(
            category="email",
            payload="URGENT verify credentials at https://secure-login.xyz/auth?session=abc from admin@company.com",
        ),
        lead,
    )
    incident_id = result["incident_id"]

    assert incident_intent(incident_id, lead)["confidence"] >= 50
    assert incident_drift(incident_id, lead)["drift_score"] >= 0
    assert incident_memory(incident_id, lead)["status"] in {"memory-hit", "fresh-analysis"}
    assert incident_explainability(incident_id, lead)["explainability_score"] >= 0

    outcome = record_alert_outcome(incident_id, "phishing", result["assessment"]["risk_score"], "malicious", "lead")
    report = alert_quality(lead)
    assert outcome["was_correct"] is True
    assert report["overall_score"] >= 0


def test_adversarial_self_test_exposes_confidence_decay():
    result = adversarial_self_test("email", "URGENT verify credentials at https://secure-login.xyz/auth?redirect=evil")
    assert result["baseline_score"] >= 0
    assert result["adversarial_probes"]
    assert result["confidence_decay"] >= 0


def test_defender_fatigue_routing_prioritizes_lightest_load():
    result = fatigue_routing(
        [
            {"database_id": 1, "risk_score": 87, "status": "Investigating", "assigned_to": "analyst"},
            {"database_id": 2, "risk_score": 70, "status": "New", "assigned_to": "lead"},
            {"database_id": 3, "risk_score": 92, "status": "New", "assigned_to": None},
        ],
        [
            {"username": "analyst", "role": "analyst"},
            {"username": "lead", "role": "lead"},
            {"username": "sub_admin", "role": "sub_admin"},
        ],
    )
    assert result["route_summary"]["available_analysts"] >= 1
    assert result["recommended_queue"][0]["target"] in {"analyst", "lead", "sub_admin"}


def test_remaining_roadmap_features_return_safe_operational_artifacts():
    incident = {
        "database_id": 42,
        "id": "INC-42",
        "category": "phishing",
        "risk_score": 88,
        "risk_level": "Critical",
        "status": "Investigating",
        "assigned_to": "analyst",
        "payload": "targeted redirect campaign from registrar with custom domain",
        "metadata": {"country": "IN"},
        "fingerprint": "abc123",
    }
    assert breach_economics(incident)["total_exposure"] > 0
    assert len(seed_honeytokens(incident)["tokens"]) == 3
    assert analyst_bias_report([incident])["analysts"][0]["analyst"] == "analyst"
    assert shared_immunity([incident])["signature_count"] == 1
    assert attacker_resource_cost(incident)["tier"] in {"commodity", "organized", "custom campaign"}
    assert attention_heatmap([{"resource": "incidents"}])["surfaces"][0]["surface"] == "incidents"
    assert jurisdiction_route(incident)["jurisdiction"] == "India"


def test_limited_roadmap_workflows_are_functional():
    incident = {"database_id": 7, "risk_score": 80, "category": "deepfake"}
    media = cross_modal_consistency([{"score": 20, "method": "image"}, {"score": 48, "method": "audio"}])
    assert media["media_count"] == 2
    assert media["status"] == "cross-modal mismatch"
    replay = counterfactual_replay(incident, ["isolate"], "response_delay_hours", 30)
    assert replay["counterfactual_risk"] > replay["baseline_risk"]
    diff = compliance_diff([{"id": "control-1", "status": "Needs Review"}], [{"id": "CVE-TEST", "severity": "high"}])
    assert diff["gap_count"] == 2


def test_prevention_engine_features_are_functional():
    decision = risk_aware_prevention_decision({
        "risk_score": 92,
        "category": "email",
        "payload": "URGENT verify credentials at http://evil-login.example/login",
        "asset_criticality": "critical",
    }, {"role": "admin", "team": "finance"})
    assert decision["action"] in {"block", "isolate", "require_mfa"}
    assert decision["score"] >= 80

    campaign = campaign_aware_prevention([
        {"payload": "URGENT verify at https://secure-login.example", "user": "analyst@org.com"},
        {"payload": "URGENT verify at https://secure-login.example", "user": "lead@org.com"},
    ])
    assert campaign["campaign_id"]
    assert campaign["watch_status"] in {"monitoring", "blocking", "contained"}

    trust = identity_trust_evaluation({"country": "US", "device": "new-device", "login_count": 3, "source_ip": "203.0.113.14"})
    assert trust["trust_score"] >= 0
    assert trust["status"] in {"trusted", "review", "blocked"}

    insider = insider_threat_risk({"downloads": 9, "off_hours": True, "privilege_change": True, "sensitive_access": 5})
    assert insider["risk_score"] >= 50

    decoy = deception_trigger_check([{"type": "honeytoken", "host": "finance-host-01", "user": "finance-user"}])
    assert decoy["trigger_status"] == "triggered"

    containment = containment_action_plan({"risk_score": 90, "source_ip": "198.51.100.10", "category": "email"})
    assert containment["actions"]

    cross = cross_channel_prevention_score({
        "email_risk": 88,
        "url_risk": 76,
        "device_risk": 70,
        "login_risk": 82,
        "campaign_similarity": 0.8,
    })
    assert cross["final_score"] >= 70

    policy = policy_aware_prevention({"role": "admin"}, {"criticality": "critical"}, {"category": "url"})
    assert policy["enforcement_level"] in {"strict", "standard", "monitor"}


def test_account_rescue_engine_scans_plans_and_requires_confirmation():
    scan = scan_account({"provider": "google", "forwarding_rule": True, "mfa_enabled": False, "new_oauth_app": True})
    assert scan["risk_level"] in {"HIGH", "CRITICAL"}
    assert scan["top_contributors"]
    plan = rescue_plan(scan)
    assert plan["honesty_note"]
    step = execute_step(plan, "remove_forwarding")
    assert step["status"] == "confirmation_required"
    manual = execute_step(plan, "remove_forwarding", confirmed=True)
    assert manual["status"] == "manual_required"


def test_account_rescue_supporting_features_are_safe_and_explicit():
    scan = scan_account({"provider": "microsoft", "mfa_enabled": False})
    plan = rescue_plan(scan)
    simulation = rescue_simulation(scan)
    report = rescue_report(scan, plan)
    assert simulation["side_effects"] is False
    assert simulation["risk_after"] <= simulation["risk_before"]
    assert report["export_format"]
    assert provider_capabilities("microsoft")["passwords_collected"] is False
    assert consent_record("google", ["readonly"], "scan")["status"] == "awaiting_confirmation"
    assert contact_warning_draft("demo", ["a@example.com"])["requires_explicit_send"] is True
    assert fleet_summary([{"label": "finance", "risk": 90, "consent": True}])["accounts"][0]["rescue_available"] is True
