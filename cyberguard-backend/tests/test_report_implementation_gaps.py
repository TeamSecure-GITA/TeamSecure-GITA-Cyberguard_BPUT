import pytest
from fastapi import HTTPException

import detection_engine
import main
import media_engine
from extended_intel import analyze_trust_media, build_global_threat_map, build_identity_heatmap
from forecast_engine import forecast_risk
import malware_scanner


def test_identity_heatmap_uses_observed_incidents_without_synthetic_roles():
    empty = build_identity_heatmap([])
    observed = build_identity_heatmap([
        {"payload": "Security alert for Alice <alice@example.com>", "risk_score": 80},
        {"payload": "alice@example.com reported a suspicious login", "risk_score": 40},
        {"payload": "No identity in this event", "risk_score": 99},
    ])

    assert empty["status"] == "insufficient_data"
    assert empty["identities"] == []
    assert observed["identities"] == [{
        "label": "a***@example.com",
        "risk": 60,
        "incidents": 2,
        "max_risk": 80,
    }]


def test_threat_map_only_counts_incidents_with_explicit_valid_source_coordinates():
    result = build_global_threat_map([
        {"category": "url", "metadata": {}},
        {"category": "email", "metadata": {"source_location": {"country": "IN", "lat": 20.5, "lng": 78.9}}},
        {"category": "ato", "metadata": {"source_location": {"country": "XX", "lat": 100, "lng": 0}}},
    ])

    assert result["status"] == "observed"
    assert result["total_events"] == 3
    assert result["geolocated_events"] == 1
    assert result["locations"] == [{
        "country": "IN",
        "code": "IN",
        "lat": 20.5,
        "lng": 78.9,
        "category": "email",
        "count": 1,
        "source": "reported_metadata",
    }]


def test_source_location_metadata_is_validated_and_preserved_for_incidents():
    normalized = main.normalize_residency_metadata({
        "source_location": {"country": "IN", "lat": "20.5", "lng": 78.9},
    })

    assert normalized["source_location"] == {
        "country": "IN",
        "lat": 20.5,
        "lng": 78.9,
        "source": "reported_metadata",
    }
    with pytest.raises(HTTPException, match="outside valid latitude/longitude ranges"):
        main.normalize_residency_metadata({"source_location": {"country": "IN", "lat": 100, "lng": 78.9}})


@pytest.mark.parametrize("password_value", [None, ""])
def test_demo_password_must_be_configured_to_enable_demo_credentials(
    monkeypatch,
    tmp_path,
    password_value,
):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "demo-passwords.sqlite")
    if password_value is None:
        monkeypatch.delenv("CYBERGUARD_DEMO_ANALYST_PASSWORD", raising=False)
    else:
        monkeypatch.setenv("CYBERGUARD_DEMO_ANALYST_PASSWORD", password_value)

    main.initialize_database()

    with main.get_db() as db:
        account = db.execute(
            "SELECT status FROM users WHERE lower(username) = 'analyst' AND role = 'analyst'"
        ).fetchone()

    assert account is None or account["status"] == "disabled"


def test_insider_risk_uses_observed_application_audit_events(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "insider-audit.sqlite")
    main.initialize_database()
    user = {"username": "audit-analyst", "role": "analyst"}
    with main.get_db() as db:
        db.executemany(
            "INSERT INTO audit_logs (username, action, resource, details, created_at) VALUES (?, ?, ?, ?, ?)",
            [
                ("audit-analyst", "export_report", "case-1", "routine report export", "2026-10-01T23:00:00+00:00"),
                ("audit-analyst", "role_update", "user-2", "sensitive credential access", "2026-10-01T23:30:00+00:00"),
                ("other-user", "export_report", "case-2", "bulk_export sensitive", "2026-10-01T23:45:00+00:00"),
            ],
        )

    result = main.prevention_insider_risk(user)

    assert result["assessment_source"] == "application_audit_telemetry"
    assert result["event_count"] == 2
    assert result["observation_window_days"] == 30
    assert result["flags"]["off_hours"] is True
    assert result["flags"]["privilege_change"] is True
    assert result["flags"]["suspicious_downloads"] is False
    assert result["flags"]["sensitive_access"] == 1
    assert result["risk_score"] == 48
    assert result["incident_id"] is None


def test_media_trust_uses_detector_result_and_discloses_uncalibrated_score(monkeypatch):
    monkeypatch.setattr(media_engine, "analyze_media", lambda *_: {
        "score": 72,
        "method": "pretrained-image-detector",
        "reasons": ["Model flagged the image for review."],
        "indicators": [{"name": "Image detector", "model_output": 72}],
        "pretrained_model": {"model": "local-test-model"},
    })

    result = analyze_trust_media(b"image bytes", "sample.png", "image/png")

    assert result["media_type"] == "image"
    assert result["risk_score"] == 72
    assert result["trust_score"] == 28
    assert result["voice_authenticity"] is None
    assert result["face_authenticity"] is None
    assert result["lip_sync_match"] is None
    assert "not a probability" in result["calibration"]
    assert result["method"] == "pretrained-image-detector"


def test_forecast_projection_has_no_fabricated_confidence_and_follows_observed_trend():
    result = forecast_risk([
        {"risk_score": 40, "created_at": "2026-10-02T12:15:00+00:00"},
        {"risk_score": 60, "created_at": "2026-10-02T11:15:00+00:00"},
        {"risk_score": 80, "created_at": "2026-10-02T10:15:00+00:00"},
    ], horizon=2)

    assert result["baseline"] == 40
    assert result["trend"] == "declining"
    assert [point["risk"] for point in result["forecast"]] == [20, 0]
    assert all("confidence" not in point for point in result["forecast"])
    assert result["sample_count"] == 3


def test_forecast_has_no_projected_zero_risk_when_there_is_no_incident_data():
    result = forecast_risk([], horizon=2)

    assert result["forecast"] == []
    assert result["method"] == "insufficient_data"
    assert result["drivers"] == ["No recent incidents"]


def test_high_risk_recommendations_are_specific_to_threat_category(monkeypatch):
    monkeypatch.setattr(detection_engine, "model_signal", lambda _payload: (0, None))
    monkeypatch.setattr(detection_engine, "analyze_url_intelligence", lambda _payload: (85, ["test URL signal"], []))
    monkeypatch.setattr(detection_engine, "analyze_deepfake", lambda _payload: (85, ["test media signal"], []))
    monkeypatch.setattr(detection_engine, "analyze_authentication_event", lambda _payload: (90, ["test login signal"], []))

    url_actions = detection_engine.evaluate_threat_payload("url", "http://login-verify.example")["recommended_actions"]
    media_actions = detection_engine.evaluate_threat_payload("deepfake", "synthetic video review")["recommended_actions"]
    ato_actions = detection_engine.evaluate_threat_payload(
        "ato",
        '{"failed_attempts": 8, "total_attempts": 10, "distinct_accounts": 6, "new_device": true}',
    )["recommended_actions"]

    assert url_actions[0]["id"] == "block_domain"
    assert media_actions[0]["id"] == "quarantine"
    assert "manual authenticity review" in media_actions[0]["label"]
    assert ato_actions[0]["id"] == "revoke_session"
    assert all(any(action["id"] == "notify_soc" for action in actions) for actions in (url_actions, media_actions, ato_actions))


def test_auto_category_router_prefers_structured_network_evidence():
    result = detection_engine.predict_threat_category(
        '{"src_ip":"10.0.0.4","dst_ip":"10.0.0.8","src_port":443,"bytes_out":9000}'
    )

    assert result["category"] == "network"
    assert result["candidates"][0]["category"] == "network"
    assert len(result["candidates"]) == 3
    assert "not probabilities" in result["calibration"]


def test_analyze_endpoint_accepts_missing_category_and_returns_candidates():
    main.initialize_database()
    response = main.analyze_threat(
        main.ThreatAnalysisRequest(payload='{"src_ip":"10.0.0.4","dst_port":443,"bytes_out":9000}'),
        {"username": "auto-router-test", "role": "analyst"},
    )

    assert response["category"] == "network"
    assert response["assessment"]["classification"]["candidates"][0]["category"] == "network"


def test_dashboard_metrics_include_all_scenario_categories(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "dashboard-families.sqlite")
    main.initialize_database()
    now = "2026-10-08T00:00:00+00:00"
    with main.get_db() as db:
        db.executemany(
            "INSERT INTO incidents (category, payload, risk_score, risk_level, assessment, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            [(category, "sample", 50, "Medium", "{}", now) for category in (
                "email", "phishing", "image", "audio", "video", "deepfake", "ato", "auth_logs", "anomaly", "impersonation"
            )],
        )

    metrics = main.dashboard_metrics({"username": "dashboard-test", "role": "analyst"})

    assert metrics["phishingCount"] == 2
    assert metrics["deepfakeCount"] == 4
    assert metrics["atoCount"] == 3
    assert metrics["impersonationCount"] == 1


def test_text_model_is_not_applied_to_structured_or_media_categories(monkeypatch):
    monkeypatch.setattr(
        detection_engine,
        "model_signal",
        lambda _payload: (_ for _ in ()).throw(AssertionError("text model called for non-text category")),
    )

    for category in ("url", "network", "system_logs", "image", "audio", "video", "malware"):
        detection_engine.evaluate_threat_payload(category, "routine evidence")


def test_malware_signatures_cover_credential_dumping_script_download_and_persistence():
    samples = {
        "dump.bin": b"lsass.exe OpenProcess MiniDumpWriteDump",
        "download.ps1": b"DownloadString Invoke-Expression",
        "persist.reg": b"Software\\Microsoft\\Windows\\CurrentVersion\\Run powershell.exe",
    }

    results = {filename: malware_scanner.scan_artifact(content, filename) for filename, content in samples.items()}

    assert results["dump.bin"]["status"] == "matches_found"
    assert "Windows_Credential_Dumping_Primitives" in {item["rule"] for item in results["dump.bin"]["matches"]}
    assert "Scripted_Remote_Download_And_Execution" in {item["rule"] for item in results["download.ps1"]["matches"]}
    assert "Windows_Persistence_Run_Key_With_Script_Launch" in {item["rule"] for item in results["persist.reg"]["matches"]}


def test_screenshot_brand_domain_mismatch_requires_login_text_and_untrusted_domain():
    mismatch = detection_engine.analyze_screenshot_brand_mismatches(
        "Microsoft sign in. Enter your password at https://microsoft-login.example"
    )
    trusted = detection_engine.analyze_screenshot_brand_mismatches(
        "Microsoft sign in. Enter your password at https://login.microsoft.com"
    )
    no_login_claim = detection_engine.analyze_screenshot_brand_mismatches(
        "Microsoft news: https://microsoft-login.example"
    )

    assert mismatch == [{
        "brand": "microsoft",
        "observed_domain": "microsoft-login.example",
        "expected_domain": "microsoft.com",
    }]
    assert trusted == []
    assert no_login_claim == []
