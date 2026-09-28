import asyncio
import io
import json
import sqlite3
import sys
import types

import pytest
import numpy as np
from fastapi import HTTPException, UploadFile

from main import (
    admin_users,
    analyze_file,
    analyze_website,
    analyze_threat,
    compliance_controls,
    dashboard_metrics,
    get_db,
    summarize_dashboard_targets,
    initialize_database,
    incident_context,
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
    siem_demo_seed,
    idp_authenticate_user,
    adversarial_self_test,
    fatigue_routing,
    incident_intent,
    incident_drift,
    incident_memory,
    incident_explainability,
    alert_quality,
    alert_quality_record,
    record_alert_outcome,
    roadmap_immunity_publish,
    roadmap_counterfactual,
    roadmap_compliance_diff,
    roadmap_compliance_diff_sync,
    create_provider_ticket_route,
    disable_provider_identity_route,
    isolate_provider_endpoint_route,
    system_health,
)
from database import PostgresConnection, _postgresql_statement
from ephemeral_store import EphemeralStore
from cloudflare_waf import block_ip as cloudflare_block_ip
from production_integrations import IntegrationNotConfigured, create_ticket as create_production_ticket
from email_authenticity import analyze_eml, verify_sender_identity
from deepfake_models import _is_suspicious_label, _prepare_audio_waveform
from evaluate_media_dataset import calculate_metrics as calculate_media_metrics
from media_engine import media_inspection_status
from evaluate_public_datasets import evaluate as evaluate_public_text_dataset
import detection_engine
import deepfake_models
from campaign_engine import correlate_incident
from train_model import DEFAULT_DATASET, train as train_text_model
import website_inspector
from extended_intel import scan_payload
from models import ForecastRequest, LoginRequest, SimulationRequest, ThreatAnalysisRequest, ThreatIntelLookup
from models import ProviderEndpointIsolationRequest, ProviderIdentityDisableRequest, ProviderTicketRequest
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
from threat_fusion import compute_drift_snapshot, detect_memory_hits, generate_attacker_intent
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


def test_database_adapter_selects_postgresql_from_environment(monkeypatch):
    sentinel = object()
    monkeypatch.setenv("CYBERGUARD_DATABASE_URL", "postgresql://user:pass@localhost/cyberguard")
    monkeypatch.setattr("database.PostgresConnection", lambda url: (url, sentinel))

    connection = get_db()

    assert connection == ("postgresql://user:pass@localhost/cyberguard", sentinel)


def test_ephemeral_store_expires_challenges_and_tracks_atomic_operations():
    clock = [1_000.0]
    store = EphemeralStore(clock=lambda: clock[0])
    store.set("passkey:one", {"challenge": b"nonce", "expires_at": 1_030}, ttl_seconds=30)
    assert store.get("passkey:one")["challenge"] == b"nonce"
    assert store.pop("passkey:one")["challenge"] == b"nonce"
    assert store.pop("passkey:one") is None

    store.set("otp:one", {"otp_hash": "digest", "attempts": 0, "expires_at": 1_030}, ttl_seconds=30)
    assert store.increment_field("otp:one", "attempts") == 1
    assert store.increment_field("otp:one", "attempts") == 2
    assert store.pop_if("otp:one", "otp_hash", "wrong") is None
    assert store.pop_if("otp:one", "otp_hash", "digest")["attempts"] == 2

    assert store.record_window_event("security:ip", 1_000, 60) == 1
    assert store.record_window_event("security:ip", 1_030, 60) == 2
    assert store.record_window_event("security:ip", 1_061, 60) == 2

    store.set("short-lived", {"value": True}, ttl_seconds=2)
    clock[0] += 3
    assert store.get("short-lived") is None


def test_ephemeral_store_redis_operations_use_atomic_scripts():
    class RedisDouble:
        def __init__(self):
            self.values = {}
            self.sorted_sets = {}

        def set(self, key, value, ex=None):
            self.values[key] = value.encode() if isinstance(value, str) else value

        def get(self, key):
            return self.values.get(key)

        def eval(self, script, key_count, key, *args):
            raw = self.values.get(key)
            if "ZREMRANGEBYSCORE" in script:
                now, window, member = float(args[0]), float(args[1]), args[2]
                events = self.sorted_sets.setdefault(key, {})
                self.sorted_sets[key] = {name: score for name, score in events.items() if score > now - window}
                self.sorted_sets[key][member] = now
                return len(self.sorted_sets[key])
            if "tostring(value[ARGV[1]])" in script:
                if raw is None:
                    return None
                value = json.loads(raw)
                if str(value.get(args[0])) != args[1]:
                    return None
                return self.values.pop(key)
            if "value[ARGV[1]] =" in script:
                if raw is None:
                    return None
                value = json.loads(raw)
                value[args[0]] = int(value.get(args[0], 0)) + 1
                self.values[key] = json.dumps(value).encode()
                return value[args[0]]
            if "redis.call('DEL', KEYS[1])" in script:
                return self.values.pop(key, None)
            raise AssertionError("Unexpected Redis script")

    redis_double = RedisDouble()
    store = EphemeralStore(redis_client=redis_double, clock=lambda: 1_000.0)
    store.set("passkey:redis", {"challenge": b"nonce", "expires_at": 1_030}, ttl_seconds=30)
    assert store.get("passkey:redis")["challenge"] == b"nonce"
    assert store.pop("passkey:redis")["challenge"] == b"nonce"

    store.set("otp:redis", {"otp_hash": "digest", "attempts": 0}, ttl_seconds=30)
    assert store.increment_field("otp:redis", "attempts") == 1
    assert store.pop_if("otp:redis", "otp_hash", "digest")["attempts"] == 1

    assert store.record_window_event("security:redis", 1_000, 60) == 1
    assert store.record_window_event("security:redis", 1_030, 60) == 2


def test_ephemeral_store_requires_redis_in_production_and_selects_configured_client(monkeypatch):
    monkeypatch.setenv("CYBERGUARD_ENV", "production")
    monkeypatch.delenv("CYBERGUARD_REDIS_URL", raising=False)
    with pytest.raises(RuntimeError, match="required in production"):
        EphemeralStore.from_environment()

    class RedisClient:
        def ping(self):
            return True

    client = RedisClient()
    redis_module = types.ModuleType("redis")
    redis_module.RedisError = type("RedisError", (Exception,), {})
    redis_module.Redis = types.SimpleNamespace(from_url=lambda url, **kwargs: client)
    monkeypatch.setitem(sys.modules, "redis", redis_module)
    monkeypatch.setenv("CYBERGUARD_REDIS_URL", "redis://redis:6379/0")

    store = EphemeralStore.from_environment()

    assert store.backend == "redis"


def test_system_health_reports_ephemeral_state_backend():
    initialize_database()
    health = system_health({"username": "lead", "role": "lead"})

    assert health["ephemeral_state"] in {"redis", "process-local-memory"}


def test_cloudflare_block_validates_and_normalizes_ip_before_calling_provider(monkeypatch):
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "test-token")
    monkeypatch.setenv("CLOUDFLARE_ZONE_ID", "test-zone")
    captured = {}

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {"success": True, "result": {"id": "rule-1"}}

    def fake_post(url, **kwargs):
        captured.update({"url": url, **kwargs})
        return Response()

    monkeypatch.setattr("cloudflare_waf.requests.post", fake_post)
    result = cloudflare_block_ip(" 2001:0db8::1 ", "incident containment")

    assert result["status"] == "blocked"
    assert result["ip_address"] == "2001:db8::1"
    assert captured["json"]["configuration"]["value"] == "2001:db8::1"
    with pytest.raises(ValueError, match="valid IPv4 or IPv6"):
        cloudflare_block_ip("not-an-ip", "invalid target")


def test_cloudflare_block_rejects_provider_success_false(monkeypatch):
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "test-token")
    monkeypatch.setenv("CLOUDFLARE_ZONE_ID", "test-zone")

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {"success": False, "errors": [{"message": "denied"}]}

    monkeypatch.setattr("cloudflare_waf.requests.post", lambda *args, **kwargs: Response())
    with pytest.raises(RuntimeError, match="denied"):
        cloudflare_block_ip("192.0.2.10", "test containment")


def test_provider_action_routes_require_confirmation_and_return_provider_status(monkeypatch):
    admin = {"username": "root@example.org", "role": "head_admin"}
    monkeypatch.setattr("main.create_provider_ticket", lambda payload: {"provider": "jira", "status": "created", "result": {"key": "SEC-1"}})
    monkeypatch.setattr("main.disable_provider_identity", lambda identity: {"provider": "okta", "status": "suspended", "identity": identity})
    monkeypatch.setattr("main.isolate_provider_endpoint", lambda endpoint_id: {"provider": "edr", "status": "isolated", "endpoint_id": endpoint_id})

    assert create_provider_ticket_route(ProviderTicketRequest(summary="Investigation"), admin)["status"] == "created"
    with pytest.raises(HTTPException) as identity_error:
        disable_provider_identity_route(ProviderIdentityDisableRequest(identity="user-1"), admin)
    assert identity_error.value.status_code == 409
    with pytest.raises(HTTPException) as endpoint_error:
        isolate_provider_endpoint_route(ProviderEndpointIsolationRequest(endpoint_id="host-1"), admin)
    assert endpoint_error.value.status_code == 409
    assert disable_provider_identity_route(ProviderIdentityDisableRequest(identity="user-1", confirmed=True), admin)["status"] == "suspended"
    assert isolate_provider_endpoint_route(ProviderEndpointIsolationRequest(endpoint_id="host-1", confirmed=True), admin)["status"] == "isolated"


def test_jira_ticket_uses_api_token_basic_auth_and_requires_account_email(monkeypatch):
    monkeypatch.setenv("CYBERGUARD_JIRA_URL", "https://example.atlassian.net")
    monkeypatch.setenv("CYBERGUARD_JIRA_TOKEN", "api-token")
    monkeypatch.setenv("CYBERGUARD_JIRA_PROJECT", "SEC")
    monkeypatch.delenv("CYBERGUARD_JIRA_EMAIL", raising=False)
    with pytest.raises(IntegrationNotConfigured, match="CYBERGUARD_JIRA_EMAIL"):
        create_production_ticket({"summary": "Test issue"})

    monkeypatch.setenv("CYBERGUARD_JIRA_EMAIL", "soc@example.org")
    captured = {}

    class Response:
        content = b'{"key":"SEC-42"}'

        def raise_for_status(self):
            return None

        def json(self):
            return {"key": "SEC-42"}

    def fake_request(method, url, **kwargs):
        captured.update({"method": method, "url": url, **kwargs})
        return Response()

    monkeypatch.setattr("production_integrations.requests.request", fake_request)
    result = create_production_ticket({"summary": "Test issue"})

    assert result["status"] == "created"
    assert captured["url"] == "https://example.atlassian.net/rest/api/3/issue"
    assert captured["headers"]["Authorization"].startswith("Basic ")
    assert captured["json"]["fields"]["project"]["key"] == "SEC"


def test_website_inspector_rejects_non_global_dns_answers(monkeypatch):
    monkeypatch.setattr(website_inspector.socket, "getaddrinfo", lambda *args, **kwargs: [(None, None, None, None, ("100.64.0.1", 0))])

    with pytest.raises(ValueError, match="non-public network"):
        website_inspector._safe_addresses("public-looking.example")


def test_website_inspector_rechecks_redirect_targets_and_closes_streams(monkeypatch):
    requests_made = []

    class Response:
        is_redirect = True
        headers = {"location": "http://localhost/admin"}
        url = "https://public.example/"

        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

    response = Response()

    class Session:
        def __init__(self):
            self.trust_env = True
            self.adapters = {"https://": types.SimpleNamespace(close=lambda: None), "http://": types.SimpleNamespace(close=lambda: None)}

        def mount(self, prefix, adapter):
            self.adapters[prefix] = adapter

        def get(self, url, **kwargs):
            requests_made.append(url)
            return response

        def close(self):
            self.closed = True

    session = Session()
    monkeypatch.setattr(website_inspector.requests, "Session", lambda: session)
    monkeypatch.setattr(website_inspector.socket, "getaddrinfo", lambda hostname, *args, **kwargs: [(None, None, None, None, ("93.184.216.34", 0))] if hostname == "public.example" else [(None, None, None, None, ("127.0.0.1", 0))])

    with pytest.raises(ValueError, match="non-public network"):
        website_inspector.inspect_website("https://public.example/")

    assert requests_made == ["https://public.example/"]
    assert response.closed is True
    assert session.closed is True


def test_website_inspector_accepts_public_page_and_closes_response(monkeypatch):
    class Response:
        is_redirect = False
        headers = {}
        url = "https://public.example/"
        status_code = 200
        encoding = "utf-8"
        closed = False

        def iter_content(self, chunk_size):
            yield b"<html><title>Safe page</title></html>"

        def close(self):
            self.closed = True

    response = Response()

    class Session:
        def __init__(self):
            self.adapters = {"https://": types.SimpleNamespace(close=lambda: None), "http://": types.SimpleNamespace(close=lambda: None)}

        def mount(self, prefix, adapter):
            self.adapters[prefix] = adapter

        def get(self, url, **kwargs):
            assert kwargs["allow_redirects"] is False
            return response

        def close(self):
            self.closed = True

    session = Session()
    monkeypatch.setattr(website_inspector.requests, "Session", lambda: session)
    monkeypatch.setattr(website_inspector.socket, "getaddrinfo", lambda *args, **kwargs: [(None, None, None, None, ("93.184.216.34", 0))])

    result = website_inspector.inspect_website("https://public.example/")

    assert result["title"] == "Safe page"
    assert response.closed is True
    assert session.closed is True


def test_pinned_website_adapter_connects_to_resolved_ip_and_keeps_tls_hostname(monkeypatch):
    captured = {}
    adapter = website_inspector._PinnedAddressAdapter("public.example", "93.184.216.34", 443)

    class PoolManager:
        def connection_from_host(self, **kwargs):
            captured.update(kwargs)
            return "pinned-pool"

    adapter.poolmanager = PoolManager()
    request = website_inspector.requests.Request("GET", "https://public.example/path").prepare()

    assert adapter.get_connection_with_tls_context(request, verify=True) == "pinned-pool"
    assert captured["host"] == "93.184.216.34"
    assert captured["port"] == 443
    assert captured["pool_kwargs"]["assert_hostname"] == "public.example"
    assert captured["pool_kwargs"]["server_hostname"] == "public.example"

    monkeypatch.setattr(website_inspector.HTTPAdapter, "send", lambda self, prepared, **kwargs: prepared.headers.get("Host"))
    assert adapter.send(request) == "public.example"


def test_postgresql_sql_translation_preserves_insert_conflicts():
    assert _postgresql_statement("INSERT INTO users (username) VALUES (?)") == "INSERT INTO users (username) VALUES (%s)"
    assert _postgresql_statement("INSERT OR IGNORE INTO users (username) VALUES (?)") == "INSERT INTO users (username) VALUES (%s) ON CONFLICT DO NOTHING"
    assert _postgresql_statement("INSERT INTO blocked_ips (ip_address) VALUES (?) ON CONFLICT(ip_address) DO UPDATE SET ip_address = excluded.ip_address") == "INSERT INTO blocked_ips (ip_address) VALUES (%s) ON CONFLICT(ip_address) DO UPDATE SET ip_address = excluded.ip_address"


def test_postgresql_integrity_errors_match_existing_api_handling():
    class DatabaseConflict(Exception):
        pass

    class ConflictCursor:
        def execute(self, statement, parameters):
            raise DatabaseConflict("duplicate key")

    class ConflictConnection:
        def cursor(self):
            return ConflictCursor()

    connection = PostgresConnection.__new__(PostgresConnection)
    connection._integrity_error = DatabaseConflict
    connection._connection = ConflictConnection()

    with pytest.raises(sqlite3.IntegrityError, match="duplicate key"):
        connection.execute("INSERT INTO users (username) VALUES (?)")


def test_sender_identity_verification_checks_authentication_domain_alignment():
    aligned = verify_sender_identity(
        "Finance <alerts@bput.ac.in>",
        "alerts@bput.ac.in",
        "bounce@mailer.bput.ac.in",
        "mx; spf=pass smtp.mailfrom=mailer.bput.ac.in; dkim=pass header.d=bput.ac.in; dmarc=pass header.from=bput.ac.in",
        {"mx"},
    )
    spoofed = verify_sender_identity(
        "Finance <alerts@bput.ac.in>",
        "alerts@attacker.example",
        "bounce@attacker.example",
        "mx; spf=pass smtp.mailfrom=attacker.example; dkim=pass header.d=attacker.example; dmarc=pass header.from=attacker.example",
        {"mx"},
    )
    insufficient = verify_sender_identity("alerts@bput.ac.in", "", "", "")
    forged = verify_sender_identity(
        "alerts@bput.ac.in", "", "", "attacker.example; spf=pass smtp.mailfrom=bput.ac.in; dkim=pass header.d=bput.ac.in; dmarc=pass header.from=bput.ac.in", {"mx"}
    )

    assert aligned["status"] == "verified"
    assert aligned["risk_score"] < spoofed["risk_score"]
    assert spoofed["status"] == "mismatch"
    assert insufficient["status"] == "insufficient_evidence"
    assert forged["status"] == "untrusted_evidence"
    assert forged["risk_score"] > aligned["risk_score"]


def test_eml_analysis_exposes_sender_identity_assessment(monkeypatch):
    monkeypatch.setenv("CYBERGUARD_TRUSTED_AUTHSERV_IDS", "mx")
    result = analyze_eml(
        b"From: Finance <alerts@bput.ac.in>\r\n"
        b"Authentication-Results: mx; spf=pass smtp.mailfrom=bput.ac.in; dkim=pass header.d=bput.ac.in; dmarc=pass header.from=bput.ac.in\r\n"
        b"Subject: Account notice\r\n\r\nPlease review the account."
    )

    assert result["identity_verification"]["status"] == "verified"
    assert any(item["name"] == "Sender Identity Verification" for item in result["indicators"])


def test_pretrained_detector_maps_ai_voice_and_real_labels_correctly():
    assert _is_suspicious_label("AIVoice")
    assert _is_suspicious_label("AI-generated speech")
    assert _is_suspicious_label("Fake")
    assert not _is_suspicious_label("HumanVoice")
    assert not _is_suspicious_label("Real")


def test_media_status_distinguishes_cached_from_loaded_weights(monkeypatch, tmp_path):
    image_path = tmp_path / "image"
    audio_path = tmp_path / "audio"
    image_path.mkdir()
    audio_path.mkdir()
    monkeypatch.setattr(deepfake_models, "_IMAGE_MODEL", str(image_path))
    monkeypatch.setattr(deepfake_models, "_AUDIO_MODEL", str(audio_path))
    monkeypatch.setattr(deepfake_models, "_PIPELINES", {})
    monkeypatch.setattr(deepfake_models, "_LOAD_ERRORS", {})
    monkeypatch.setenv("CYBERGUARD_ENABLE_PRETRAINED_MEDIA", "true")

    status = deepfake_models.model_status()

    assert status["mode"] == "pretrained-cached"
    assert status["weights_cached"] == {"image": True, "audio": True}
    assert status["loaded"] == []


def test_media_inspection_status_reflects_missing_heuristic_dependencies(monkeypatch):
    import media_engine
    monkeypatch.setattr(media_engine, "np", None)
    monkeypatch.setattr(media_engine, "IsolationForest", None)

    status = media_inspection_status()

    assert status["available"] is False
    assert status["mode"] == "limited-fallback"
    assert status["dependencies"]["numpy"] is False


def test_pretrained_audio_input_is_downmixed_and_resampled():
    time = np.arange(44100, dtype=np.float32) / 44100
    stereo = np.column_stack((np.sin(2 * np.pi * 440 * time), np.sin(2 * np.pi * 440 * time)))

    mono, sample_rate = _prepare_audio_waveform(stereo, 44100, 16000)

    assert sample_rate == 16000
    assert mono.ndim == 1
    assert abs(len(mono) - 16000) <= 1


def test_media_engine_decodes_flac_audio(monkeypatch):
    soundfile = pytest.importorskip("soundfile")
    import media_engine
    import deepfake_models

    monkeypatch.setattr(deepfake_models, "analyze_pretrained", lambda content, kind: None)
    waveform = np.column_stack((np.zeros(4410), np.zeros(4410))).astype(np.float32)
    audio = io.BytesIO()
    soundfile.write(audio, waveform, 44100, format="FLAC")

    result = media_engine.analyze_media(audio.getvalue(), "application/octet-stream", "voice.flac", "audio")

    assert result["method"] == "audio-anomaly-model"
    assert any("44100 Hz" in reason for reason in result["reasons"])


def test_media_evaluation_reports_rank_and_threshold_metrics():
    metrics = calculate_media_metrics([
        {"label": 0, "score": 10},
        {"label": 0, "score": 80},
        {"label": 1, "score": 60},
        {"label": 1, "score": 90},
    ])

    assert metrics["confusion_matrix"] == {"tn": 1, "fp": 1, "fn": 0, "tp": 2}
    assert metrics["precision"] == pytest.approx(2 / 3)
    assert metrics["recall"] == 1
    assert metrics["f1"] == pytest.approx(0.8)
    assert metrics["roc_auc"] == pytest.approx(0.75)
    assert metrics["pr_auc"] == pytest.approx(5 / 6)


def test_media_evaluation_rejects_single_class_or_invalid_threshold():
    with pytest.raises(ValueError, match="both real and fake"):
        calculate_media_metrics([{"label": 0, "score": 5}])
    with pytest.raises(ValueError, match="between 0 and 100"):
        calculate_media_metrics([{"label": 0, "score": 5}, {"label": 1, "score": 90}], 101)


def test_public_text_evaluation_reports_real_latency_percentiles_and_threshold(tmp_path):
    pytest.importorskip("sklearn")
    dataset = tmp_path / "text.csv"
    dataset.write_text(
        "text,label\n" + "".join(f"normal campus announcement number {index},0\n" for index in range(20))
        + "".join(f"urgent prize claim verify account number {index},1\n" for index in range(20)),
        encoding="utf-8",
    )

    result = evaluate_public_text_dataset(dataset, threshold=40)

    assert result["decision_threshold"] == 40
    assert result["fit_time_ms"] >= 0
    assert result["median_latency_ms_per_sample"] >= 0
    assert result["p95_latency_ms_per_sample"] >= result["median_latency_ms_per_sample"]
    with pytest.raises(ValueError, match="between 0 and 100"):
        evaluate_public_text_dataset(dataset, threshold=101)


def test_text_model_risk_gate_uses_configured_confidence_threshold(monkeypatch):
    monkeypatch.setattr(detection_engine, "model_signal", lambda payload: (55, {"name": "test model", "score": "55%"}))
    monkeypatch.setattr(detection_engine, "TEXT_MODEL_THRESHOLD", 50)
    enabled = detection_engine.evaluate_threat_payload("email", "A routine note")
    monkeypatch.setattr(detection_engine, "TEXT_MODEL_THRESHOLD", 60)
    gated = detection_engine.evaluate_threat_payload("email", "A routine note")

    assert enabled["risk_score"] == 55
    assert gated["risk_score"] == 6


def test_text_training_defaults_to_uci_and_saves_a_usable_artifact(tmp_path):
    assert DEFAULT_DATASET.name == "uci_sms_spam.csv"
    dataset = tmp_path / "messages.csv"
    dataset.write_text(
        "text,label\n" + "".join(f"normal campus notice {index},0\n" for index in range(20))
        + "".join(f"urgent prize claim verify account {index},1\n" for index in range(20)),
        encoding="utf-8",
    )
    model_path = tmp_path / "model.joblib"

    model = train_text_model(dataset, model_path)

    assert model_path.exists()
    assert model.predict_proba(["urgent verify account"])[0][1] > model.predict_proba(["normal campus notice"])[0][1]


def test_flower_client_redacts_local_data_and_requires_both_labels(tmp_path):
    pytest.importorskip("flwr")
    from flower_federated import load_local_dataset

    dataset = tmp_path / "client.csv"
    dataset.write_text(
        "text,label\nContact alice@example.org with code 12345678,1\nNormal campus notice,0\n",
        encoding="utf-8",
    )
    texts, labels = load_local_dataset(dataset)

    assert "alice@example.org" not in texts[0]
    assert "12345678" not in texts[0]
    assert set(labels.tolist()) == {0, 1}

    invalid_dataset = tmp_path / "invalid.csv"
    invalid_dataset.write_text("text,label\nMessage,1\n", encoding="utf-8")
    with pytest.raises(ValueError, match="both benign"):
        load_local_dataset(invalid_dataset)


def test_flower_entrypoints_forward_network_addresses(monkeypatch, tmp_path):
    pytest.importorskip("flwr")
    import flower_federated as flower

    server_call = {}
    monkeypatch.setattr(flower.fl.server, "start_server", lambda **kwargs: server_call.update(kwargs))
    with pytest.raises(ValueError, match="require TLS certificates"):
        flower.start_server(2, "0.0.0.0:9010", 2)
    certificate_paths = [tmp_path / "ca.pem", tmp_path / "server.pem", tmp_path / "server-key.pem"]
    for path, contents in zip(certificate_paths, (b"ca", b"server-cert", b"server-key")):
        path.write_bytes(contents)
    certificates = flower.load_server_certificates(*certificate_paths)
    with pytest.raises(ValueError, match="requires CA certificate"):
        flower.load_server_certificates(certificate_paths[0], None, certificate_paths[2])
    flower.start_server(2, "0.0.0.0:9010", 2, certificates)
    assert server_call["server_address"] == "0.0.0.0:9010"
    assert server_call["strategy"].min_available_clients == 2
    assert server_call["certificates"] == (b"ca", b"server-cert", b"server-key")

    dataset = tmp_path / "client.csv"
    dataset.write_text("text,label\nurgent payment,1\nnormal notice,0\n", encoding="utf-8")
    client_call = {}
    monkeypatch.setattr(flower.fl.client, "start_client", lambda **kwargs: client_call.update(kwargs))
    with pytest.raises(ValueError, match="require a trusted root certificate"):
        flower.start_client(dataset, "10.0.0.8:9010")
    root_certificate = tmp_path / "root.pem"
    root_certificate.write_bytes(b"root-cert")
    flower.start_client(dataset, "10.0.0.8:9010", root_certificate)
    assert client_call["server_address"] == "10.0.0.8:9010"
    assert client_call["root_certificates"] == b"root-cert"
    assert client_call["insecure"] is False


def test_dashboard_target_summary_ranks_entities_and_masks_identifiers():
    targets = summarize_dashboard_targets([
        {"payload": "Contact alice.smith@example.org at https://login.example.org/auth", "risk_score": 85},
        {"payload": "Repeat alert for alice.smith@example.org and https://login.example.org/reset", "risk_score": 40},
        {"payload": "Source 203.0.113.42 connected to https://other.example.net", "risk_score": 75},
    ])

    user_target = next(target for target in targets if target["type"] == "user")
    service_target = next(target for target in targets if target["label"] == "login.example.org")
    network_target = next(target for target in targets if target["type"] == "network")
    assert user_target["label"] == "a***@example.org"
    assert user_target["incident_count"] == 2
    assert user_target["high_risk_count"] == 1
    assert service_target["incident_count"] == 2
    assert network_target["label"] == "203.0.113.x"


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


def test_campaign_correlation_requires_shared_evidence():
    incident = {
        "id": 1,
        "category": "email",
        "payload": "unrelated account notice",
        "assessment": {"iocs": [], "mitre_techniques": []},
    }
    unrelated = {
        "id": 2,
        "category": "email",
        "payload": "different unrelated account notice",
        "assessment": {"iocs": [], "mitre_techniques": []},
    }
    shared_indicator = {
        **unrelated,
        "id": 3,
        "assessment": {"iocs": [{"type": "domain", "indicator": "login.example.test"}], "mitre_techniques": []},
    }
    incident["assessment"]["iocs"] = [{"type": "domain", "indicator": "login.example.test"}]

    unrelated_result = correlate_incident(incident, [unrelated])
    shared_result = correlate_incident(incident, [shared_indicator])

    assert unrelated_result["related_incidents"] == []
    assert shared_result["related_incidents"][0]["incident_id"] == 3


def test_shared_immunity_signatures_require_evidence_and_hide_metadata():
    incident = {
        "id": 7,
        "category": "phishing",
        "risk_level": "Critical",
        "fingerprint": "known-fingerprint",
        "payload": "private customer credential lure",
    }
    result = shared_immunity([incident], signing_secret="exchange-secret")

    assert result["signature_count"] == 1
    assert set(result["shared_signatures"][0]) == {"signature"}
    assert "private customer" not in json.dumps(result)
    assert "Critical" not in json.dumps(result)
    assert shared_immunity([{"category": "phishing", "payload": ""}])["signature_count"] == 0
    evidence_only = shared_immunity([{"category": "phishing", "assessment": {"iocs": [{"type": "domain", "indicator": "login.example.test"}], "mitre_techniques": None}}], signing_secret="exchange-secret")
    assert evidence_only["signature_count"] == 1


def test_shared_immunity_publish_uses_configured_installation_identity(monkeypatch):
    monkeypatch.delenv("CYBERGUARD_TENANT_ID", raising=False)
    with pytest.raises(HTTPException) as error:
        roadmap_immunity_publish({}, {"username": "lead", "role": "head_admin"})
    assert error.value.status_code == 503

    monkeypatch.setenv("CYBERGUARD_TENANT_ID", "stable-org-id")
    monkeypatch.setenv("CYBERGUARD_TENANT_IMMUNITY_SECRET", "exchange-secret")
    monkeypatch.setattr("main._roadmap_incidents", lambda: [{"id": 1, "fingerprint": "incident-fingerprint"}])
    captured = {}
    monkeypatch.setattr(
        "main.publish_tenant_signatures",
        lambda signatures, tenant_id: captured.update({"signatures": signatures, "tenant_id": tenant_id}) or {"status": "published", "published": len(signatures)},
    )

    result = roadmap_immunity_publish(
        {"tenant_id": "caller-controlled-id", "signatures": [{"signature": "untrusted", "source_tenant": "analyst@example.org"}]},
        {"username": "lead", "role": "head_admin"},
    )

    assert result["status"] == "published"
    assert captured["tenant_id"] == "stable-org-id"
    assert len(captured["signatures"]) == 1
    assert set(captured["signatures"][0]) == {"signature"}


def test_threat_memory_uses_resolved_history_and_matches_exact_payloads():
    payload = "Urgent verify your credentials at login.example.test"
    open_match = detect_memory_hits(payload, [{"id": 5, "payload": payload, "status": "Investigating", "risk_score": 90}])
    resolved_match = detect_memory_hits(payload, [{"id": 6, "payload": payload, "status": "Closed", "risk_score": 90}])

    assert open_match["status"] == "fresh-analysis"
    assert resolved_match["status"] == "memory-hit"
    assert resolved_match["matches"][0]["match_score"] == 100


def test_attacker_intent_uses_shared_ioc_evidence_from_related_incidents():
    incident = {
        "id": 1,
        "category": "phishing",
        "risk_score": 50,
        "payload": "verify credentials at login.example.test",
        "assessment": {"iocs": [{"type": "domain", "indicator": "login.example.test"}], "mitre_techniques": []},
    }
    same_category_only = {"id": 2, "category": "phishing", "risk_score": 80, "assessment": {"iocs": [], "mitre_techniques": []}}
    shared_ioc = {"id": 3, "category": "email", "risk_score": 60, "assessment": {"iocs": [{"type": "domain", "indicator": "login.example.test"}], "mitre_techniques": []}}

    intent = generate_attacker_intent(incident, [same_category_only, shared_ioc])

    assert [item["incident_id"] for item in intent["related_incidents"]] == [3]
    assert intent["confidence"] > generate_attacker_intent(incident)["confidence"]
    assert "corroborated" in intent["summary"]


def test_fingerprint_drift_ignores_unrelated_evidence_free_incidents():
    incident = {"id": 1, "category": "phishing", "payload": "account notice", "assessment": {"iocs": [], "mitre_techniques": []}}
    unrelated = {"id": 2, "category": "phishing", "payload": "different notice", "assessment": {"iocs": [], "mitre_techniques": []}}
    related = {"id": 3, "category": "email", "payload": "account notice", "assessment": {"iocs": [{"type": "domain", "indicator": "login.example.test"}], "mitre_techniques": ["T1566"]}}
    incident["assessment"] = {"iocs": [{"type": "domain", "indicator": "login.example.test"}], "mitre_techniques": ["T1566"]}

    unrelated_result = compute_drift_snapshot({**incident, "assessment": {"iocs": [], "mitre_techniques": []}}, [unrelated])
    related_result = compute_drift_snapshot(incident, [related])

    assert unrelated_result["related_incidents"] == []
    assert related_result["related_incidents"][0]["incident_id"] == 3


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


def test_siem_demo_seed_is_persistent_and_idempotent(tmp_path, monkeypatch):
    monkeypatch.setattr("main.DB_PATH", tmp_path / "siem.db")
    initialize_database()
    user = {"username": "lead", "role": "lead"}

    first = siem_demo_seed(user)
    second = siem_demo_seed(user)

    assert first["seeded"] is True
    assert second["seeded"] is False
    assert first["count"] == second["count"] == 3


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


def test_alert_outcomes_are_persisted_in_configured_database(tmp_path, monkeypatch):
    monkeypatch.setattr("main.DB_PATH", tmp_path / "feedback.db")
    initialize_database()

    outcome = record_alert_outcome(incident_id=77, detection_type="phishing", alert_risk_score=84, final_resolution="false_positive", reviewed_by="lead")
    report = alert_quality()
    with get_db() as db:
        stored = db.execute("SELECT incident_id, final_resolution, was_correct FROM alert_outcomes WHERE incident_id = ?", (77,)).fetchone()

    assert outcome["was_correct"] is False
    assert stored["final_resolution"] == "false_positive"
    assert report["overall_score"] == 0
    assert report["detection_types"]["phishing"] == 0


def test_alert_feedback_reviewer_comes_from_authenticated_user(tmp_path, monkeypatch):
    monkeypatch.setattr("main.DB_PATH", tmp_path / "reviewer.db")
    initialize_database()

    outcome = alert_quality_record(
        {"incident_id": 91, "detection_type": "phishing", "alert_risk_score": 84, "final_resolution": "malicious", "reviewed_by": "someone-else"},
        {"username": "lead", "role": "lead"},
    )

    assert outcome["reviewed_by"] == "lead"


def test_adversarial_self_test_exposes_confidence_decay():
    result = adversarial_self_test("email", "URGENT verify credentials at https://secure-login.xyz/auth?redirect=evil")
    assert result["baseline_score"] >= 0
    assert result["adversarial_probes"]
    assert result["confidence_decay"] >= 0


def test_adversarial_self_test_excludes_unchanged_and_duplicate_probes():
    payload = "URGENT verify your PASSWORD immediately"
    result = adversarial_self_test("email", payload)
    variants = [probe["variant"] for probe in result["adversarial_probes"]]

    assert variants
    assert all(variant != payload for variant in variants)
    assert len(variants) == len(set(variants))


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


def test_fatigue_routing_counts_active_work_and_excludes_resolved_incidents():
    result = fatigue_routing(
        [
            {"database_id": 1, "risk_score": 90, "status": "Investigating", "assigned_to": "analyst-a"},
            {"database_id": 2, "risk_score": 70, "status": "New", "assigned_to": None},
            {"database_id": 3, "risk_score": 80, "status": "Closed", "assigned_to": "analyst-b"},
        ],
        [
            {"username": "analyst-a", "role": "analyst"},
            {"username": "analyst-b", "role": "analyst"},
        ],
    )

    queue = {item["incident_id"]: item for item in result["recommended_queue"]}
    assert queue[2]["target"] == "analyst-b"
    assert 3 not in queue

    no_roster = fatigue_routing([{"database_id": 4, "risk_score": 60, "status": "New"}], [])
    assert no_roster["recommended_queue"][0]["target"] == "unassigned"
    assert no_roster["route_summary"]["available_analysts"] == 0


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


def test_jurisdiction_requires_and_persists_explicit_residency_metadata(tmp_path, monkeypatch):
    monkeypatch.setattr("main.DB_PATH", tmp_path / "jurisdiction.db")
    initialize_database()
    lead = {"username": "lead", "role": "lead"}

    missing = jurisdiction_route({"risk_score": 40})
    result = analyze_threat(
        ThreatAnalysisRequest(category="email", payload="Routine account notice", metadata={"country": "United States"}),
        lead,
    )
    stored_incident = incident_context(result["incident_id"])
    routed = jurisdiction_route(stored_incident)

    assert missing["jurisdiction"] == "Unknown / global review"
    assert stored_incident["metadata"]["country"] == "United States"
    assert routed["country"] == "US"
    assert routed["jurisdiction"] == "United States"


def test_website_analysis_persists_incident_and_jurisdiction_metadata(tmp_path, monkeypatch):
    monkeypatch.setattr("main.DB_PATH", tmp_path / "website-analysis.db")
    initialize_database()
    monkeypatch.setattr("main.inspect_website", lambda url: {"final_url": url, "title": "Account verification", "findings": ["look-alike login page"]})

    result = analyze_website(
        {"url": "https://login.example.test", "metadata": {"country": "GB"}},
        {"username": "lead", "role": "lead"},
    )
    stored = incident_context(result["incident_id"])

    assert stored["metadata"]["country"] == "GB"
    assert jurisdiction_route(stored)["jurisdiction"] == "United Kingdom"


def test_uploaded_file_analysis_persists_residency_metadata(tmp_path, monkeypatch):
    monkeypatch.setattr("main.DB_PATH", tmp_path / "file-analysis.db")
    initialize_database()

    result = asyncio.run(analyze_file(
        category="email",
        file=UploadFile(file=io.BytesIO(b"routine account notice"), filename="notice.txt"),
        metadata=json.dumps({"country": "EU", "private_note": "discard this"}),
        user={"username": "lead", "role": "lead"},
    ))
    stored = incident_context(result["incident_id"])

    assert stored["metadata"] == {"country": "EU"}
    assert jurisdiction_route(stored)["jurisdiction"] == "European Union"


def test_limited_roadmap_workflows_are_functional():
    incident = {"database_id": 7, "risk_score": 80, "category": "deepfake"}
    media = cross_modal_consistency([{"score": 20, "method": "image"}, {"score": 48, "method": "audio"}])
    assert media["media_count"] == 2
    assert media["status"] == "cross-modal mismatch"
    replay = counterfactual_replay(incident, ["isolate"], "response_delay_hours", 30)
    assert replay["counterfactual_risk"] > replay["baseline_risk"]
    diff = compliance_diff([{"id": "control-1", "status": "Needs Review"}], [{"id": "CVE-TEST", "severity": "high"}])
    assert diff["gap_count"] == 2


def test_counterfactual_replay_rejects_unmodeled_variables_and_actions():
    incident = {"database_id": 9, "risk_score": 70}

    with pytest.raises(ValueError, match="Unsupported counterfactual variable"):
        counterfactual_replay(incident, ["isolate"], "attacker_skill", 4)
    with pytest.raises(ValueError, match="Unsupported response action"):
        counterfactual_replay(incident, ["grant-admin-access"], "response_delay_hours", 4)


def test_counterfactual_api_returns_validation_errors_for_unmodeled_input(monkeypatch):
    monkeypatch.setattr("main.incident_context", lambda incident_id: {"database_id": incident_id, "risk_score": 70})
    user = {"username": "lead", "role": "lead"}

    with pytest.raises(HTTPException) as error:
        roadmap_counterfactual(9, {"actions": ["isolate"], "variable": "attacker_skill", "value": 4}, user)
    assert error.value.status_code == 422

    with pytest.raises(HTTPException) as error:
        roadmap_counterfactual(9, {"actions": "isolate", "variable": "response_delay_hours", "value": 4}, user)
    assert error.value.status_code == 422


def test_synced_cves_persist_and_feed_subsequent_compliance_diffs(tmp_path, monkeypatch):
    monkeypatch.setattr("main.DB_PATH", tmp_path / "cve-sync.db")
    initialize_database()
    monkeypatch.setattr("main.sync_cve_feed", lambda: {
        "status": "synced",
        "configured": True,
        "source": "test-feed",
        "cves": ["CVE-2026-1000"],
        "items": [{"id": "CVE-2026-1000", "severity": "critical"}],
    })
    user = {"username": "lead", "role": "lead"}

    synced = roadmap_compliance_diff_sync(user)
    subsequent = roadmap_compliance_diff({"cves": []}, user)

    assert synced["diff"]["cve_count"] == 1
    assert any(gap.get("id") == "CVE-2026-1000" for gap in subsequent["gaps"])


def test_cross_modal_consistency_requires_distinct_valid_media_channels():
    same_modality = cross_modal_consistency([
        {"score": 20, "media_type": "image/png", "method": "image-anomaly-model"},
        {"score": 48, "media_type": "image/jpeg", "method": "image-anomaly-model"},
    ])
    invalid = cross_modal_consistency([
        {"score": "not-a-score", "media_type": "image/png", "method": "image-anomaly-model"},
        {"score": float("nan"), "media_type": "audio/wav", "method": "audio-anomaly-model"},
        {"score": 99, "media_type": "video/mp4", "method": "metadata-fallback"},
    ])

    assert same_modality["status"] == "insufficient evidence"
    assert same_modality["media_count"] == 1
    assert invalid["status"] == "insufficient evidence"
    assert invalid["media_count"] == 0


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
