import hashlib
import hmac
import json

import provider_integrations
import production_integrations


def test_provider_readiness_does_not_expose_secret_values(monkeypatch):
    monkeypatch.setenv("CYBERGUARD_RESPONSE_WEBHOOK_URL", "https://example.test/response")
    monkeypatch.setenv("CYBERGUARD_ALERT_WEBHOOK_URL", "https://example.test/alert")
    result = provider_integrations.provider_readiness()
    assert result["checks"]["response_webhook"]["configured"] is True
    assert result["ready"] is False
    assert "https://example.test/response" not in json.dumps(result)


def test_tenant_exchange_requires_stable_installation_id(monkeypatch):
    monkeypatch.setenv("CYBERGUARD_TENANT_IMMUNITY_URL", "https://exchange.example.test")
    monkeypatch.setenv("CYBERGUARD_TENANT_IMMUNITY_SECRET", "exchange-secret")
    monkeypatch.delenv("CYBERGUARD_TENANT_ID", raising=False)
    assert provider_integrations.tenant_exchange_status()["configured"] is False

    monkeypatch.setenv("CYBERGUARD_TENANT_ID", "stable-org-id")
    assert provider_integrations.tenant_exchange_status()["configured"] is True


def test_signed_webhook_delivery(monkeypatch):
    captured = {}

    class Response:
        content = b'{"accepted": true}'

        def raise_for_status(self):
            return None

        def json(self):
            return {"accepted": True}

    def fake_post(url, data, headers, timeout):
        captured.update({"url": url, "body": data, "headers": headers, "timeout": timeout})
        return Response()

    monkeypatch.setattr(provider_integrations.requests, "post", fake_post)
    monkeypatch.setenv("CYBERGUARD_HONEYTOKEN_WEBHOOK_URL", "https://example.test/honeytokens")
    monkeypatch.setenv("CYBERGUARD_HONEYTOKEN_SIGNING_SECRET", "test-secret")
    result = provider_integrations.deploy_honeytokens([{"token": "canary"}], 7)
    expected = hmac.new(b"test-secret", captured["body"].encode(), hashlib.sha256).hexdigest()
    assert result["status"] == "deployed"
    assert captured["url"].endswith("/honeytokens")
    assert captured["headers"]["X-CyberGuard-Signature"] == expected


def test_cve_feed_normalizes_provider_payload(monkeypatch):
    class Response:
        content = b'{"vulnerabilities": [{"cve": "CVE-TEST"}]}'

        def raise_for_status(self):
            return None

        def json(self):
            return {"vulnerabilities": [{"cve": "CVE-TEST"}]}

    monkeypatch.setenv("CYBERGUARD_CVE_FEED_URL", "https://example.test/cves")
    monkeypatch.setattr(provider_integrations.requests, "get", lambda *args, **kwargs: Response())
    result = provider_integrations.sync_cve_feed()
    assert result["status"] == "synced"
    assert result["cves"] == ["CVE-TEST"]


def test_cve_feed_preserves_normalized_severity_details(monkeypatch):
    class Response:
        content = b'{"cves":[{"id":"CVE-2026-1000","severity":"critical"}]}'

        def raise_for_status(self):
            return None

        def json(self):
            return {"cves": [{"id": "CVE-2026-1000", "severity": "critical"}]}

    monkeypatch.setenv("CYBERGUARD_CVE_FEED_URL", "https://example.test/cves")
    monkeypatch.setattr(provider_integrations.requests, "get", lambda *args, **kwargs: Response())

    result = provider_integrations.sync_cve_feed()

    assert result["cves"] == ["CVE-2026-1000"]
    assert result["items"] == [{"id": "CVE-2026-1000", "severity": "critical"}]


def test_servicenow_ticket_request_contract(monkeypatch):
    monkeypatch.delenv("CYBERGUARD_JIRA_URL", raising=False)
    monkeypatch.setenv("CYBERGUARD_SERVICENOW_URL", "https://snow.example.org")
    monkeypatch.setenv("CYBERGUARD_SERVICENOW_TOKEN", "snow-token")
    captured = {}

    class Response:
        content = b'{"result":{"number":"INC001"}}'

        def raise_for_status(self):
            return None

        def json(self):
            return {"result": {"number": "INC001"}}

    def fake_request(method, url, **kwargs):
        captured.update({"method": method, "url": url, **kwargs})
        return Response()

    monkeypatch.setattr("production_integrations.requests.request", fake_request)
    result = production_integrations.create_ticket({"summary": "Test incident", "description": "Test evidence", "urgency": 1})

    assert result["provider"] == "servicenow"
    assert result["result"]["result"]["number"] == "INC001"
    assert captured["url"] == "https://snow.example.org/api/now/table/incident"
    assert captured["headers"]["Authorization"] == "Bearer snow-token"
    assert captured["json"]["urgency"] == "1"


def test_okta_identity_suspend_encodes_identity_and_uses_ssws(monkeypatch):
    monkeypatch.setenv("CYBERGUARD_OKTA_URL", "https://okta.example.org")
    monkeypatch.setenv("CYBERGUARD_OKTA_TOKEN", "okta-token")
    captured = {}

    class Response:
        content = b""

        def raise_for_status(self):
            return None

    monkeypatch.setattr("production_integrations.requests.request", lambda method, url, **kwargs: (captured.update({"method": method, "url": url, **kwargs}) or Response()))
    result = production_integrations.disable_identity("user/name@example.org")

    assert result["status"] == "suspended"
    assert captured["url"].endswith("/api/v1/users/user%2Fname%40example.org/lifecycle/suspend")
    assert captured["headers"]["Authorization"] == "SSWS okta-token"


def test_graph_identity_disable_and_edr_isolation_request_contract(monkeypatch):
    monkeypatch.delenv("CYBERGUARD_OKTA_URL", raising=False)
    monkeypatch.setenv("CYBERGUARD_GRAPH_TOKEN", "graph-token")
    monkeypatch.setenv("CYBERGUARD_EDR_URL", "https://edr.example.org/api")
    monkeypatch.setenv("CYBERGUARD_EDR_TOKEN", "edr-token")
    captured = []

    class Response:
        content = b'{"status":"accepted"}'

        def raise_for_status(self):
            return None

        def json(self):
            return {"status": "accepted"}

    def fake_request(method, url, **kwargs):
        captured.append({"method": method, "url": url, **kwargs})
        return Response()

    monkeypatch.setattr("production_integrations.requests.request", fake_request)
    identity = production_integrations.disable_identity("user/name@example.org")
    endpoint = production_integrations.isolate_endpoint("device-42")

    assert identity["provider"] == "microsoft_graph"
    assert captured[0]["method"] == "PATCH"
    assert captured[0]["url"].endswith("/users/user%2Fname%40example.org")
    assert captured[0]["json"] == {"accountEnabled": False}
    assert endpoint["status"] == "isolated"
    assert captured[1]["url"] == "https://edr.example.org/api/endpoints/isolate"
    assert captured[1]["json"]["endpoint_id"] == "device-42"


def test_tenant_immunity_publish_pseudonymizes_and_filters_payload(monkeypatch):
    captured = {}

    class Response:
        content = b'{"accepted":true}'

        def raise_for_status(self):
            return None

        def json(self):
            return {"accepted": True}

    monkeypatch.setenv("CYBERGUARD_TENANT_IMMUNITY_URL", "https://exchange.example.test/signatures")
    monkeypatch.setenv("CYBERGUARD_TENANT_IMMUNITY_SECRET", "exchange-secret")
    monkeypatch.setattr(provider_integrations.requests, "post", lambda url, **kwargs: (captured.update({"url": url, **kwargs}) or Response()))

    result = provider_integrations.publish_tenant_signatures(
        [{"signature": "a" * 64, "category": "phishing", "source_tenant": "analyst@example.org"}],
        "tenant-private-id",
    )

    payload = json.loads(captured["data"])
    expected_tenant = hmac.new(b"exchange-secret", b"tenant-private-id", hashlib.sha256).hexdigest()
    assert result["status"] == "published"
    assert payload["tenant_id"] == expected_tenant
    assert payload["signatures"] == [{"signature": "a" * 64}]
    assert "tenant-private-id" not in captured["data"]
    assert "analyst@example.org" not in captured["data"]
