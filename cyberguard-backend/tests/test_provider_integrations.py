import hashlib
import hmac
import json

import provider_integrations


def test_provider_readiness_does_not_expose_secret_values(monkeypatch):
    monkeypatch.setenv("CYBERGUARD_RESPONSE_WEBHOOK_URL", "https://example.test/response")
    monkeypatch.setenv("CYBERGUARD_ALERT_WEBHOOK_URL", "https://example.test/alert")
    result = provider_integrations.provider_readiness()
    assert result["checks"]["response_webhook"]["configured"] is True
    assert result["ready"] is False
    assert "https://example.test/response" not in json.dumps(result)


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
