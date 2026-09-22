from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any

import requests


def _post_json(url: str, payload: dict[str, Any], token: str | None = None, secret: str | None = None) -> dict[str, Any]:
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if secret:
        headers["X-CyberGuard-Signature"] = hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()
    response = requests.post(url, data=body, headers=headers, timeout=10)
    response.raise_for_status()
    return response.json() if response.content else {"status": "accepted"}


def honeytoken_provider_status() -> dict[str, Any]:
    return {"configured": bool(os.getenv("CYBERGUARD_HONEYTOKEN_WEBHOOK_URL")), "provider": os.getenv("CYBERGUARD_HONEYTOKEN_PROVIDER", "generic-webhook")}


def deploy_honeytokens(tokens: list[dict[str, Any]], incident_id: Any) -> dict[str, Any]:
    url = os.getenv("CYBERGUARD_HONEYTOKEN_WEBHOOK_URL")
    if not url:
        return {"status": "not_configured", "configured": False, "message": "Set CYBERGUARD_HONEYTOKEN_WEBHOOK_URL to enable provider deployment."}
    result = _post_json(url, {"incident_id": incident_id, "tokens": tokens, "mode": "staged-canary"}, os.getenv("CYBERGUARD_HONEYTOKEN_API_TOKEN"), os.getenv("CYBERGUARD_HONEYTOKEN_SIGNING_SECRET"))
    return {"status": "deployed", "configured": True, "provider": os.getenv("CYBERGUARD_HONEYTOKEN_PROVIDER", "generic-webhook"), "result": result}


def sync_cve_feed() -> dict[str, Any]:
    url = os.getenv("CYBERGUARD_CVE_FEED_URL")
    if not url:
        return {"status": "not_configured", "configured": False, "cves": [], "message": "Set CYBERGUARD_CVE_FEED_URL to enable CVE synchronization."}
    headers = {"Authorization": f"Bearer {os.getenv('CYBERGUARD_CVE_FEED_TOKEN')}"} if os.getenv("CYBERGUARD_CVE_FEED_TOKEN") else {}
    response = requests.get(url, headers=headers, timeout=15)
    response.raise_for_status()
    payload = response.json()
    cves = payload.get("cves", payload.get("vulnerabilities", payload if isinstance(payload, list) else []))
    if isinstance(cves, list):
        cves = [item.get("cve", item) if isinstance(item, dict) else item for item in cves]
    return {"status": "synced", "configured": True, "source": url, "cves": cves[:500], "count": len(cves)}


def tenant_exchange_status() -> dict[str, Any]:
    return {"configured": bool(os.getenv("CYBERGUARD_TENANT_IMMUNITY_URL") and os.getenv("CYBERGUARD_TENANT_IMMUNITY_SECRET")), "provider": "signed-tenant-exchange"}


def publish_tenant_signatures(signatures: list[dict[str, Any]], tenant_id: str) -> dict[str, Any]:
    url = os.getenv("CYBERGUARD_TENANT_IMMUNITY_URL")
    secret = os.getenv("CYBERGUARD_TENANT_IMMUNITY_SECRET")
    if not url or not secret:
        return {"status": "not_configured", "configured": False, "published": 0, "message": "Set CYBERGUARD_TENANT_IMMUNITY_URL and CYBERGUARD_TENANT_IMMUNITY_SECRET to enable signed sharing."}
    result = _post_json(url, {"tenant_id": tenant_id, "signatures": signatures}, secret=secret)
    return {"status": "published", "configured": True, "published": len(signatures), "result": result}


def integration_status() -> dict[str, Any]:
    return {
        "honeytokens": honeytoken_provider_status(),
        "cve_feed": {"configured": bool(os.getenv("CYBERGUARD_CVE_FEED_URL")), "source": os.getenv("CYBERGUARD_CVE_FEED_URL", "")},
        "tenant_immunity": tenant_exchange_status(),
        "response_webhook": {"configured": bool(os.getenv("CYBERGUARD_RESPONSE_WEBHOOK_URL"))},
        "alert_webhook": {"configured": bool(os.getenv("CYBERGUARD_ALERT_WEBHOOK_URL"))},
        "urlhaus": {"configured": bool(os.getenv("CYBERGUARD_URLHAUS_AUTH_KEY")), "source": "https://urlhaus.abuse.ch"},
        "abuseipdb": {"configured": bool(os.getenv("CYBERGUARD_ABUSEIPDB_KEY")), "source": "https://www.abuseipdb.com"},
    }
