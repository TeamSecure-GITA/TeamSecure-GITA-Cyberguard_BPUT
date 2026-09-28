from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
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
    cves = payload.get("cves", payload.get("vulnerabilities", [])) if isinstance(payload, dict) else payload if isinstance(payload, list) else []
    identifiers = []
    items = []
    for item in cves if isinstance(cves, list) else []:
        nested = item.get("cve") if isinstance(item, dict) else None
        detail = nested if isinstance(nested, dict) else item if isinstance(item, dict) else {}
        identifier = detail.get("id") or detail.get("cve_id") or nested if isinstance(nested, str) else detail.get("id") or detail.get("cve_id")
        if not identifier and isinstance(item, str):
            identifier = item
        if not identifier:
            continue
        metrics = detail.get("metrics") if isinstance(detail.get("metrics"), dict) else {}
        cvss = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or []
        cvss_severity = cvss[0].get("cvssData", {}).get("baseSeverity") if cvss and isinstance(cvss[0], dict) else None
        severity = str((item.get("severity") if isinstance(item, dict) else None) or detail.get("severity") or cvss_severity or "unknown").lower()
        identifier = str(identifier)
        identifiers.append(identifier)
        items.append({"id": identifier, "severity": severity})
    return {"status": "synced", "configured": True, "source": url, "cves": identifiers[:500], "items": items[:500], "count": len(items)}


def tenant_exchange_status() -> dict[str, Any]:
    configured = all(os.getenv(name, "").strip() for name in (
        "CYBERGUARD_TENANT_IMMUNITY_URL",
        "CYBERGUARD_TENANT_IMMUNITY_SECRET",
        "CYBERGUARD_TENANT_ID",
    ))
    return {"configured": configured, "provider": "signed-tenant-exchange"}


def publish_tenant_signatures(signatures: list[dict[str, Any]], tenant_id: str) -> dict[str, Any]:
    url = os.getenv("CYBERGUARD_TENANT_IMMUNITY_URL")
    secret = os.getenv("CYBERGUARD_TENANT_IMMUNITY_SECRET")
    if not url or not secret:
        return {"status": "not_configured", "configured": False, "published": 0, "message": "Set CYBERGUARD_TENANT_IMMUNITY_URL, CYBERGUARD_TENANT_IMMUNITY_SECRET, and CYBERGUARD_TENANT_ID to enable signed sharing."}
    normalized_signatures = []
    seen = set()
    for item in signatures:
        signature = item.get("signature") if isinstance(item, dict) else None
        if not isinstance(signature, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", signature):
            continue
        signature = signature.lower()
        if signature not in seen:
            seen.add(signature)
            normalized_signatures.append({"signature": signature})
    if not normalized_signatures:
        return {"status": "no_signatures", "configured": True, "published": 0}
    tenant_id = str(tenant_id or "").strip()
    if not tenant_id:
        return {"status": "missing_tenant_id", "configured": True, "published": 0}
    opaque_tenant_id = hmac.new(secret.encode(), tenant_id.encode(), hashlib.sha256).hexdigest()
    result = _post_json(url, {"tenant_id": opaque_tenant_id, "signatures": normalized_signatures}, secret=secret)
    return {"status": "published", "configured": True, "published": len(normalized_signatures), "result": result}


def integration_status() -> dict[str, Any]:
    return {
        "honeytokens": honeytoken_provider_status(),
        "cve_feed": {"configured": bool(os.getenv("CYBERGUARD_CVE_FEED_URL")), "source": os.getenv("CYBERGUARD_CVE_FEED_URL", "")},
        "tenant_immunity": tenant_exchange_status(),
        "response_webhook": {"configured": bool(os.getenv("CYBERGUARD_RESPONSE_WEBHOOK_URL"))},
        "alert_webhook": {"configured": bool(os.getenv("CYBERGUARD_ALERT_WEBHOOK_URL"))},
    }


def provider_readiness() -> dict[str, Any]:
    checks = integration_status()
    placeholder_markers = ("your-", "your_", "example.", "example/", "change-me")
    configured_checks = []
    for name, status in checks.items():
        if not status.get("configured"):
            continue
        values = " ".join(str(value).lower() for key, value in status.items() if key != "configured")
        if any(marker in values for marker in placeholder_markers):
            continue
        configured_checks.append(name)
    required_values = [
        os.getenv("CYBERGUARD_HONEYTOKEN_WEBHOOK_URL", ""),
        os.getenv("CYBERGUARD_CVE_FEED_URL", ""),
        os.getenv("CYBERGUARD_TENANT_IMMUNITY_URL", ""),
        os.getenv("CYBERGUARD_TENANT_IMMUNITY_SECRET", ""),
        os.getenv("CYBERGUARD_TENANT_ID", ""),
        os.getenv("CYBERGUARD_RESPONSE_WEBHOOK_URL", ""),
        os.getenv("CYBERGUARD_ALERT_WEBHOOK_URL", ""),
    ]
    ready = bool(checks) and len(configured_checks) == len(checks) and all(value and not any(marker in value.lower() for marker in placeholder_markers) for value in required_values)
    return {
        "ready": ready,
        "checks": checks,
        "configured_count": len(configured_checks),
        "total_checks": len(checks),
    }
