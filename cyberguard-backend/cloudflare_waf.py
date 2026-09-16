from __future__ import annotations

import os
from typing import Any

import requests


CLOUDFLARE_API = "https://api.cloudflare.com/client/v4"


def configuration() -> dict[str, Any]:
    return {
        "configured": bool(os.getenv("CLOUDFLARE_API_TOKEN") and os.getenv("CLOUDFLARE_ZONE_ID")),
        "zone_id": os.getenv("CLOUDFLARE_ZONE_ID", ""),
        "email": os.getenv("CYBERGUARD_SECURITY_OWNER_EMAIL", "teamsecure.project@gmail.com"),
    }


def block_ip(ip_address: str, reason: str) -> dict[str, Any]:
    token = os.getenv("CLOUDFLARE_API_TOKEN")
    zone_id = os.getenv("CLOUDFLARE_ZONE_ID")
    if not token or not zone_id:
        return {"status": "not_configured", "configured": False, "ip_address": ip_address, "message": "Set CLOUDFLARE_API_TOKEN and CLOUDFLARE_ZONE_ID to enable Cloudflare blocking."}
    response = requests.post(
        f"{CLOUDFLARE_API}/zones/{zone_id}/firewall/access_rules/rules",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json={"mode": "block", "configuration": {"target": "ip", "value": ip_address}, "notes": reason[:500]},
        timeout=10,
    )
    response.raise_for_status()
    payload = response.json()
    if not payload.get("success"):
        raise RuntimeError(payload.get("errors") or "Cloudflare rejected the IP block")
    return {"status": "blocked", "configured": True, "ip_address": ip_address, "provider": "cloudflare-waf", "result": payload.get("result")}
