from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any


PROVIDER_LINKS = {
    "google": {
        "password": "https://myaccount.google.com/signinoptions/password",
        "mfa": "https://myaccount.google.com/security",
        "recovery": "https://accounts.google.com/signin/recovery",
        "apps": "https://myaccount.google.com/permissions",
    },
    "microsoft": {
        "password": "https://account.live.com/password/change",
        "mfa": "https://mysignins.microsoft.com/security-info",
        "recovery": "https://account.live.com/acsr",
        "apps": "https://myaccount.microsoft.com/organizations",
    },
    "generic": {
        "password": "https://support.google.com/accounts/answer/41078",
        "mfa": "https://support.google.com/accounts/answer/185839",
        "recovery": "https://accounts.google.com/signin/recovery",
        "apps": "https://myaccount.google.com/permissions",
    },
}


def _score_signal(category: str, confidence: float) -> float:
    weights = {"persistence": 0.9, "presence": 0.7, "exposure": 0.4, "history": 0.2}
    return weights.get(category, 0.2) * max(0.0, min(1.0, float(confidence)))


def _level(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def scan_account(signals: dict[str, Any] | None = None) -> dict[str, Any]:
    data = signals or {}
    findings: list[dict[str, Any]] = []
    signal_map = [
        ("unknown_session", "presence", data.get("unknown_session", True), 0.9, "Unknown device or active session detected"),
        ("suspicious_login", "presence", data.get("suspicious_login", True), 0.85, "Suspicious login or impossible travel detected"),
        ("new_oauth_app", "persistence", data.get("new_oauth_app", True), 0.86, "New connected application has account access"),
        ("forwarding_rule", "persistence", data.get("forwarding_rule", True), 0.95, "External mail forwarding or hiding rule detected"),
        ("mfa_disabled", "exposure", not data.get("mfa_enabled", False), 0.8, "Multi-factor authentication is not enabled"),
        ("recovery_changed", "persistence", data.get("recovery_changed", False), 0.92, "Recovery information changed recently"),
        ("breach_history", "history", data.get("breach_history", False), 0.75, "Account identifier appears in breach intelligence"),
    ]
    for identifier, category, active, confidence, description in signal_map:
        if active:
            findings.append({"id": identifier, "category": category, "confidence": confidence, "weight": round(_score_signal(category, confidence), 3), "description": description})
    remaining = 1.0
    for finding in findings:
        remaining *= 1.0 - finding["weight"]
    score = round((1.0 - remaining) * 100)
    findings.sort(key=lambda item: item["weight"], reverse=True)
    provider = str(data.get("provider") or "generic").lower()
    return {
        "scan_id": "scan_" + secrets.token_urlsafe(8),
        "provider": provider if provider in PROVIDER_LINKS else "generic",
        "score": score,
        "risk_level": _level(score),
        "findings": findings,
        "top_contributors": findings[:3],
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "data_minimization": "security metadata only; no password or message body collected",
    }


def rescue_plan(scan: dict[str, Any]) -> dict[str, Any]:
    links = PROVIDER_LINKS.get(scan.get("provider", "generic"), PROVIDER_LINKS["generic"])
    finding_ids = {finding["id"] for finding in scan.get("findings", [])}
    steps = [
        {"id": "revoke_unknown_sessions", "title": "Revoke unknown sessions", "kind": "containment", "confirmation": "explicit", "supported": False, "status": "manual_required", "fallback": "Open the provider security page and sign out unknown devices."},
        {"id": "remove_oauth_app", "title": "Review suspicious connected apps", "kind": "containment", "confirmation": "explicit", "supported": False, "status": "manual_required", "fallback": "Review and remove unfamiliar applications from the provider permissions page.", "link": links["apps"]},
        {"id": "remove_forwarding", "title": "Review forwarding and mail rules", "kind": "containment", "confirmation": "explicit", "supported": False, "status": "manual_required", "fallback": "Open mail settings and remove unknown forwarding addresses and rules."},
        {"id": "reset_password", "title": "Reset password through the provider", "kind": "recovery", "confirmation": "explicit", "supported": False, "status": "manual_required", "fallback": "CyberGuard never sees your password. Use the official provider page.", "link": links["password"]},
        {"id": "enable_mfa", "title": "Enable multi-factor authentication", "kind": "recovery", "confirmation": "explicit", "supported": False, "status": "manual_required", "fallback": "Use a security key or authenticator app from the provider security page.", "link": links["mfa"]},
        {"id": "check_recovery", "title": "Verify recovery email and phone", "kind": "hardening", "confirmation": "explicit", "supported": False, "status": "manual_required", "fallback": "Confirm recovery contacts belong to you and remove unknown values.", "link": links["recovery"]},
        {"id": "rescan_account", "title": "Re-scan account", "kind": "verification", "confirmation": "none", "supported": True, "status": "ready", "fallback": "Run another metadata-only scan after provider changes."},
        {"id": "guardian_mode", "title": "Keep protecting my account", "kind": "monitoring", "confirmation": "explicit", "supported": True, "status": "ready", "fallback": "Enable Guardian Mode to monitor future security changes."},
    ]
    if "unknown_session" not in finding_ids:
        steps[0]["status"] = "not_needed"
    if "new_oauth_app" not in finding_ids:
        steps[1]["status"] = "not_needed"
    if "forwarding_rule" not in finding_ids:
        steps[2]["status"] = "not_needed"
    return {"plan_id": "plan_" + secrets.token_urlsafe(8), "scan_id": scan.get("scan_id"), "risk_before": scan.get("score", 0), "steps": steps, "explicit_confirmation_required": True, "honesty_note": "Account Rescue aims for maximum containment and recovery; it cannot guarantee recovery if provider recovery controls or the device are compromised."}


def execute_step(plan: dict[str, Any], step_id: str, confirmed: bool = False) -> dict[str, Any]:
    step = next((item for item in plan.get("steps", []) if item["id"] == step_id), None)
    if not step:
        raise ValueError("Unknown rescue step")
    if step["confirmation"] == "explicit" and not confirmed:
        return {"status": "confirmation_required", "step": step, "message": "Explicit confirmation is required before this high-impact action."}
    if not step["supported"]:
        return {"status": "manual_required", "step": step, "verified": False, "message": step["fallback"]}
    return {"status": "completed", "step": step, "verified": True, "completed_at": datetime.now(timezone.utc).isoformat()}


def evidence_snapshot(scan: dict[str, Any], account_label: str = "connected-account") -> dict[str, Any]:
    return {"evidence_id": "ev_" + secrets.token_urlsafe(8), "account_label": account_label, "scan": scan, "created_at": datetime.now(timezone.utc).isoformat(), "expires_at": (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()}


def lockdown_plan(scan: dict[str, Any]) -> dict[str, Any]:
    plan = rescue_plan(scan)
    return {"lockdown_id": "lock_" + secrets.token_urlsafe(8), "risk_before": scan.get("score", 0), "steps": [step for step in plan["steps"] if step["kind"] in {"containment", "recovery", "hardening"}], "requires_step_up": True, "requires_confirmation": True, "status": "awaiting_confirmation"}


def guardian_watch(scan: dict[str, Any], enabled: bool = True) -> dict[str, Any]:
    return {"watch_id": "watch_" + secrets.token_urlsafe(8), "enabled": enabled, "baseline_scan_id": scan.get("scan_id"), "watch_window_hours": 24, "signals": ["new_login", "new_device", "recovery_change", "oauth_change", "forwarding_change", "mfa_change"], "status": "active" if enabled else "disabled"}


def locked_out_recovery(provider: str = "generic") -> dict[str, Any]:
    links = PROVIDER_LINKS.get(provider, PROVIDER_LINKS["generic"])
    return {"mode": "locked_out", "provider": provider, "official_recovery_url": links["recovery"], "steps": ["Use a known device and location", "Use the provider's official recovery form", "Secure banking and other accounts that use this email", "Warn contacts about suspicious messages", "Report financial loss to the bank and cybercrime authorities"], "password_required_by_cyberguard": False}


def blast_radius(provider: str = "generic") -> dict[str, Any]:
    return {"provider": provider, "assets": [{"name": "Bank / UPI", "risk": "high", "reason": "email may be a password-reset channel"}, {"name": "Cloud storage", "risk": "high", "reason": "account recovery and files may be reachable"}, {"name": "Social accounts", "risk": "medium", "reason": "password reset dependency"}, {"name": "Shopping accounts", "risk": "medium", "reason": "saved payment metadata"}], "metadata_only": True}


def offline_rescue_card(provider: str = "generic") -> dict[str, Any]:
    links = PROVIDER_LINKS.get(provider, PROVIDER_LINKS["generic"])
    return {"card_id": "card_" + secrets.token_urlsafe(8), "provider": provider, "recovery_url": links["recovery"], "security_url": links["mfa"], "checklist": ["Keep backup codes offline", "Use a clean device", "Confirm recovery contacts", "Contact your bank if money is at risk"], "generated_at": datetime.now(timezone.utc).isoformat()}


def provider_capabilities(provider: str = "generic") -> dict[str, Any]:
    normalized = provider if provider in {"google", "microsoft"} else "generic"
    automated = {"sessions": normalized == "microsoft", "oauth": False, "forwarding": normalized in {"google", "microsoft"}, "mfa": False, "password": False}
    return {"provider": normalized, "scope_policy": "read-only scan first; write scope only after explicit confirmation", "capabilities": {key: {"supported": value, "fallback": "official provider security page" if not value else "authorized provider API"} for key, value in automated.items()}, "passwords_collected": False}


def rescue_simulation(scan: dict[str, Any]) -> dict[str, Any]:
    plan = rescue_plan(scan)
    reductions = {"revoke_unknown_sessions": 28, "remove_oauth_app": 20, "remove_forwarding": 24, "reset_password": 12, "enable_mfa": 18, "check_recovery": 8}
    score = int(scan.get("score", 0))
    steps = []
    for step in plan["steps"]:
        reduction = reductions.get(step["id"], 0)
        score = max(0, score - reduction)
        steps.append({"id": step["id"], "title": step["title"], "projected_score": score, "status": "simulated_verified"})
    return {"mode": "synthetic_only", "risk_before": scan.get("score", 0), "risk_after": score, "steps": steps, "side_effects": False, "message": "Simulation changed no provider state."}


def rescue_report(scan: dict[str, Any], plan: dict[str, Any], actions: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {"report_id": "report_" + secrets.token_urlsafe(8), "generated_at": datetime.now(timezone.utc).isoformat(), "scan": scan, "plan": plan, "actions": actions or [], "limitations": ["Provider actions require authorized APIs or official manual flows", "Recovery cannot be guaranteed if recovery controls or the device are compromised"], "export_format": "json; render to PDF in deployment report service"}


def rollback_record(action_id: str, snapshot: dict[str, Any]) -> dict[str, Any]:
    return {"action_id": action_id, "undo_available": True, "can_undo_until": (datetime.now(timezone.utc) + timedelta(days=7)).isoformat(), "snapshot": snapshot, "status": "ready_for_provider_restore"}


def consent_record(provider: str, scopes: list[str], action: str, confirmed: bool = False) -> dict[str, Any]:
    return {"consent_id": "consent_" + secrets.token_urlsafe(8), "provider": provider, "action": action, "scopes": scopes, "confirmed": confirmed, "least_privilege": True, "passwords_collected": False, "status": "confirmed" if confirmed else "awaiting_confirmation"}


def contact_warning_draft(account_label: str, contacts: list[str] | None = None) -> dict[str, Any]:
    safe_contacts = [str(contact) for contact in (contacts or [])][:25]
    return {"broadcast_id": "broadcast_" + secrets.token_urlsafe(8), "account_label": account_label, "recipients": safe_contacts, "recipient_cap": 25, "requires_explicit_send": True, "message": "My account may have been compromised. Please ignore recent messages asking for money, passwords, or links until I confirm it is secure.", "status": "draft"}


def guardian_contact(contact: str, enabled: bool = True) -> dict[str, Any]:
    return {"guardian_contact_id": "guardian_" + secrets.token_urlsafe(8), "contact": contact, "enabled": enabled, "critical_only": True, "status": "active" if enabled else "disabled"}


def fleet_summary(accounts: list[dict[str, Any]] | None) -> dict[str, Any]:
    rows = accounts or []
    return {"accounts": [{"label": row.get("label", "account"), "risk": int(row.get("risk", 0)), "consent": bool(row.get("consent", False)), "rescue_available": int(row.get("risk", 0)) >= 50} for row in rows], "requires_per_account_consent": True, "total": len(rows)}
