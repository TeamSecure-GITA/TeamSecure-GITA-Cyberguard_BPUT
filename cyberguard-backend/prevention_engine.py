from __future__ import annotations

import hashlib
from typing import Any


def _normalize_score(value: Any, minimum: int = 0, maximum: int = 100) -> int:
    try:
        score = int(value)
    except (TypeError, ValueError):
        return minimum
    return max(minimum, min(maximum, score))


def risk_aware_prevention_decision(payload: dict[str, Any] | None, user_context: dict[str, Any] | None = None) -> dict[str, Any]:
    data = payload or {}
    score = _normalize_score(data.get("risk_score", 0))
    category = str(data.get("category") or "unknown")
    criticality = str(data.get("asset_criticality") or "medium")
    team = str((user_context or {}).get("team") or "general")
    role = str((user_context or {}).get("role") or "analyst")
    suspicious = "http" in str(data.get("payload") or "").lower() or "verify" in str(data.get("payload") or "").lower() or "urgent" in str(data.get("payload") or "").lower()

    weighted = score
    if criticality.lower() == "critical":
        weighted += 12
    if team.lower() in {"finance", "security", "admin"}:
        weighted += 10
    if role.lower() in {"admin", "head_admin", "lead"}:
        weighted += 8
    if suspicious:
        weighted += 10

    weighted = max(0, min(100, weighted))

    if weighted >= 90:
        action = "block"
        decision = "block"
    elif weighted >= 75:
        action = "isolate"
        decision = "isolate"
    elif weighted >= 60:
        action = "require_mfa"
        decision = "warn"
    else:
        action = "allow"
        decision = "allow"

    recommended = {
        "block": "Quarantine the sender, block the domain, and isolate the targeted endpoint.",
        "isolate": "Isolate the affected host and require a fresh identity verification before access resumes.",
        "require_mfa": "Trigger step-up authentication and review the user session before continuing.",
        "allow": "Monitor the event and keep the user on normal workflow with light alerting.",
    }.get(action, "Review the event and gather more evidence before action.")

    return {
        "score": weighted,
        "action": action,
        "decision": decision,
        "category": category,
        "reason": "Risk score, business context, and suspicious content all indicate preventive action.",
        "confidence": min(99, max(55, weighted)),
        "recommended_response": recommended,
    }


def campaign_aware_prevention(incidents: list[dict[str, Any]] | None) -> dict[str, Any]:
    rows = incidents or []
    if not rows:
        return {
            "campaign_id": "CMP-EMPTY",
            "affected_users": [],
            "matched_signals": [],
            "global_block_actions": [],
            "watch_status": "monitoring",
        }

    payloads = [str(item.get("payload") or "").lower() for item in rows]
    common = sorted({chunk for chunk in payloads if "secure-login" in chunk or "verify" in chunk or "urgent" in chunk})
    campaign_id = "CMP-" + hashlib.sha256("|".join(common).encode()).hexdigest()[:8].upper()
    affected_users = [str(item.get("user") or item.get("username") or "unknown") for item in rows if item.get("user") or item.get("username")]
    block_domains = []
    for item in rows:
        payload = str(item.get("payload") or "")
        if "https://" in payload:
            domain = payload.split("https://", 1)[1].split("/", 1)[0]
            block_domains.append(domain)

    watch_status = "blocking" if len(rows) >= 2 else "monitoring"
    return {
        "campaign_id": campaign_id,
        "affected_users": affected_users,
        "matched_signals": common,
        "global_block_actions": sorted(set(block_domains)),
        "watch_status": watch_status,
    }


def identity_trust_evaluation(login_context: dict[str, Any] | None) -> dict[str, Any]:
    context = login_context or {}
    device = str(context.get("device") or "known-device")
    country = str(context.get("country") or "US")
    login_count = int(context.get("login_count") or 0)
    source_ip = str(context.get("source_ip") or "")
    score = 80

    if device.lower() in {"new-device", "unknown-device"}:
        score -= 18
    if country.upper() not in {"US", "IN", "GB", "EU"}:
        score -= 12
    if login_count >= 3:
        score -= 10
    if source_ip.startswith("203.") or source_ip.startswith("198."):
        score -= 10

    score = max(0, min(100, score))
    if score >= 75:
        status = "trusted"
        required_action = "allow_session"
    elif score >= 50:
        status = "review"
        required_action = "require_mfa"
    else:
        status = "blocked"
        required_action = "block_session"

    return {"trust_score": score, "status": status, "required_action": required_action}


def insider_threat_risk(user_activity: dict[str, Any] | None) -> dict[str, Any]:
    activity = user_activity or {}
    downloads = int(activity.get("downloads") or 0)
    off_hours = bool(activity.get("off_hours"))
    privilege_change = bool(activity.get("privilege_change"))
    sensitive_access = int(activity.get("sensitive_access") or 0)

    score = downloads * 4 + sensitive_access * 6
    if off_hours:
        score += 18
    if privilege_change:
        score += 20

    score = max(0, min(100, score))
    if score >= 80:
        preventive_action = "freeze_access_and_request_approval"
    elif score >= 60:
        preventive_action = "require_manager_approval"
    else:
        preventive_action = "monitor"

    return {
        "risk_score": score,
        "flags": {
            "off_hours": off_hours,
            "privilege_change": privilege_change,
            "suspicious_downloads": downloads > 5,
            "sensitive_access": sensitive_access,
        },
        "preventive_action": preventive_action,
    }


def deception_trigger_check(decoy_events: list[dict[str, Any]] | None) -> dict[str, Any]:
    events = decoy_events or []
    if not events:
        return {"trigger_status": "idle", "host": "none", "user": "none", "containment_action": "monitor"}

    event = events[0]
    return {
        "trigger_status": "triggered",
        "host": event.get("host") or "unknown-host",
        "user": event.get("user") or "unknown-user",
        "containment_action": "isolate_host_and_revoke_session",
    }


def containment_action_plan(risk_event: dict[str, Any] | None) -> dict[str, Any]:
    event = risk_event or {}
    risk_score = _normalize_score(event.get("risk_score", 0))
    source_ip = str(event.get("source_ip") or "unknown")
    category = str(event.get("category") or "unknown")
    actions: list[str] = []
    if risk_score >= 85:
        actions.extend(["isolate_host", "revoke_session", "block_ip"])
    elif risk_score >= 60:
        actions.extend(["require_mfa", "review_session"])
    else:
        actions.append("monitor")

    if category.lower() in {"email", "url"}:
        actions.append("quarantine_message")

    return {
        "risk_score": risk_score,
        "source_ip": source_ip,
        "category": category,
        "actions": sorted(set(actions)),
        "priority": "high" if risk_score >= 85 else "medium" if risk_score >= 60 else "low",
    }


def cross_channel_prevention_score(event_bundle: dict[str, Any] | None) -> dict[str, Any]:
    bundle = event_bundle or {}
    email_risk = _normalize_score(bundle.get("email_risk", 0))
    url_risk = _normalize_score(bundle.get("url_risk", 0))
    device_risk = _normalize_score(bundle.get("device_risk", 0))
    login_risk = _normalize_score(bundle.get("login_risk", 0))
    campaign_similarity = float(bundle.get("campaign_similarity", 0.0))
    final_score = int(round((email_risk * 0.3) + (url_risk * 0.2) + (device_risk * 0.2) + (login_risk * 0.2) + (campaign_similarity * 100 * 0.1)))
    final_score = max(0, min(100, final_score))
    if final_score >= 80:
        action = "block_and_isolate"
    elif final_score >= 65:
        action = "require_mfa_and_review"
    else:
        action = "monitor"

    return {
        "final_score": final_score,
        "action": action,
        "signals": {
            "email_risk": email_risk,
            "url_risk": url_risk,
            "device_risk": device_risk,
            "login_risk": login_risk,
            "campaign_similarity": campaign_similarity,
        },
    }


def policy_aware_prevention(user: dict[str, Any] | None, asset: dict[str, Any] | None, event: dict[str, Any] | None) -> dict[str, Any]:
    user_profile = user or {}
    asset_profile = asset or {}
    event_profile = event or {}
    role = str(user_profile.get("role") or "analyst")
    criticality = str(asset_profile.get("criticality") or "medium")
    category = str(event_profile.get("category") or "unknown")

    if role.lower() in {"admin", "head_admin", "lead"}:
        enforcement_level = "strict"
    elif criticality.lower() in {"critical", "high"}:
        enforcement_level = "strict"
    elif category.lower() in {"email", "url"}:
        enforcement_level = "standard"
    else:
        enforcement_level = "monitor"

    return {
        "role": role,
        "asset_criticality": criticality,
        "event_category": category,
        "enforcement_level": enforcement_level,
    }
