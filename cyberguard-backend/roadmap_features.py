"""Deterministic, simulation-safe implementations for the remaining roadmap features."""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from typing import Any


JURISDICTION_RULES = {
    "IN": {"jurisdiction": "India", "regulations": ["DPDP Act", "CERT-In 6-hour reporting"]},
    "US": {"jurisdiction": "United States", "regulations": ["State breach notification review", "SEC cyber disclosure review"]},
    "EU": {"jurisdiction": "European Union", "regulations": ["GDPR 72-hour notification"]},
    "GB": {"jurisdiction": "United Kingdom", "regulations": ["UK GDPR notification review"]},
}


def _risk(incident: dict[str, Any]) -> int:
    return int(incident.get("risk_score") or incident.get("riskScore") or 0)


def breach_economics(incident: dict[str, Any], delay_hours: int = 4) -> dict[str, Any]:
    risk = max(0, min(99, _risk(incident)))
    affected_assets = max(1, int(incident.get("affected_assets") or incident.get("asset_count") or 1))
    records = max(100, int(incident.get("records_exposed") or risk * 120))
    direct_exposure = round(records * (1.25 + risk / 100) + affected_assets * 850, 2)
    delay_cost = round(max(0, delay_hours) * (direct_exposure * 0.018 + risk * 35), 2)
    return {
        "risk_score": risk,
        "affected_assets": affected_assets,
        "records_at_risk": records,
        "direct_exposure": direct_exposure,
        "delay_hours": max(0, delay_hours),
        "delay_cost": delay_cost,
        "total_exposure": round(direct_exposure + delay_cost, 2),
        "currency": "USD",
        "confidence": max(45, min(96, 55 + risk // 3)),
        "mode": "simulation; no financial transaction was executed",
    }


def seed_honeytokens(incident: dict[str, Any], count: int = 3) -> dict[str, Any]:
    seed = hashlib.sha256(f"{incident.get('id', '')}:{incident.get('category', '')}:{_risk(incident)}".encode()).hexdigest()
    token_count = max(1, min(10, count))
    tokens = []
    for index in range(token_count):
        token_seed = seed[index * 8 : index * 8 + 16]
        tokens.append({
            "token_id": f"HT-{token_seed[:8].upper()}",
            "kind": ["credential", "document", "api-key"][index % 3],
            "canary_value": f"cg-canary-{token_seed}",
            "trigger": "alert and isolate on access",
            "status": "staged",
        })
    return {"incident_id": incident.get("database_id") or incident.get("id"), "tokens": tokens, "mode": "simulation; no real credential or file was planted"}


def analyst_bias_report(incidents: list[dict[str, Any]], audit_events: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    by_analyst: dict[str, list[dict[str, Any]]] = {}
    for incident in incidents:
        analyst = incident.get("assigned_to") or "unassigned"
        by_analyst.setdefault(analyst, []).append(incident)
    analysts = []
    for name, rows in by_analyst.items():
        high = [row for row in rows if _risk(row) >= 65]
        closed = [row for row in rows if str(row.get("status", "")).lower() in {"closed", "mitigated"}]
        dismissal_rate = round(sum(_risk(row) < 40 for row in rows) / max(len(rows), 1) * 100)
        analysts.append({"analyst": name, "assigned": len(rows), "high_risk": len(high), "resolved": len(closed), "low_risk_dismissal_rate": dismissal_rate, "review_flag": dismissal_rate >= 70 and high})
    actions = Counter(str(event.get("action", "unknown")) for event in (audit_events or []))
    return {"analysts": analysts, "audit_action_counts": dict(actions), "signals": ["high-risk workload imbalance", "rapid low-risk closure pattern"], "status": "review recommended" if any(item["review_flag"] for item in analysts) else "no strong bias signal"}


def shared_immunity(incidents: list[dict[str, Any]], tenant: str = "default") -> dict[str, Any]:
    signatures = []
    for incident in incidents:
        raw = str(incident.get("fingerprint") or incident.get("campaign_id") or incident.get("category") or "unknown")
        signature = hashlib.sha256(raw.encode()).hexdigest()[:16]
        signatures.append({"signature": signature, "category": incident.get("category", "unknown"), "risk_level": incident.get("risk_level", "unknown"), "source_tenant": tenant})
    unique = {item["signature"]: item for item in signatures}
    return {"shared_signatures": list(unique.values()), "signature_count": len(unique), "privacy": "one-way signatures only; raw tenant payloads are excluded", "status": "ready"}


def attacker_resource_cost(incident: dict[str, Any]) -> dict[str, Any]:
    payload = str(incident.get("payload") or incident.get("explanation") or "").lower()
    signals = {"automation": bool(re.search(r"bot|script|spray|scan|bulk", payload)), "customization": bool(re.search(r"director|registrar|targeted|internal", payload)), "infrastructure": bool(re.search(r"redirect|domain|c2|proxy|shortener", payload))}
    score = min(99, _risk(incident) // 2 + sum(22 for value in signals.values() if value))
    tier = "commodity" if score < 35 else "organized" if score < 70 else "custom campaign"
    return {"resource_score": score, "tier": tier, "estimated_operator_hours": round(1 + score / 18, 1), "signals": signals, "confidence": 72}


def attention_heatmap(events: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    counts = Counter()
    for event in events or []:
        surface = str(event.get("resource") or event.get("surface") or "unknown")
        counts[surface] += 1
    if not counts:
        counts.update({"dashboard": 1, "incidents": 1, "intelligence": 1})
    total = sum(counts.values())
    return {"surfaces": [{"surface": key, "events": value, "share": round(value / total * 100)} for key, value in counts.most_common()], "total_events": total, "status": "observational; no keystrokes or biometric data collected"}


def jurisdiction_route(incident: dict[str, Any]) -> dict[str, Any]:
    metadata = incident.get("metadata") if isinstance(incident.get("metadata"), dict) else {}
    country = str(metadata.get("country") or incident.get("country") or metadata.get("region") or "IN").upper()
    rule = JURISDICTION_RULES.get(country, {"jurisdiction": "Unknown / global review", "regulations": ["Coordinate legal and privacy review"]})
    return {"country": country, **rule, "priority": "urgent" if _risk(incident) >= 85 else "standard", "reason": "derived from incident residency metadata; confirm with legal counsel"}


def cross_modal_consistency(media_results: list[dict[str, Any]]) -> dict[str, Any]:
    usable = [item for item in media_results if item.get("score") is not None]
    if not usable:
        return {"consistency_score": 0, "authenticity_score": 0, "media_count": 0, "status": "insufficient evidence", "results": []}
    scores = [int(item.get("score", 0)) for item in usable]
    average = sum(scores) / len(scores)
    spread = max(scores) - min(scores)
    consistency = max(0, min(99, round(100 - spread * 1.4)))
    authenticity = max(0, min(99, round((100 - average) * 0.65 + consistency * 0.35)))
    return {
        "consistency_score": consistency,
        "authenticity_score": authenticity,
        "media_count": len(usable),
        "status": "cross-modal mismatch" if spread >= 25 else "consistent signal",
        "score_spread": spread,
        "results": usable,
        "method": "normalized anomaly-score comparison across supplied media channels",
    }


def counterfactual_replay(incident: dict[str, Any], actions: list[str], variable: str = "response_delay_hours", value: int = 4) -> dict[str, Any]:
    baseline = _risk(incident)
    action_reduction = min(80, len(actions) * 12)
    delay_penalty = max(0, min(30, int(value))) if variable == "response_delay_hours" else 0
    projected = max(0, min(99, baseline - action_reduction + delay_penalty))
    return {
        "incident_id": incident.get("database_id") or incident.get("id"),
        "baseline_risk": baseline,
        "counterfactual_risk": projected,
        "changed_variable": variable,
        "changed_value": value,
        "actions": actions,
        "risk_delta": projected - baseline,
        "outcome": "improved" if projected < baseline else "degraded" if projected > baseline else "unchanged",
        "method": "deterministic replay model; original incident record was not modified",
    }


def compliance_diff(controls: list[dict[str, Any]], cves: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    cves = cves or []
    gaps = []
    for cve in cves:
        severity = str(cve.get("severity", "medium")).lower()
        if severity in {"critical", "high"}:
            gaps.append({"type": "cve", "id": cve.get("id", "unknown"), "severity": severity, "action": "review affected controls and response evidence"})
    for control in controls:
        if str(control.get("status", "")).lower() not in {"compliant", "passed"}:
            gaps.append({"type": "control", "id": control.get("id", "unknown"), "severity": "review", "action": control.get("evidence", "collect updated evidence")})
    return {"control_count": len(controls), "cve_count": len(cves), "gaps": gaps, "gap_count": len(gaps), "status": "attention required" if gaps else "no gaps detected", "source": "local control inventory and supplied CVE feed"}
