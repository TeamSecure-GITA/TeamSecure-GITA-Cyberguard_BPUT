"""Deterministic, simulation-safe implementations for the remaining roadmap features."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
from collections import Counter, deque
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


def shared_immunity(incidents: list[dict[str, Any]], signing_secret: str | None = None) -> dict[str, Any]:
    signatures = []
    for incident in incidents:
        raw = str(incident.get("fingerprint") or incident.get("campaign_id") or "").strip()
        if not raw:
            assessment = incident.get("assessment") if isinstance(incident.get("assessment"), dict) else {}
            iocs = sorted({
                (str(item.get("type") or "unknown").lower(), str(item.get("indicator") or item.get("value") or "").strip().lower())
                for item in (assessment.get("iocs") or [])
                if isinstance(item, dict) and (item.get("indicator") or item.get("value"))
            })
            techniques = sorted({str(item).strip().upper() for item in (assessment.get("mitre_techniques") or []) if str(item).strip()})
            if not iocs and not techniques:
                continue
            raw = json.dumps({"category": incident.get("category", "unknown"), "iocs": iocs, "techniques": techniques}, sort_keys=True, separators=(",", ":"))
        signature_bytes = raw.encode("utf-8")
        signature = hmac.new(signing_secret.encode("utf-8"), signature_bytes, hashlib.sha256).hexdigest() if signing_secret else hashlib.sha256(signature_bytes).hexdigest()
        signatures.append({"signature": signature})
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
    raw_country = metadata.get("country") or incident.get("country") or metadata.get("region")
    aliases = {
        "INDIA": "IN",
        "UNITED STATES": "US",
        "UNITED STATES OF AMERICA": "US",
        "USA": "US",
        "EUROPEAN UNION": "EU",
        "UNITED KINGDOM": "GB",
        "UK": "GB",
        "GREAT BRITAIN": "GB",
    }
    country_name = str(raw_country or "UNKNOWN").strip().upper()
    country = aliases.get(country_name, country_name)
    rule = JURISDICTION_RULES.get(country, {"jurisdiction": "Unknown / global review", "regulations": ["Coordinate legal and privacy review"]})
    return {"country": country, **rule, "priority": "urgent" if _risk(incident) >= 85 else "standard", "reason": "derived from incident residency metadata; confirm with legal counsel"}


def cross_modal_consistency(media_results: list[dict[str, Any]]) -> dict[str, Any]:
    modalities = {"image", "audio", "video"}
    usable = []
    for item in media_results:
        if not isinstance(item, dict) or str(item.get("method") or "").lower() in {"qr-decoder", "metadata-fallback", "media-fallback"}:
            continue
        try:
            score = float(item.get("score"))
        except (TypeError, ValueError):
            continue
        if not math.isfinite(score) or not 0 <= score <= 100 or isinstance(item.get("score"), bool):
            continue

        raw_type = str(item.get("media_type") or "").lower().split(";", 1)[0].strip()
        modality = raw_type.split("/", 1)[0] if "/" in raw_type else raw_type
        method = str(item.get("method") or "").lower()
        if modality not in modalities:
            modality = next((candidate for candidate in modalities if candidate in method), "")
        if modality not in modalities:
            continue
        usable.append({**item, "score": round(score), "media_type": modality})

    by_modality: dict[str, list[int]] = {}
    for item in usable:
        by_modality.setdefault(item["media_type"], []).append(item["score"])
    channel_scores = {modality: sum(scores) / len(scores) for modality, scores in by_modality.items()}
    if len(channel_scores) < 2:
        return {
            "consistency_score": 0,
            "authenticity_score": 0,
            "risk_score": 0,
            "media_count": len(channel_scores),
            "sample_count": len(usable),
            "modalities": sorted(channel_scores),
            "status": "insufficient evidence",
            "results": usable,
            "method": "at least two distinct image, audio, or video channels with valid anomaly scores are required",
        }

    scores = list(channel_scores.values())
    average = sum(scores) / len(scores)
    spread = max(scores) - min(scores)
    consistency = max(0, min(99, round(100 - spread * 1.4)))
    risk = max(0, min(100, round(average)))
    authenticity = 100 - risk
    return {
        "consistency_score": consistency,
        "authenticity_score": authenticity,
        "risk_score": risk,
        "media_count": len(channel_scores),
        "sample_count": len(usable),
        "modalities": sorted(channel_scores),
        "status": "cross-modal mismatch" if spread >= 25 else "consistent signal",
        "score_spread": spread,
        "results": usable,
        "method": "mean anomaly-risk comparison across distinct media channels; authenticity score is an inverse risk proxy, not a probability",
    }


def counterfactual_replay(incident: dict[str, Any], actions: list[str], variable: str = "response_delay_hours", value: int = 4) -> dict[str, Any]:
    if variable != "response_delay_hours":
        raise ValueError(f"Unsupported counterfactual variable: {variable}")
    if not isinstance(actions, list):
        raise ValueError("Counterfactual actions must be a list")
    supported_actions = {"isolate", "revoke", "block", "notify"}
    normalized_actions = list(dict.fromkeys(str(action).strip().lower() for action in actions))
    unsupported_actions = [action for action in normalized_actions if action not in supported_actions]
    if unsupported_actions:
        raise ValueError(f"Unsupported response action: {unsupported_actions[0]}")
    try:
        delay_hours = int(value)
    except (TypeError, ValueError) as error:
        raise ValueError("Response delay must be an integer hour count") from error
    baseline = _risk(incident)
    action_reduction = min(80, len(normalized_actions) * 12)
    delay_hours = max(0, min(30, delay_hours))
    delay_penalty = delay_hours
    projected = max(0, min(99, baseline - action_reduction + delay_penalty))
    return {
        "incident_id": incident.get("database_id") or incident.get("id"),
        "baseline_risk": baseline,
        "counterfactual_risk": projected,
        "changed_variable": variable,
        "changed_value": delay_hours,
        "actions": normalized_actions,
        "risk_delta": projected - baseline,
        "outcome": "improved" if projected < baseline else "degraded" if projected > baseline else "unchanged",
        "method": "deterministic replay model; original incident record was not modified",
    }


def compliance_diff(controls: list[dict[str, Any]], cves: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    cves = cves or []
    gaps = []
    for cve in cves:
        if isinstance(cve, str):
            cve = {"id": cve, "severity": "unknown"}
        if not isinstance(cve, dict):
            continue
        severity = str(cve.get("severity", "unknown")).lower()
        if severity in {"critical", "high"}:
            gaps.append({"type": "cve", "id": cve.get("id", "unknown"), "severity": severity, "action": "review affected controls and response evidence"})
    for control in controls:
        if str(control.get("status", "")).lower() not in {"compliant", "passed"}:
            gaps.append({"type": "control", "id": control.get("id", "unknown"), "severity": "review", "action": control.get("evidence", "collect updated evidence")})
    return {"control_count": len(controls), "cve_count": len(cves), "gaps": gaps, "gap_count": len(gaps), "status": "attention required" if gaps else "no gaps detected", "source": "local control inventory and supplied CVE feed"}


def supply_chain_blast_radius(
    nodes: list[dict[str, Any]],
    dependencies: list[dict[str, Any]],
    compromised_nodes: list[str],
) -> dict[str, Any]:
    """Propagate a supplied supplier-to-dependent graph without claiming live discovery."""
    if not isinstance(nodes, list) or len(nodes) > 1_000:
        raise ValueError("Supply-chain inventory must be a list of at most 1000 nodes.")
    if not isinstance(dependencies, list) or len(dependencies) > 5_000:
        raise ValueError("Supply-chain dependencies must be a list of at most 5000 edges.")
    if not isinstance(compromised_nodes, list) or len(compromised_nodes) > 1_000:
        raise ValueError("Compromised node identifiers must be a list of at most 1000 ids.")

    node_by_id: dict[str, dict[str, Any]] = {}
    for index, node in enumerate(nodes):
        if not isinstance(node, dict):
            raise ValueError(f"Supply-chain node {index} must be an object.")
        node_id = str(node.get("id") or node.get("node_id") or "").strip()
        if not node_id:
            raise ValueError(f"Supply-chain node {index} is missing an id.")
        if len(node_id) > 128:
            raise ValueError(f"Supply-chain node {index} id exceeds 128 characters.")
        if node_id in node_by_id:
            raise ValueError(f"Duplicate supply-chain node id: {node_id}")
        node_by_id[node_id] = node

    graph: dict[str, list[str]] = {node_id: [] for node_id in node_by_id}
    for index, edge in enumerate(dependencies):
        if not isinstance(edge, dict):
            raise ValueError(f"Supply-chain dependency {index} must be an object.")
        supplier = str(edge.get("supplier") or edge.get("source") or "").strip()
        dependent = str(edge.get("dependent") or edge.get("target") or "").strip()
        if not supplier or not dependent:
            raise ValueError(f"Supply-chain dependency {index} requires supplier and dependent ids.")
        if len(supplier) > 128 or len(dependent) > 128:
            raise ValueError(f"Supply-chain dependency {index} node ids exceed 128 characters.")
        if supplier not in node_by_id or dependent not in node_by_id:
            raise ValueError(f"Supply-chain dependency {index} references an unknown node.")
        graph[supplier].append(dependent)

    sources = list(dict.fromkeys(str(node_id).strip() for node_id in compromised_nodes if str(node_id).strip()))
    if any(source not in node_by_id for source in sources):
        raise ValueError("Compromised node list references an unknown node.")

    affected: dict[str, list[str]] = {}
    queue = deque((source, [source]) for source in sources)
    visited = set(sources)
    while queue:
        current, path = queue.popleft()
        for dependent in graph[current]:
            if dependent in visited:
                continue
            visited.add(dependent)
            affected[dependent] = path + [dependent]
            queue.append((dependent, path + [dependent]))

    affected_nodes = [
        {
            "id": node_id,
            "name": str(node_by_id[node_id].get("name") or node_by_id[node_id].get("label") or node_id)[:256],
            "dependency_chain": affected[node_id],
            "criticality": str(node_by_id[node_id].get("criticality") or "unknown")[:64],
        }
        for node_id in sorted(affected)
    ]
    return {
        "compromised_nodes": sources,
        "affected_count": len(affected_nodes),
        "affected_nodes": affected_nodes,
        "edge_direction": "supplier to downstream dependent",
        "status": "blast radius calculated" if affected_nodes else "no downstream dependencies",
        "mode": "data-driven simulation; inventory and compromise signals were operator supplied",
    }
