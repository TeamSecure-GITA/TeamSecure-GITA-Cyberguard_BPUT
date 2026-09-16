from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from typing import Any


def _entropy(values: list[str]) -> float:
    if not values:
        return 0.0
    counts = Counter(values)
    total = len(values)
    return round(-sum((count / total) * math.log2(count / total) for count in counts.values()), 3)


def predict_threat_physics(nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> dict[str, Any]:
    degree = Counter()
    for edge in edges:
        degree[edge.get("source")] += 1
        degree[edge.get("target")] += 1
    entropy = _entropy([str(edge.get("relationship", "unknown")) for edge in edges])
    hotspots = sorted(
        ({"node": node.get("id"), "label": node.get("label", node.get("id")), "degree": degree[node.get("id")]} for node in nodes),
        key=lambda item: item["degree"],
        reverse=True,
    )[:5]
    risk = min(99, round(25 + entropy * 12 + (max(degree.values(), default=0) * 8)))
    return {"engine": "graph-entropy-prototype", "risk_score": risk, "entropy": entropy, "hotspots": hotspots, "forecast": "high-connectivity nodes are likely lateral-movement pressure points", "disclaimer": "Predictive simulation, not a guarantee of future attacker behavior."}


def cognitive_deception_session(message: str, replies: list[str] | None = None) -> dict[str, Any]:
    text = message.lower()
    tactics = {"urgency": r"urgent|immediately|asap", "authority": r"admin|director|registrar|official|ceo", "fear": r"suspend|breach|penalty|warning", "reward": r"refund|prize|reward|scholarship"}
    detected = [name for name, pattern in tactics.items() if re.search(pattern, text)]
    response_times = [len(reply) for reply in (replies or [])]
    style = "high-pressure authority" if len(detected) >= 2 else "single-vector lure" if detected else "unclassified"
    return {"session_id": hashlib.sha256(message.encode()).hexdigest()[:12].upper(), "cognitive_style": style, "tactics": detected, "engagement_budget": min(99, 20 + len(detected) * 19), "reply_length_profile": response_times, "safe_persona_response": "Can you provide the verified ticket reference and official channel?", "mode": "sandboxed simulation; no external message was sent"}


def morph_topology(nodes: list[dict[str, Any]], edges: list[dict[str, Any]], trigger: str = "reconnaissance") -> dict[str, Any]:
    salt = hashlib.sha256(f"{trigger}:{len(nodes)}:{len(edges)}".encode()).hexdigest()[:8]
    mapped_nodes = [{**node, "ephemeral_id": f"{node.get('id', 'node')}-{salt}"} for node in nodes]
    mapped_edges = [{**edge, "route_epoch": salt} for edge in edges]
    return {"epoch": salt, "trigger": trigger, "nodes": mapped_nodes, "edges": mapped_edges, "proof": "simulated-state-commitment", "mode": "preview only; no routing tables were changed"}


def static_artifact_analysis(content: bytes, filename: str) -> dict[str, Any]:
    digest = hashlib.sha256(content).hexdigest()
    text = content[:2_000_000].decode("utf-8", errors="ignore")
    indicators = []
    for label, pattern in (("network-capability", r"socket|connect|http|dns"), ("persistence", r"startup|cron|registry|scheduled"), ("obfuscation", r"base64|eval\(|exec\(|powershell"), ("destructive", r"delete|encrypt|ransom|wipe")):
        matches = len(re.findall(pattern, text, flags=re.I))
        if matches:
            indicators.append({"label": label, "matches": matches})
    score = min(99, 12 + len(indicators) * 18 + (20 if len(content) > 10_000_000 else 0))
    return {"filename": filename, "sha256": digest, "risk_score": score, "indicators": indicators, "logic_tree": ["artifact", "decode metadata", "extract capability signals", "rank risk"], "mode": "zero-execution static prototype; artifact was not executed"}


def agent_consensus(telemetry: list[dict[str, Any]]) -> dict[str, Any]:
    votes = []
    for item in telemetry:
        risk = int(item.get("risk_score", 0))
        votes.append({"agent": item.get("agent", f"endpoint-{len(votes) + 1}"), "recommendation": "isolate" if risk >= 75 else "observe" if risk < 40 else "challenge", "confidence": min(99, max(10, risk))})
    counts = Counter(vote["recommendation"] for vote in votes)
    decision = counts.most_common(1)[0][0] if counts else "observe"
    return {"decision": decision, "votes": votes, "quorum": len(votes), "consensus": round(counts[decision] / max(len(votes), 1) * 100), "mode": "simulated consensus; no endpoint action was executed"}


def assess_analyst_load(telemetry: dict[str, Any]) -> dict[str, Any]:
    heart_rate = float(telemetry.get("heart_rate", 72))
    blink_rate = float(telemetry.get("blink_rate", 15))
    keystroke_variance = float(telemetry.get("keystroke_variance", 0.35))
    alert_queue = int(telemetry.get("alert_queue", 0))
    fatigue = min(99, round(max(0, heart_rate - 72) * 0.7 + max(0, 12 - blink_rate) * 2 + keystroke_variance * 30 + alert_queue * 2))
    route = "secondary analyst review" if fatigue >= 70 else "supervised primary response" if fatigue >= 40 else "primary analyst"
    return {"fatigue_score": fatigue, "risk_level": "high" if fatigue >= 70 else "moderate" if fatigue >= 40 else "low", "recommended_route": route, "signals": {"heart_rate": heart_rate, "blink_rate": blink_rate, "keystroke_variance": keystroke_variance, "alert_queue": alert_queue}, "consent": "synthetic telemetry only; no camera or peripheral was accessed"}


def assess_q_state(telemetry: dict[str, Any]) -> dict[str, Any]:
    phase_variance = float(telemetry.get("phase_variance", 0.01))
    coherence = max(0.0, min(1.0, float(telemetry.get("coherence", 0.98))))
    error_rate = float(telemetry.get("qber", 0.01))
    anomaly = min(99, round(phase_variance * 1000 + (1 - coherence) * 70 + error_rate * 250))
    return {"decoherence_anomaly": anomaly, "status": "investigate" if anomaly >= 60 else "nominal", "signals": {"phase_variance": phase_variance, "coherence": coherence, "qber": error_rate}, "mode": "Q-state telemetry simulation; no quantum hardware was accessed"}


def assess_satellite_link(telemetry: dict[str, Any]) -> dict[str, Any]:
    doppler_error = abs(float(telemetry.get("doppler_error", 0.0)))
    rf_degradation = float(telemetry.get("rf_degradation", 0.0))
    injection_score = float(telemetry.get("telemetry_mismatch", 0.0))
    risk = min(99, round(doppler_error * 8 + rf_degradation * 0.6 + injection_score * 0.8))
    return {"risk_score": risk, "status": "isolate link for review" if risk >= 60 else "nominal", "signals": {"doppler_error": doppler_error, "rf_degradation": rf_degradation, "telemetry_mismatch": injection_score}, "mode": "satellite telemetry simulation; no RF or orbital system was controlled"}


def build_cognitive_echo(query: str) -> dict[str, Any]:
    digest = hashlib.sha256(query.encode()).hexdigest()[:12].upper()
    topics = [word for word in re.findall(r"[a-z]{5,}", query.lower()) if word not in {"about", "where", "which", "their"}][:5]
    return {"echo_id": digest, "queried_topics": topics, "decoy_documents": [f"internal-{topic}-review.md" for topic in topics], "safe_response": "Access request logged for analyst verification.", "mode": "sandboxed decoy preview; no external actor was contacted and no real document was changed"}


def assess_neuromorphic_telemetry(telemetry: dict[str, Any]) -> dict[str, Any]:
    firing_rate = float(telemetry.get("firing_rate", 0.4))
    stdp_delta = abs(float(telemetry.get("stdp_delta", 0.1)))
    burst_rate = float(telemetry.get("burst_rate", 0.1))
    risk = min(99, round(firing_rate * 45 + stdp_delta * 35 + burst_rate * 40))
    return {"risk_score": risk, "status": "spike injection review" if risk >= 60 else "nominal", "signals": {"firing_rate": firing_rate, "stdp_delta": stdp_delta, "burst_rate": burst_rate}, "mode": "neuromorphic telemetry simulation; no hardware state was modified"}


def frontier_overview(incidents: list[dict[str, Any]]) -> dict[str, Any]:
    nodes = [{"id": "gateway", "label": "BPUT Gateway"}, {"id": "soc", "label": "SOC Core"}]
    nodes.extend({"id": f"incident-{item['id']}", "label": item.get("category", "incident")} for item in incidents[:8])
    edges = [{"source": "gateway", "target": "soc", "relationship": "telemetry"}]
    edges.extend({"source": "gateway", "target": f"incident-{item['id']}", "relationship": "detected"} for item in incidents[:8])
    return {"physics": predict_threat_physics(nodes, edges), "topology": morph_topology(nodes, edges), "agents": agent_consensus([{"agent": "gateway-agent", "risk_score": item.get("risk_score", 0)} for item in incidents[:4]])}
