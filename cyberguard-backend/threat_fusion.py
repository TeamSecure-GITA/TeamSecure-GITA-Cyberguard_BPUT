import hashlib
import json
import re
from difflib import SequenceMatcher
from typing import Any



def build_genome(incident: dict[str, Any]) -> dict[str, Any]:
    assessment = incident.get("assessment", {})
    iocs = assessment.get("iocs", [])
    material = "|".join([
        incident.get("category", "unknown"),
        assessment.get("xai_explanation", ""),
        ",".join(sorted(ioc.get("type", "") for ioc in iocs)),
        ",".join(sorted(assessment.get("mitre_techniques", []))),
    ])
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
    payload_text = (incident.get("payload", "") or "").lower()
    tactic_signals = []
    if any(token in payload_text for token in ["verify", "credential", "password", "otp"]):
        tactic_signals.append("credential-theft")
    if any(token in payload_text for token in ["mfa", "session", "token", "login"]):
        tactic_signals.append("session-takeover")
    if any(token in payload_text for token in ["transfer", "wire", "exfil", "data"]):
        tactic_signals.append("data-exfiltration")
    return {
        "fingerprint": digest[:16].upper(),
        "hash": digest,
        "attack_vector_cluster": incident.get("category", "unknown"),
        "ttp_signature": assessment.get("mitre_techniques", []),
        "mutation_score": min(99, 35 + len(iocs) * 7 + len(assessment.get("mitre_techniques", [])) * 8),
        "previous_similarity": 0,
        "vectors": {
            "initial_access": incident.get("category", "unknown"),
            "techniques": assessment.get("mitre_techniques", []),
            "ioc_types": sorted({ioc.get("type", "unknown") for ioc in iocs}),
            "signals": assessment.get("signal_count", len(assessment.get("indicators", []))),
            "tactics": tactic_signals,
        },
        "similarity_score": min(99, 42 + len(iocs) * 9 + len(assessment.get("mitre_techniques", [])) * 7),
    }


def generate_attacker_intent(incident: dict[str, Any], related: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    assessment = incident.get("assessment", {})
    payload = (incident.get("payload") or "").lower()
    risk_score = int(incident.get("risk_score", 0) or 0)
    techs = assessment.get("mitre_techniques", [])

    goals = []
    if any(token in payload for token in ["verify", "password", "credential", "otp", "login"]):
        goals.append("credential theft")
    if any(token in payload for token in ["mfa", "session", "token", "access"]):
        goals.append("session takeover")
    if any(token in payload for token in ["transfer", "wire", "exfil", "gift card", "payment"]):
        goals.append("financial theft or exfiltration")
    if not goals:
        goals.append("reconnaissance and persistence")
    if any(tech in {"T1078", "T1110", "T1556"} for tech in techs):
        goals.insert(0, "identity compromise")

    summary = "Likely intent: " + " -> ".join(goals[:3])
    confidence = min(99, max(50, risk_score + len(assessment.get("iocs", [])) * 6 + len(techs) * 7))
    recommended_action = "Isolate the account, revoke active sessions, and validate account ownership." if "credential" in summary.lower() or "identity" in summary.lower() else "Contain the malicious flow and review all related assets."
    evidence = []
    for ioc in assessment.get("iocs", [])[:5]:
        value = ioc.get("value") or ioc.get("indicator") or "unknown"
        evidence.append(f"{ioc.get('type', 'indicator')}: {value}")
    if not evidence:
        evidence.append(incident.get("category", "unknown").replace("_", " ").title())
    return {
        "summary": summary,
        "confidence": confidence,
        "risk_score": risk_score,
        "status": "high" if confidence >= 75 else "medium" if confidence >= 50 else "low",
        "evidence": evidence,
        "recommended_action": recommended_action,
    }


def compute_drift_snapshot(incident: dict[str, Any], related: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    current = build_genome(incident)
    related = related or []
    matches = []
    for candidate in related[:10]:
        candidate_genome = build_genome(candidate)
        overlap = len(set(current["vectors"].get("ioc_types", [])) & set(candidate_genome["vectors"].get("ioc_types", [])))
        similarity = min(99, max(0, round((candidate_genome["similarity_score"] + current["similarity_score"]) / 2 - max(0, overlap * 4))))
        if similarity >= 25:
            matches.append({"incident_id": candidate.get("id"), "similarity": similarity, "risk_score": candidate.get("risk_score", 0)})
    drift_score = 0 if not matches else round(100 - (sum(item["similarity"] for item in matches) / len(matches)))
    drift_label = "stable" if drift_score < 25 else "mutating" if drift_score < 60 else "high-drift"
    return {
        "summary": f"Fingerprint drift is {drift_label} across related incidents.",
        "drift_score": drift_score,
        "confidence": min(99, max(40, 65 + drift_score // 2)),
        "status": drift_label,
        "related_incidents": matches,
        "mutation_summary": f"Current genome differs from recent campaign artifacts by {drift_score}%.",
    }


def detect_memory_hits(payload: str, history: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    history = history or []
    normalized = re.sub(r"\s+", " ", (payload or "")).strip().lower()
    matches = []
    for item in history[:15]:
        previous = (item.get("payload") or "").lower()
        if not previous or previous == normalized:
            continue
        score = SequenceMatcher(None, normalized, previous).ratio()
        if score >= 0.78:
            matches.append({"incident_id": item.get("id"), "match_score": round(score * 100), "risk_score": item.get("risk_score", 0)})
    if matches:
        strongest = max(matches, key=lambda item: item["match_score"])
        return {
            "summary": "Known malicious pattern was matched against previous resolved incidents.",
            "status": "memory-hit",
            "confidence": strongest["match_score"],
            "similarity": strongest["match_score"],
            "matches": matches[:5],
            "recommended_action": "Use historical containment playbook and validate for current campaign context.",
        }
    return {
        "summary": "No known historical memory match was found; this appears like a fresh assessment.",
        "status": "fresh-analysis",
        "confidence": 60,
        "similarity": 0,
        "matches": [],
        "recommended_action": "Treat as a new incident and gather fresh evidence."
    }


def score_explainability(incident: dict[str, Any]) -> dict[str, Any]:
    assessment = incident.get("assessment", {})
    indicators = assessment.get("indicators", []) or []
    iocs = assessment.get("iocs", []) or []
    risk_score = int(incident.get("risk_score", 0) or 0)
    score = min(99, 30 + len(indicators) * 8 + len(iocs) * 9 + min(25, risk_score // 3))
    if not indicators and not iocs:
        score = max(0, score - 18)
    trust = "high" if score >= 75 else "medium" if score >= 45 else "low"
    return {
        "summary": "Model explanation is traceable and evidence-backed." if trust == "high" else "Model explanation is partially supported; analyst verification recommended." if trust == "medium" else "Model explanation is weak; manual review advised.",
        "explainability_score": score,
        "explanation_trust": trust,
        "risk_score": risk_score,
    }


_ALERT_OUTCOMES: list[dict[str, Any]] = []


def record_alert_outcome(incident_id: int, detection_type: str, alert_risk_score: int, final_resolution: str, reviewed_by: str = "analyst") -> dict[str, Any]:
    outcome = {
        "incident_id": incident_id,
        "detection_type": detection_type,
        "alert_risk_score": int(alert_risk_score),
        "final_resolution": final_resolution,
        "was_correct": final_resolution.lower() in {"true_positive", "contained", "critical", "malicious", "high-risk"},
        "reviewed_by": reviewed_by,
    }
    _ALERT_OUTCOMES.append(outcome)
    return outcome


def alert_quality_report() -> dict[str, Any]:
    if not _ALERT_OUTCOMES:
        return {"summary": "No alert outcomes recorded yet.", "overall_score": 0, "detection_types": {}, "entries": []}
    total = len(_ALERT_OUTCOMES)
    correct = sum(1 for item in _ALERT_OUTCOMES if item["was_correct"])
    grouped: dict[str, Any] = {}
    for item in _ALERT_OUTCOMES:
        key = item["detection_type"]
        bucket = grouped.setdefault(key, {"count": 0, "correct": 0})
        bucket["count"] += 1
        bucket["correct"] += 1 if item["was_correct"] else 0
    detection_types = {key: round((value["correct"] / max(value["count"], 1)) * 100) for key, value in grouped.items()}
    return {
        "summary": "Alert quality scoring is active.",
        "overall_score": round((correct / total) * 100),
        "detection_types": detection_types,
        "entries": _ALERT_OUTCOMES,
    }


def correlation_key(incident: dict[str, Any]) -> str:
    genome = build_genome(incident)
    return genome["hash"][:12]


def serialize_genome(genome: dict[str, Any]) -> str:
    return json.dumps(genome, sort_keys=True)