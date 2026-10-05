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
    assessment = incident.get("assessment") if isinstance(incident.get("assessment"), dict) else {}
    payload = (incident.get("payload") or "").lower()
    risk_score = int(incident.get("risk_score", 0) or 0)
    techs = {str(item).strip().upper() for item in (assessment.get("mitre_techniques") or []) if str(item).strip()}
    iocs = assessment.get("iocs") or []
    ioc_values = {
        str(item.get("indicator") or item.get("value") or "").strip().lower()
        for item in iocs
        if isinstance(item, dict) and (item.get("indicator") or item.get("value"))
    }

    goals = []
    if any(token in payload for token in ["verify", "password", "credential", "otp", "login"]):
        goals.append("credential theft")
    if any(token in payload for token in ["mfa", "session", "token", "access"]):
        goals.append("session takeover")
    if any(token in payload for token in ["transfer", "wire", "exfil", "gift card", "payment"]):
        goals.append("financial theft or exfiltration")
    if not goals:
        goals.append("reconnaissance and persistence")
    if techs & {"T1078", "T1110", "T1556"}:
        goals.insert(0, "identity compromise")

    related_matches = []
    for candidate in (related or [])[:50]:
        candidate_assessment = candidate.get("assessment") if isinstance(candidate.get("assessment"), dict) else {}
        candidate_iocs = candidate_assessment.get("iocs") or []
        candidate_values = {
            str(item.get("indicator") or item.get("value") or "").strip().lower()
            for item in candidate_iocs
            if isinstance(item, dict) and (item.get("indicator") or item.get("value"))
        }
        candidate_techniques = {str(item).strip().upper() for item in (candidate_assessment.get("mitre_techniques") or []) if str(item).strip()}
        shared_techniques = sorted(techs & candidate_techniques)
        shared_ioc_count = len(ioc_values & candidate_values)
        if shared_ioc_count or shared_techniques:
            related_matches.append({
                "incident_id": candidate.get("id"),
                "shared_ioc_count": shared_ioc_count,
                "shared_techniques": shared_techniques,
                "risk_score": candidate.get("risk_score", 0),
            })

    related_matches.sort(key=lambda item: (-(item["shared_ioc_count"] + len(item["shared_techniques"])), -int(item["risk_score"] or 0)))
    related_matches = related_matches[:5]
    summary = "Likely intent: " + " -> ".join(goals[:3])
    if related_matches:
        summary += f"; corroborated by {len(related_matches)} related incident(s) sharing threat evidence"
    confidence = min(99, max(50, risk_score + len(iocs) * 6 + len(techs) * 7) + min(15, len(related_matches) * 5))
    recommended_action = "Isolate the account, revoke active sessions, and validate account ownership." if "credential" in summary.lower() or "identity" in summary.lower() else "Contain the malicious flow and review all related assets."
    evidence = []
    for ioc in iocs[:5]:
        value = ioc.get("value") or ioc.get("indicator") or "unknown"
        evidence.append(f"{ioc.get('type', 'indicator')}: {value}")
    if not evidence:
        evidence.append(incident.get("category", "unknown").replace("_", " ").title())
    if related_matches:
        evidence.append(f"Corroborated by {len(related_matches)} related incident(s) with shared IOC or ATT&CK evidence.")
    return {
        "summary": summary,
        "confidence": confidence,
        "risk_score": risk_score,
        "status": "high" if confidence >= 75 else "medium" if confidence >= 50 else "low",
        "evidence": evidence,
        "related_incidents": related_matches,
        "recommended_action": recommended_action,
    }


def compute_drift_snapshot(incident: dict[str, Any], related: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    current = build_genome(incident)
    current_assessment = incident.get("assessment") if isinstance(incident.get("assessment"), dict) else {}
    current_iocs = {
        str(item.get("indicator") or item.get("value") or "").strip().lower()
        for item in (current_assessment.get("iocs") or [])
        if isinstance(item, dict) and (item.get("indicator") or item.get("value"))
    }
    current_techniques = {str(item).strip().upper() for item in (current_assessment.get("mitre_techniques") or []) if str(item).strip()}
    current_tactics = set(current["vectors"].get("tactics", []))
    current_payload = re.sub(r"\s+", " ", str(incident.get("payload") or "")).strip().lower()
    related = related or []
    matches = []
    for candidate in related[:10]:
        candidate_genome = build_genome(candidate)
        candidate_assessment = candidate.get("assessment") if isinstance(candidate.get("assessment"), dict) else {}
        candidate_iocs = {
            str(item.get("indicator") or item.get("value") or "").strip().lower()
            for item in (candidate_assessment.get("iocs") or [])
            if isinstance(item, dict) and (item.get("indicator") or item.get("value"))
        }
        candidate_techniques = {str(item).strip().upper() for item in (candidate_assessment.get("mitre_techniques") or []) if str(item).strip()}
        candidate_tactics = set(candidate_genome["vectors"].get("tactics", []))
        candidate_payload = re.sub(r"\s+", " ", str(candidate.get("payload") or "")).strip().lower()
        shared_iocs = current_iocs & candidate_iocs
        shared_techniques = current_techniques & candidate_techniques
        shared_tactics = current_tactics & candidate_tactics
        payload_similarity = SequenceMatcher(None, current_payload, candidate_payload).ratio() if current_payload and candidate_payload else 0
        if not (shared_iocs or shared_techniques or shared_tactics or payload_similarity >= 0.82):
            continue

        evidence = []
        if shared_iocs:
            evidence.append("shared IOC values")
        if shared_techniques:
            evidence.append("shared ATT&CK techniques")
        if shared_tactics:
            evidence.append("shared tactics")
        if payload_similarity >= 0.82:
            evidence.append("similar payload language")
        ioc_similarity_score = len(shared_iocs) / max(len(current_iocs | candidate_iocs), 1)
        technique_similarity = len(shared_techniques) / max(len(current_techniques | candidate_techniques), 1)
        tactic_similarity = len(shared_tactics) / max(len(current_tactics | candidate_tactics), 1)
        similarity = round(100 * (0.4 * ioc_similarity_score + 0.3 * technique_similarity + 0.1 * tactic_similarity + 0.2 * payload_similarity))
        matches.append({
            "incident_id": candidate.get("id"),
            "similarity": min(99, similarity),
            "risk_score": candidate.get("risk_score", 0),
            "evidence": evidence,
        })
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
    normalized = re.sub(r"\s+", " ", (payload or "")).strip().lower()
    matches = []
    resolved_history = [
        item for item in (history or [])
        if str(item.get("status") or "").strip().lower() in {"closed", "mitigated"}
    ]
    for item in resolved_history[:15]:
        previous = re.sub(r"\s+", " ", (item.get("payload") or "")).strip().lower()
        if not previous:
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
    risk_score = int(incident.get("risk_score", 0) or 0)
    scoring = assessment.get("scoring")
    if not isinstance(scoring, dict) or scoring.get("method") != "evidence_weighted_attribution_v1":
        return {
            "summary": "This legacy incident has no stored evidence attribution; no explainability score is inferred.",
            "contribution_status": "unavailable_for_legacy_incident",
            "risk_score": risk_score,
            "indicator_count": len(assessment.get("indicators", []) or []),
            "contributions": [],
        }

    indicators = assessment.get("indicators", []) or []
    return {
        "summary": scoring["interpretation"],
        "contribution_status": "available",
        "risk_score": risk_score,
        "indicator_count": len(indicators),
        "contributions": [
            {
                "name": item.get("name", "Unnamed signal"),
                "share": item.get("score"),
                "risk_points": item.get("contribution", 0),
                "weight": item.get("weight"),
                "feature_attribution": item.get("feature_attribution"),
            }
            for item in indicators
        ],
        "evidence_summary": scoring.get("evidence_summary"),
    }


def record_alert_outcome(incident_id: int, detection_type: str, alert_risk_score: int, final_resolution: str, reviewed_by: str = "analyst") -> dict[str, Any]:
    resolution = str(final_resolution).strip().lower()
    outcome = {
        "incident_id": incident_id,
        "detection_type": detection_type,
        "alert_risk_score": int(alert_risk_score),
        "final_resolution": resolution,
        "was_correct": resolution in {"true_positive", "contained", "critical", "malicious", "high-risk"},
        "reviewed_by": reviewed_by,
    }
    return outcome


def alert_quality_report(outcomes: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    outcomes = outcomes or []
    if not outcomes:
        return {"summary": "No alert outcomes recorded yet.", "overall_score": 0, "detection_types": {}, "entries": []}
    total = len(outcomes)
    correct = sum(1 for item in outcomes if item["was_correct"])
    grouped: dict[str, Any] = {}
    for item in outcomes:
        key = item["detection_type"]
        bucket = grouped.setdefault(key, {"count": 0, "correct": 0})
        bucket["count"] += 1
        bucket["correct"] += 1 if item["was_correct"] else 0
    detection_types = {key: round((value["correct"] / max(value["count"], 1)) * 100) for key, value in grouped.items()}
    return {
        "summary": "Alert quality scoring is active.",
        "overall_score": round((correct / total) * 100),
        "detection_types": detection_types,
        "entries": outcomes,
    }


def correlation_key(incident: dict[str, Any]) -> str:
    genome = build_genome(incident)
    return genome["hash"][:12]


def serialize_genome(genome: dict[str, Any]) -> str:
    return json.dumps(genome, sort_keys=True)