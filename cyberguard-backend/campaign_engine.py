from typing import Any

from threat_fusion import build_genome, correlation_key
from threat_intel import ioc_similarity


def correlate_incident(incident: dict[str, Any], related: list[dict[str, Any]]) -> dict[str, Any]:
    genome = build_genome(incident)
    assessment = incident.get("assessment", {})
    incident_iocs = assessment.get("iocs", [])
    incident_techniques = set(assessment.get("mitre_techniques", []))
    incident_tactics = set(genome["vectors"].get("tactics", []))
    matches = []
    for candidate in related:
        candidate_assessment = candidate.get("assessment", {})
        candidate_genome = build_genome(candidate)
        candidate_iocs = candidate_assessment.get("iocs", [])
        shared_ioc_types = set(genome["vectors"]["ioc_types"]) & set(candidate_genome["vectors"]["ioc_types"])
        shared_techniques = incident_techniques & set(candidate_assessment.get("mitre_techniques", []))
        shared_tactics = incident_tactics & set(candidate_genome["vectors"].get("tactics", []))
        ioc_score = ioc_similarity(incident_iocs, candidate_iocs)
        score = round(ioc_score * 0.5)
        score += 12 if shared_ioc_types else 0
        score += min(40, len(shared_techniques) * 20)
        score += min(20, len(shared_tactics) * 10)
        score += 15 if candidate.get("category") == incident.get("category") else 0
        if score >= 55:
            evidence = []
            if ioc_score:
                evidence.append("IOC values")
            if shared_ioc_types:
                evidence.append("IOC types")
            if shared_techniques:
                evidence.append("ATT&CK techniques")
            if shared_tactics:
                evidence.append("tactics")
            if candidate.get("category") == incident.get("category"):
                evidence.append("attack category")
            matches.append({
                "incident_id": candidate["id"],
                "score": min(score, 98),
                "reason": "Shared " + ", ".join(evidence),
            })
    campaign_id = f"CMP-{correlation_key(incident).upper()}"
    return {"campaign_id": campaign_id, "confidence": min(98, 55 + len(matches) * 9), "related_incidents": matches[:8], "stage": "Discovery" if incident.get("risk_score", 0) < 70 else "Active exploitation"}