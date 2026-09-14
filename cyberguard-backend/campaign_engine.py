from typing import Any

from threat_fusion import build_genome, correlation_key
from threat_intel import ioc_similarity


def correlate_incident(incident: dict[str, Any], related: list[dict[str, Any]]) -> dict[str, Any]:
    genome = build_genome(incident)
    matches = []
    for candidate in related:
        candidate_genome = build_genome(candidate)
        score = 72 if candidate.get("category") == incident.get("category") else 38
        score += ioc_similarity(incident.get("assessment", {}).get("iocs", []), candidate.get("assessment", {}).get("iocs", [])) // 4
        if candidate_genome["vectors"]["ioc_types"] == genome["vectors"]["ioc_types"]:
            score += 18
        if score >= 55:
            matches.append({"incident_id": candidate["id"], "score": min(score, 98), "reason": "Shared attack vector and IOC profile"})
    campaign_id = f"CMP-{correlation_key(incident).upper()}"
    return {"campaign_id": campaign_id, "confidence": min(98, 55 + len(matches) * 9), "related_incidents": matches[:8], "stage": "Discovery" if incident.get("risk_score", 0) < 70 else "Active exploitation"}