import hashlib
import json
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
    return {
        "fingerprint": digest[:16].upper(),
        "hash": digest,
        "vectors": {
            "initial_access": incident.get("category", "unknown"),
            "techniques": assessment.get("mitre_techniques", []),
            "ioc_types": sorted({ioc.get("type", "unknown") for ioc in iocs}),
            "signals": assessment.get("signal_count", len(assessment.get("indicators", []))),
        },
        "similarity_score": min(99, 42 + len(iocs) * 9 + len(assessment.get("mitre_techniques", [])) * 7),
    }


def correlation_key(incident: dict[str, Any]) -> str:
    genome = build_genome(incident)
    return genome["hash"][:12]


def serialize_genome(genome: dict[str, Any]) -> str:
    return json.dumps(genome, sort_keys=True)