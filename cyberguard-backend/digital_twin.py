from typing import Any


def build_twin(incidents: list[dict[str, Any]]) -> dict[str, Any]:
    nodes = [{"id": "internet", "label": "External Internet", "kind": "source", "status": "elevated" if incidents else "stable"}, {"id": "gateway", "label": "BPUT Gateway", "kind": "control", "status": "protected"}, {"id": "soc", "label": "SOC Core", "kind": "control", "status": "online"}]
    for index, incident in enumerate(incidents[:6]):
        nodes.append({"id": f"incident-{incident['id']}", "label": incident.get("category", "threat").replace("_", " ").title(), "kind": "threat", "status": incident.get("risk_level", "Unknown").lower(), "risk_score": incident.get("risk_score", 0)})
    edges = [{"source": "internet", "target": "gateway", "label": "ingress"}, {"source": "gateway", "target": "soc", "label": "telemetry"}]
    edges.extend({"source": "gateway", "target": f"incident-{incident['id']}", "label": "detected"} for incident in incidents[:6])
    return {"nodes": nodes, "edges": edges, "last_updated": "live"}