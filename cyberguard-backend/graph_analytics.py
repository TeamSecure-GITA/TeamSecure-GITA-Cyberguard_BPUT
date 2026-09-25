"""Explainable incident entity graph analytics with a NetworkX optional path."""
from collections import defaultdict
import re
from typing import Any
from urllib.parse import urlparse

URL_PATTERN = re.compile(r"https?://[^\s<>\"']+")
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_PATTERN = re.compile(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b")


def build_incident_graph(incidents: list[dict[str, Any]]) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[tuple[str, str], dict[str, Any]] = {}
    incident_entities: dict[str, set[str]] = defaultdict(set)

    def add_node(node_id: str, label: str, kind: str, risk_score: int = 0):
        node = nodes.setdefault(node_id, {"id": node_id, "label": label, "kind": kind, "risk_score": 0, "incidents": 0})
        node["risk_score"] = max(node["risk_score"], risk_score)
        node["incidents"] += 1

    def connect(left: str, right: str, relation: str):
        key = tuple(sorted((left, right)))
        if key not in edges:
            edges[key] = {"source": left, "target": right, "label": relation, "weight": 0}
        edges[key]["weight"] += 1

    add_node("origin", "External Threat Sources", "origin")
    for incident in incidents:
        incident_id = f"incident-{incident.get('id', incident.get('database_id'))}"
        risk_score = int(incident.get("risk_score", incident.get("riskScore", 0)) or 0)
        add_node(incident_id, str(incident.get("category", "threat")).replace("_", " ").title(), "incident", risk_score)
        payload = str(incident.get("payload", ""))
        entities = []
        entities.extend((f"domain:{urlparse(url).hostname}", urlparse(url).hostname, "domain") for url in URL_PATTERN.findall(payload) if urlparse(url).hostname)
        entities.extend((f"ip:{value}", value, "ip") for value in IP_PATTERN.findall(payload))
        entities.extend((f"email:{value.lower()}", value.lower(), "email") for value in EMAIL_PATTERN.findall(payload))
        entities.append((f"category:{incident.get('category', 'unknown')}", str(incident.get("category", "unknown")).replace("_", " ").title(), "category"))
        for entity_id, label, kind in entities:
            add_node(entity_id, label, kind, risk_score)
            connect("origin", entity_id, "observed")
            connect(entity_id, incident_id, "linked-to")
            incident_entities[incident_id].add(entity_id)
        for left in incident_entities[incident_id]:
            for right in incident_entities[incident_id]:
                if left < right:
                    connect(left, right, "shared-incident")

    adjacency = defaultdict(set)
    for (left, right), edge in edges.items():
        adjacency[left].add(right)
        adjacency[right].add(left)
    communities = []
    visited = set()
    for node_id in nodes:
        if node_id in visited:
            continue
        stack = [node_id]
        members = []
        while stack:
            current = stack.pop()
            if current in visited:
                continue
            visited.add(current)
            members.append(current)
            stack.extend(adjacency[current] - visited)
        communities.append({"community_id": f"campaign-{len(communities) + 1}", "members": members, "size": len(members)})
    community_by_node = {member: community["community_id"] for community in communities for member in community["members"]}
    for node in nodes.values():
        node["community_id"] = community_by_node.get(node["id"])
    return {"nodes": list(nodes.values()), "edges": list(edges.values()), "communities": communities, "analytics": {"entity_count": len(nodes), "edge_count": len(edges), "community_count": len(communities), "method": "connected-component campaign clustering"}}
