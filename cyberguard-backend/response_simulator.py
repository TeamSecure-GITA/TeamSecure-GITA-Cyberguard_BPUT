from typing import Any


ACTIONS = {"isolate": (28, "Isolate affected endpoint"), "revoke": (20, "Revoke sessions and enforce MFA"), "block": (18, "Block malicious IOC"), "notify": (8, "Notify impacted users")}


def simulate_response(risk_score: int, actions: list[str]) -> dict[str, Any]:
    selected = [action for action in actions if action in ACTIONS]
    reduction = min(max(risk_score - 5, 0), sum(ACTIONS[action][0] for action in selected))
    projected = max(0, risk_score - reduction)
    return {"actions": [{"id": action, "label": ACTIONS[action][1], "reduction": ACTIONS[action][0]} for action in selected], "current_risk": risk_score, "projected_risk": projected, "risk_reduction": reduction, "outcome": "Contained" if projected < 35 else "Reduced" if reduction else "Unchanged"}