from typing import Any


def run_battle(risk_score: int, defender_actions: list[str]) -> dict[str, Any]:
    rounds = [{"round": 1, "attacker": "Initial access attempt", "defender": "Telemetry inspected", "result": "Detected"}, {"round": 2, "attacker": "Credential replay", "defender": "MFA challenge and session revocation", "result": "Blocked" if "revoke" in defender_actions else "Escalated"}, {"round": 3, "attacker": "Lateral movement", "defender": "Endpoint isolation", "result": "Contained" if "isolate" in defender_actions else "At risk"}]
    score = max(8, risk_score - len(defender_actions) * 17)
    return {"winner": "defender" if score < risk_score else "attacker", "surviving_risk": score, "rounds": rounds}