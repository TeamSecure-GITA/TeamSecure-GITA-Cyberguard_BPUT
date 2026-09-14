def recommend_healing(incident: dict) -> dict:
    risk = incident.get("risk_score", 0)
    actions = ["Preserve forensic evidence", "Block extracted IOCs", "Revoke affected sessions", "Verify MFA and endpoint health"]
    if risk < 50:
        actions = ["Monitor related indicators", "Notify the asset owner", "Schedule a follow-up review"]
    return {"priority": "critical" if risk >= 85 else "high" if risk >= 65 else "normal", "actions": [{"order": index + 1, "label": action, "status": "recommended"} for index, action in enumerate(actions)], "estimated_recovery_minutes": 15 + len(actions) * 10}