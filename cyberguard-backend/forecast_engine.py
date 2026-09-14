from typing import Any


def forecast_risk(incidents: list[dict[str, Any]], horizon: int = 6) -> dict[str, Any]:
    recent = incidents[:10]
    baseline = round(sum(item.get("risk_score", 0) for item in recent) / len(recent)) if recent else 0
    points = [{"step": index + 1, "label": f"T+{index + 1}h", "risk": min(99, max(0, baseline + index * max(2, round(baseline / 14)))), "confidence": max(54, 91 - index * 5)} for index in range(horizon)]
    return {"baseline": baseline, "trend": "escalating" if points and points[-1]["risk"] > baseline else "stable", "forecast": points, "drivers": ["Recent incident density", "Uncontained high-risk signals", "Shared IOC patterns"] if baseline else ["No recent incidents"]}