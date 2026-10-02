from collections import defaultdict
from datetime import datetime, timezone
from typing import Any


def forecast_risk(incidents: list[dict[str, Any]], horizon: int = 6) -> dict[str, Any]:
    recent = incidents[:10]
    scores = [max(0, min(99, int(item.get("risk_score", 0) or 0))) for item in recent]
    if not scores:
        return {
            "baseline": 0,
            "trend": "stable",
            "forecast": [],
            "method": "insufficient_data",
            "sample_count": 0,
            "drivers": ["No recent incidents"],
        }
    hourly_scores: dict[int, list[int]] = defaultdict(list)
    for incident, score in zip(recent, scores):
        try:
            timestamp = datetime.fromisoformat(str(incident.get("created_at", "")).replace("Z", "+00:00"))
        except ValueError:
            continue
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        hour = int(timestamp.timestamp() // 3600)
        hourly_scores[hour].append(score)

    hourly_averages = sorted(
        (hour, sum(values) / len(values))
        for hour, values in hourly_scores.items()
    )
    if hourly_averages:
        latest_hour, latest_average = hourly_averages[-1]
        baseline = round(latest_average)
        coordinates = [(hour - latest_hour, risk) for hour, risk in hourly_averages]
        mean_x = sum(x for x, _ in coordinates) / len(coordinates)
        mean_y = sum(y for _, y in coordinates) / len(coordinates)
        variance = sum((x - mean_x) ** 2 for x, _ in coordinates)
        slope = (
            sum((x - mean_x) * (y - mean_y) for x, y in coordinates) / variance
            if variance
            else 0
        )
        method = "linear projection of observed hourly incident risk averages; not a calibrated prediction"
        sample_count = sum(len(values) for values in hourly_scores.values())
    else:
        baseline = sum(scores) / len(scores) if scores else 0
        slope = 0
        method = "flat carry-forward; insufficient valid incident timestamps for a trend"
        sample_count = 0
    points = [
        {
            "step": index + 1,
            "label": f"T+{index + 1}h",
            "risk": round(min(99, max(0, baseline + slope * (index + 1)))),
        }
        for index in range(max(0, horizon))
    ]
    trend = "escalating" if slope > 0 else "declining" if slope < 0 else "stable"
    return {
        "baseline": baseline,
        "trend": trend,
        "forecast": points,
        "method": method,
        "sample_count": sample_count,
        "drivers": ["Recent incident risk scores"] if scores else ["No recent incidents"],
    }