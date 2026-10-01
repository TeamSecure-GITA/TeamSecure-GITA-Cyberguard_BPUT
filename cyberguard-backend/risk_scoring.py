"""Shared risk-score attribution for stored incident assessments."""

import math
from typing import Any


def _apportion(total: int, weights: list[float]) -> list[int]:
    weight_total = sum(weights)
    if not weights or weight_total <= 0:
        return []
    exact = [total * weight / weight_total for weight in weights]
    apportioned = [math.floor(value) for value in exact]
    remainder = total - sum(apportioned)
    order = sorted(range(len(weights)), key=lambda index: exact[index] - apportioned[index], reverse=True)
    for index in order[:remainder]:
        apportioned[index] += 1
    return apportioned


def score_event(assessment: dict[str, Any]) -> dict[str, Any]:
    """Preserve the detector total and attribute it across triggered evidence signals."""
    risk_score = max(0, min(99, int(assessment.get("risk_score", 0) or 0)))
    indicators = [dict(item) for item in (assessment.get("indicators") or []) if isinstance(item, dict)]
    weights = []
    for indicator in indicators:
        value = indicator.get("weight")
        try:
            weight = float(value)
        except (TypeError, ValueError):
            weight = 1.0
        weights.append(weight if math.isfinite(weight) and weight > 0 else 1.0)

    share_points = _apportion(100, weights)
    risk_points = _apportion(risk_score, weights)
    for index, indicator in enumerate(indicators):
        indicator.pop("score", None)
        indicator["score"] = f"{share_points[index]}%"
        indicator["score_kind"] = "evidence_share"
        indicator["contribution"] = risk_points[index]

    assessment["risk_score"] = risk_score
    assessment["indicators"] = indicators
    assessment["scoring"] = {
        "method": "evidence_weighted_attribution_v1",
        "risk_score": risk_score,
        "risk_level": assessment.get("risk_level", "Unknown"),
        "indicator_count": len(indicators),
        "contributions_total": sum(risk_points),
        "interpretation": "Risk score is the detector output. Indicator percentages are normalized shares of triggered evidence, not probabilities or confidence values.",
        "evidence_summary": assessment.get("explanation_summary") or assessment.get("xai_explanation") or "No explanation evidence was supplied by the detector.",
    }
    return assessment