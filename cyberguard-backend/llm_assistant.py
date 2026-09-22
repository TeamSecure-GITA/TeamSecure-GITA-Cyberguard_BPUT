import json
import os
import re
from typing import Any

import requests

PII_PATTERNS = [
    (re.compile(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b"), "[REDACTED_EMAIL]"),
    (re.compile(r"\b(?:\d[ -]*?){13,16}\b"), "[REDACTED_ACCOUNT]"),
    (re.compile(r"\b(?:password|otp|token|secret)\s*[:=]\s*\S+", re.I), "[REDACTED_SECRET]"),
]


def redact_evidence(value: Any) -> str:
    text = json.dumps(value, ensure_ascii=True) if not isinstance(value, str) else value
    for pattern, replacement in PII_PATTERNS:
        text = pattern.sub(replacement, text)
    return text[:12000]


def _template(assessment: dict[str, Any]) -> dict[str, Any]:
    level = assessment.get("risk_level", "Unknown")
    explanation = assessment.get("xai_explanation", "No explanation available.")
    actions = [item.get("label", item.get("id", "review")) for item in assessment.get("recommended_actions", [])]
    return {"summary": f"{level} risk event. {explanation}", "next_steps": actions[:5] or ["Review evidence and confirm the affected identity manually."], "model": "offline-template", "privacy": "PII redacted before any external request"}


def generate_analysis(assessment: dict[str, Any], incident: dict[str, Any] | None = None) -> dict[str, Any]:
    evidence = redact_evidence({"assessment": assessment, "incident": incident or {}})
    endpoint = os.getenv("CYBERGUARD_LLM_ENDPOINT", "").strip()
    api_key = os.getenv("CYBERGUARD_LLM_API_KEY", "").strip()
    model = os.getenv("CYBERGUARD_LLM_MODEL", "gpt-4o-mini")
    if not endpoint or not api_key:
        return _template(assessment)
    body = {"model": model, "temperature": 0.1, "response_format": {"type": "json_object"}, "messages": [{"role": "system", "content": "You are a SOC analyst. Return JSON with summary, next_steps, and uncertainty. Do not invent facts."}, {"role": "user", "content": evidence}]}
    try:
        response = requests.post(endpoint, headers={"Authorization": f"Bearer {api_key}"}, json=body, timeout=20)
        response.raise_for_status()
        content = response.json()["choices"][0]["message"]["content"]
        result = json.loads(content)
        return {"summary": str(result.get("summary", "")), "next_steps": list(result.get("next_steps", []))[:5], "uncertainty": str(result.get("uncertainty", "")), "model": model, "privacy": "PII redacted before external request"}
    except (requests.RequestException, KeyError, TypeError, ValueError) as error:
        fallback = _template(assessment)
        fallback["provider_error"] = str(error)
        return fallback
