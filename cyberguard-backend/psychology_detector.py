import re


TACTICS = {"urgency": r"urgent|immediately|asap|within \d+ hours", "fear": r"suspend|penalty|breach|compromised|warning", "authority": r"director|admin|registrar|official|ceo", "reward": r"prize|refund|reward|scholarship"}


def analyze_psychology(payload: str) -> dict[str, object]:
    text = payload.lower()
    tactics = [{"name": name, "detected": bool(re.search(pattern, text)), "evidence": re.findall(pattern, text)[:3]} for name, pattern in TACTICS.items()]
    detected = [item for item in tactics if item["detected"]]
    score = min(99, len(detected) * 22 + (12 if "http" in text else 0))
    return {"manipulation_score": score, "risk_level": "High" if score >= 60 else "Moderate" if score >= 30 else "Low", "tactics": tactics, "summary": f"{len(detected)} social engineering tactic(s) detected."}