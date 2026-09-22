from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
import re
from typing import Any


def analyze_eml(content: bytes) -> dict[str, Any]:
    message = BytesParser(policy=policy.default).parsebytes(content)
    headers = {name.lower(): str(value) for name, value in message.items()}
    from_address = parseaddr(headers.get("from", ""))[1].lower()
    reply_to = parseaddr(headers.get("reply-to", ""))[1].lower()
    return_path = parseaddr(headers.get("return-path", ""))[1].lower()
    authentication = headers.get("authentication-results", "").lower()
    reasons: list[str] = []
    indicators: list[dict[str, str]] = []
    score = 5
    for protocol in ("spf", "dkim", "dmarc"):
        match = re.search(rf"\b{protocol}\s*[:=]\s*(pass|fail|softfail|neutral|none|temperror|permerror)", authentication)
        result = match.group(1) if match else "missing"
        if result not in {"pass", "missing"}:
            score += 20
            reasons.append(f"{protocol.upper()} authentication returned {result}.")
        elif result == "missing":
            score += 8
            reasons.append(f"{protocol.upper()} authentication evidence is missing from the message.")
        indicators.append({"name": f"{protocol.upper()} Authentication", "score": f"{90 if result == 'pass' else 45}%", "status": result})
    if reply_to and from_address and reply_to != from_address:
        score += 20
        reasons.append("Reply-To does not match the visible From address.")
        indicators.append({"name": "From / Reply-To Mismatch", "score": "92%"})
    if return_path and from_address and return_path != from_address:
        score += 15
        reasons.append("Return-Path does not match the visible sender identity.")
        indicators.append({"name": "Return-Path Mismatch", "score": "86%"})
    body = message.get_body(preferencelist=("plain", "html"))
    body_text = body.get_content() if body else ""
    payload = "\n".join([headers.get("subject", ""), headers.get("from", ""), body_text])[:20000]
    return {"payload": payload, "score": min(score, 99), "reasons": reasons or ["Sender authentication headers are internally consistent."], "indicators": indicators, "metadata": {"from": from_address, "reply_to": reply_to, "return_path": return_path, "authentication_results": authentication}}
