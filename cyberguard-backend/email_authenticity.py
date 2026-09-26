from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
import os
import re
from typing import Any


def _mail_domain(value: str) -> str:
    address = parseaddr(value)[1].strip().lower()
    return address.rsplit("@", 1)[1].strip(".>") if "@" in address else ""


def _domains_aligned(left: str, right: str) -> bool:
    return bool(left and right and (left == right or left.endswith("." + right) or right.endswith("." + left)))


def verify_sender_identity(from_header: str, reply_to_header: str, return_path_header: str, authentication: str, trusted_authserv_ids: set[str] | None = None) -> dict[str, Any]:
    from_domain = _mail_domain(from_header)
    authserv_id = authentication.partition(";")[0].strip().lower()
    if trusted_authserv_ids is None:
        trusted_authserv_ids = {value.strip().lower() for value in os.getenv("CYBERGUARD_TRUSTED_AUTHSERV_IDS", "").split(",") if value.strip()}
    authentication_trusted = authserv_id in trusted_authserv_ids
    checks = {}
    for protocol, identity_field in (("spf", "smtp.mailfrom"), ("dkim", "header.d"), ("dmarc", "header.from")):
        results = []
        pattern = rf"\b{protocol}\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b([^;]*)"
        for match in re.finditer(pattern, authentication, re.IGNORECASE):
            identity_match = re.search(rf"\b{re.escape(identity_field)}\s*=\s*<?([^>\s;]+)>?", match.group(2), re.IGNORECASE)
            identity_domain = _mail_domain(identity_match.group(1)) if identity_match and "@" in identity_match.group(1) else identity_match.group(1).strip(".").lower() if identity_match else ""
            results.append({"status": match.group(1).lower(), "domain": identity_domain, "aligned": _domains_aligned(from_domain, identity_domain)})
        passing = next((result for result in results if result["status"] == "pass"), None)
        checks[protocol] = {
            "status": passing["status"] if passing else results[0]["status"] if results else "missing",
            "domains": sorted({result["domain"] for result in results if result["domain"]}),
            "aligned": any(result["status"] == "pass" and result["aligned"] for result in results),
        }

    reasons = []
    reply_domain = _mail_domain(reply_to_header)
    return_domain = _mail_domain(return_path_header)
    if not from_domain:
        reasons.append("A valid visible From domain could not be verified.")
    if reply_domain and from_domain and not _domains_aligned(reply_domain, from_domain):
        reasons.append("Reply-To domain is not aligned with the visible From domain.")
    if return_domain and from_domain and not _domains_aligned(return_domain, from_domain):
        reasons.append("Return-Path domain is not aligned with the visible From domain.")
    dmarc = checks["dmarc"]
    if dmarc["status"] == "pass" and not dmarc["aligned"]:
        reasons.append("DMARC passed for a domain that does not align with the visible From domain.")
    elif dmarc["status"] in {"fail", "softfail", "permerror"}:
        reasons.append(f"DMARC verification for the visible sender returned {dmarc['status']}.")

    domain_mismatch = bool(reply_domain and from_domain and not _domains_aligned(reply_domain, from_domain)) or bool(return_domain and from_domain and not _domains_aligned(return_domain, from_domain))
    mismatches = len(reasons)
    any_aligned = any(check["aligned"] for name, check in checks.items() if name in {"spf", "dkim"})
    any_pass = any(check["status"] == "pass" for check in checks.values())
    if not from_domain:
        status, confidence, risk_score = "insufficient_evidence", 20, 35
    elif domain_mismatch:
        status, confidence, risk_score = "mismatch", 88, 70
    elif not authentication_trusted:
        status, confidence, risk_score = ("untrusted_evidence", 20, 55) if any_pass else ("insufficient_evidence", 30, 35)
        reasons.append("Authentication-Results was not issued by a configured trusted auth server.")
    elif mismatches or (any_pass and not any_aligned and dmarc["status"] != "pass"):
        status, confidence, risk_score = "mismatch", 88, 70
        if not reasons:
            reasons.append("Passing authentication evidence did not align with the visible From domain.")
    elif dmarc["status"] == "pass" and dmarc["aligned"]:
        status, confidence, risk_score = "verified", 95, 5
        reasons.append("DMARC identity aligns with the visible From domain.")
    elif any_aligned:
        status, confidence, risk_score = "partially_verified", 68, 20
        reasons.append("Some sender authentication aligns, but DMARC evidence is incomplete.")
    else:
        status, confidence, risk_score = "insufficient_evidence", 35, 35
        reasons.append("Available authentication evidence is insufficient to verify the sender domain.")

    return {
        "status": status,
        "confidence": confidence,
        "risk_score": risk_score,
        "from_domain": from_domain,
        "authserv_id": authserv_id,
        "authentication_trusted": authentication_trusted,
        "checks": checks,
        "reasons": reasons,
    }


def analyze_eml(content: bytes) -> dict[str, Any]:
    message = BytesParser(policy=policy.default).parsebytes(content)
    headers = {name.lower(): str(value) for name, value in message.items()}
    from_address = parseaddr(headers.get("from", ""))[1].lower()
    reply_to = parseaddr(headers.get("reply-to", ""))[1].lower()
    return_path = parseaddr(headers.get("return-path", ""))[1].lower()
    authentication = headers.get("authentication-results", "").lower()
    identity_verification = verify_sender_identity(headers.get("from", ""), headers.get("reply-to", ""), headers.get("return-path", ""), authentication)
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
    score = max(score, identity_verification["risk_score"])
    reasons.extend(identity_verification["reasons"])
    indicators.append({"name": "Sender Identity Verification", "score": f"{identity_verification['confidence']}%", "status": identity_verification["status"]})
    body = message.get_body(preferencelist=("plain", "html"))
    body_text = body.get_content() if body else ""
    payload = "\n".join([headers.get("subject", ""), headers.get("from", ""), body_text])[:20000]
    return {"payload": payload, "score": min(score, 99), "reasons": reasons or ["Sender authentication headers are internally consistent."], "indicators": indicators, "metadata": {"from": from_address, "reply_to": reply_to, "return_path": return_path, "authentication_results": authentication}, "identity_verification": identity_verification}
