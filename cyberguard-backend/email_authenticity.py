from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
import hashlib
import os
import re
from typing import Any
from urllib.parse import urljoin, urlparse

MAX_ATTACHMENT_TEXT_BYTES = 1_000_000
RISKY_ATTACHMENT_EXTENSIONS = {".bat", ".cmd", ".com", ".exe", ".hta", ".iso", ".jar", ".js", ".jse", ".lnk", ".msi", ".ps1", ".scr", ".svg", ".vbs", ".wsf", ".docm", ".xlsm", ".pptm"}


class _EmailHTMLInspector(HTMLParser):
    _VOID_ELEMENTS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[dict[str, Any]] = []
        self.iframe_sources: list[str] = []
        self.form_actions: list[str] = []
        self._stack: list[tuple[str, bool]] = []

    @staticmethod
    def _is_hidden(attributes: dict[str, str | None]) -> bool:
        style = attributes.get("style") or ""
        declarations = {
            key.strip().lower(): value.strip().lower()
            for declaration in style.split(";")
            if ":" in declaration
            for key, value in [declaration.split(":", 1)]
        }
        return (
            "hidden" in attributes
            or (attributes.get("aria-hidden") or "").lower() == "true"
            or declarations.get("display") == "none"
            or declarations.get("visibility") == "hidden"
            or declarations.get("opacity") == "0"
            or declarations.get("font-size") == "0"
            or declarations.get("width") == "0"
            or declarations.get("height") == "0"
        )

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        hidden = self._is_hidden(attributes)
        parent_hidden = any(parent_is_hidden for _, parent_is_hidden in self._stack)
        if tag == "a" and attributes.get("href"):
            self.links.append({"url": attributes["href"], "hidden": hidden or parent_hidden})
        elif tag == "iframe" and attributes.get("src"):
            self.iframe_sources.append(attributes["src"])
        elif tag == "form" and attributes.get("action"):
            self.form_actions.append(attributes["action"])
        if tag not in self._VOID_ELEMENTS:
            self._stack.append((tag, hidden or parent_hidden))

    def handle_endtag(self, tag: str) -> None:
        for index in range(len(self._stack) - 1, -1, -1):
            if self._stack[index][0] == tag:
                del self._stack[index:]
                break

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if tag not in self._VOID_ELEMENTS:
            self.handle_endtag(tag)


def inspect_email_html(content: str, sender_domain: str) -> dict[str, Any]:
    parser = _EmailHTMLInspector()
    parser.feed(content)

    def domain_for(value: str) -> str:
        return (urlparse(urljoin(f"https://{sender_domain}/", value)).hostname or "").lower().strip(".")

    links = []
    hidden_links = []
    external_links = []
    for link in parser.links:
        domain = domain_for(link["url"])
        item = {**link, "domain": domain}
        links.append(item)
        if link["hidden"]:
            hidden_links.append(item)
        if domain and sender_domain and not _domains_aligned(sender_domain, domain):
            external_links.append(item)

    external_form_actions = [
        action for action in parser.form_actions
        if (domain := domain_for(action)) and sender_domain and not _domains_aligned(sender_domain, domain)
    ]
    return {
        "links": links,
        "hidden_links": hidden_links,
        "external_links": external_links,
        "iframes": parser.iframe_sources,
        "form_actions": parser.form_actions,
        "external_form_actions": external_form_actions,
    }


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
        status, risk_score = "insufficient_evidence", 35
    elif domain_mismatch:
        status, risk_score = "mismatch", 70
    elif not authentication_trusted:
        status, risk_score = ("untrusted_evidence", 55) if any_pass else ("insufficient_evidence", 35)
        reasons.append("Authentication-Results was not issued by a configured trusted auth server.")
    elif mismatches or (any_pass and not any_aligned and dmarc["status"] != "pass"):
        status, risk_score = "mismatch", 70
        if not reasons:
            reasons.append("Passing authentication evidence did not align with the visible From domain.")
    elif dmarc["status"] == "pass" and dmarc["aligned"]:
        status, risk_score = "verified", 5
        reasons.append("DMARC identity aligns with the visible From domain.")
    elif any_aligned:
        status, risk_score = "partially_verified", 20
        reasons.append("Some sender authentication aligns, but DMARC evidence is incomplete.")
    else:
        status, risk_score = "insufficient_evidence", 35
        reasons.append("Available authentication evidence is insufficient to verify the sender domain.")

    return {
        "status": status,
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
        indicators.append({"name": f"{protocol.upper()} Authentication", "weight": 20 if result not in {"pass", "missing"} else 8 if result == "missing" else 1, "status": result})
    if reply_to and from_address and reply_to != from_address:
        score += 20
        reasons.append("Reply-To does not match the visible From address.")
        indicators.append({"name": "From / Reply-To Mismatch", "weight": 20})
    if return_path and from_address and return_path != from_address:
        score += 15
        reasons.append("Return-Path does not match the visible sender identity.")
        indicators.append({"name": "Return-Path Mismatch", "weight": 15})
    score = max(score, identity_verification["risk_score"])
    reasons.extend(identity_verification["reasons"])
    indicators.append({"name": "Sender Identity Verification", "weight": max(identity_verification["risk_score"], 1), "status": identity_verification["status"]})
    body = message.get_body(preferencelist=("plain", "html"))
    body_text = body.get_content() if body else ""
    html_parts = []
    for part in message.walk():
        if part.get_content_type() != "text/html" or part.get_content_disposition() == "attachment":
            continue
        data = part.get_payload(decode=True) or b""
        if len(data) <= MAX_ATTACHMENT_TEXT_BYTES:
            html_parts.append(data.decode(part.get_content_charset() or "utf-8", errors="replace"))
    html_inspection = inspect_email_html("\n".join(html_parts), identity_verification["from_domain"]) if html_parts else None
    if html_inspection:
        if html_inspection["hidden_links"]:
            score += 20
            reasons.append(f"Email HTML contains {len(html_inspection['hidden_links'])} hidden link(s).")
            indicators.append({"name": "Hidden Email Links", "weight": 20, "count": len(html_inspection["hidden_links"])})
        if html_inspection["iframes"]:
            score += 15
            reasons.append(f"Email HTML contains {len(html_inspection['iframes'])} iframe(s).")
            indicators.append({"name": "Email HTML Iframes", "weight": 15, "count": len(html_inspection["iframes"])})
        if html_inspection["external_form_actions"]:
            score += 25
            reasons.append("An email form submits to a domain unrelated to the visible sender.")
            indicators.append({"name": "External Email Form Action", "weight": 25, "count": len(html_inspection["external_form_actions"])})
    attachment_text = []
    attachments = []
    for part in message.walk():
        if part.is_multipart() or (part.get_content_disposition() != "attachment" and not part.get_filename()):
            continue
        filename = part.get_filename() or "unnamed-attachment"
        data = part.get_payload(decode=True) or b""
        extension = os.path.splitext(filename)[1].lower()
        attachment = {
            "filename": filename[:255],
            "content_type": part.get_content_type(),
            "size_bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "status": "metadata_only",
        }
        if extension in RISKY_ATTACHMENT_EXTENSIONS:
            attachment["status"] = "active_content_review"
            score += 20
            reasons.append(f"Email attachment has a potentially active or executable file type ({extension or 'unknown'}): {filename[:120]}.")
            indicators.append({"name": "Risky Email Attachment Type", "weight": 20, "filename": filename[:120]})
        if part.get_content_maintype() == "text" and len(data) <= MAX_ATTACHMENT_TEXT_BYTES:
            charset = part.get_content_charset() or "utf-8"
            attachment_text.append(data.decode(charset, errors="replace")[:MAX_ATTACHMENT_TEXT_BYTES])
            attachment["status"] = "text_content_scanned"
        elif len(data) > MAX_ATTACHMENT_TEXT_BYTES:
            attachment["status"] = "size_limited"
        attachments.append(attachment)
    payload = "\n".join([headers.get("subject", ""), headers.get("from", ""), body_text, *attachment_text])[:20000]
    return {"payload": payload, "score": min(score, 99), "reasons": reasons or ["Sender authentication headers are internally consistent."], "indicators": indicators, "metadata": {"from": from_address, "reply_to": reply_to, "return_path": return_path, "authentication_results": authentication}, "identity_verification": identity_verification, "html_inspection": html_inspection, "attachments": attachments}
