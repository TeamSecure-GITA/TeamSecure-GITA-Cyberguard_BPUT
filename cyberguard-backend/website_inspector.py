import ipaddress
import socket
from urllib.parse import urljoin, urlparse
from typing import Any

import requests

MAX_RESPONSE_BYTES = 1_000_000


def _safe_addresses(hostname: str) -> list[str]:
    addresses = {item[4][0] for item in socket.getaddrinfo(hostname, None)}
    for address in addresses:
        parsed = ipaddress.ip_address(address)
        if parsed.is_private or parsed.is_loopback or parsed.is_link_local or parsed.is_reserved or parsed.is_unspecified:
            raise ValueError("Website resolves to a private or reserved network address")
    return sorted(addresses)


def inspect_website(url: str) -> dict[str, Any]:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Only absolute HTTP(S) URLs are accepted")
    current = url
    session = requests.Session()
    response = None
    hops = []
    for _ in range(4):
        parsed = urlparse(current)
        _safe_addresses(parsed.hostname)
        response = session.get(current, timeout=(3, 6), allow_redirects=False, headers={"User-Agent": "CyberGuard-Website-Inspector/1.0"}, stream=True)
        hops.append(current)
        if response.is_redirect:
            location = response.headers.get("location")
            if not location:
                break
            current = urljoin(current, location)
            continue
        break
    if response is None:
        raise ValueError("Website request did not produce a response")
    body = bytearray()
    for chunk in response.iter_content(8192):
        body.extend(chunk)
        if len(body) > MAX_RESPONSE_BYTES:
            raise ValueError("Website response exceeded the inspection size limit")
    text = bytes(body).decode(response.encoding or "utf-8", errors="replace")
    lowered = text.lower()
    findings = []
    if "<form" in lowered and ("password" in lowered or 'type="password"' in lowered):
        findings.append("Page contains a credential submission form.")
    if len(hops) > 1:
        findings.append(f"Redirect chain contains {len(hops)} hops.")
    if parsed.scheme != "https":
        findings.append("Page is served without HTTPS transport protection.")
    title = text.split("<title>", 1)[1].split("</title>", 1)[0].strip() if "<title>" in lowered and "</title>" in lowered else ""
    return {"final_url": response.url, "status_code": response.status_code, "redirects": hops, "title": title[:200], "findings": findings, "content_length": len(body), "sample": text[:2000]}
