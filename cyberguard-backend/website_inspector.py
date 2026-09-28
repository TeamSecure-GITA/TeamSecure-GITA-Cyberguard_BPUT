import ipaddress
import socket
from urllib.parse import urljoin, urlparse
from typing import Any

import requests
from requests.adapters import HTTPAdapter

MAX_RESPONSE_BYTES = 1_000_000


class _PinnedAddressAdapter(HTTPAdapter):
    def __init__(self, hostname: str, address: str, port: int):
        self.hostname = hostname.rstrip(".")
        self.address = address
        self.port = port
        host_label = f"[{self.hostname}]" if ":" in self.hostname else self.hostname
        self.host_header = host_label if port in {80, 443} else f"{host_label}:{port}"
        super().__init__(max_retries=0)

    def get_connection_with_tls_context(self, request, verify, proxies=None, cert=None):
        if proxies and any(proxies.values()):
            raise ValueError("Proxy routing is disabled for SSRF-safe website inspection")
        host_params, pool_kwargs = self.build_connection_pool_key_attributes(request, verify, cert)
        host_params["host"] = f"[{self.address}]" if ":" in self.address else self.address
        host_params["port"] = self.port
        if host_params["scheme"] == "https":
            pool_kwargs["assert_hostname"] = self.hostname
            pool_kwargs["server_hostname"] = self.hostname
        return self.poolmanager.connection_from_host(**host_params, pool_kwargs=pool_kwargs)

    def send(self, request, **kwargs):
        request.headers["Host"] = self.host_header
        return super().send(request, **kwargs)


def _safe_addresses(hostname: str) -> list[str]:
    addresses = {item[4][0] for item in socket.getaddrinfo(hostname, None)}
    if not addresses:
        raise ValueError("Website hostname did not resolve to an address")
    for address in addresses:
        parsed = ipaddress.ip_address(address)
        if not parsed.is_global:
            raise ValueError("Website resolves to a non-public network address")
    return sorted(addresses)


def inspect_website(url: str) -> dict[str, Any]:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Only absolute HTTP(S) URLs are accepted")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URLs containing embedded credentials are not accepted")
    current = url
    session = requests.Session()
    session.trust_env = False
    response = None
    hops = []
    try:
        for hop_index in range(4):
            parsed = urlparse(current)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username is not None or parsed.password is not None:
                raise ValueError("Redirect target must be an absolute HTTP(S) URL without embedded credentials")
            addresses = _safe_addresses(parsed.hostname)
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            adapter_prefix = f"{parsed.scheme}://"
            old_adapter = session.adapters.get(adapter_prefix)
            session.mount(adapter_prefix, _PinnedAddressAdapter(parsed.hostname, addresses[0], port))
            if old_adapter is not None:
                old_adapter.close()
            response = session.get(current, timeout=(3, 6), allow_redirects=False, headers={"User-Agent": "CyberGuard-Website-Inspector/1.0"}, stream=True)
            hops.append(current)
            if not response.is_redirect:
                break
            location = response.headers.get("location")
            response.close()
            response = None
            if not location:
                raise ValueError("Website returned a redirect without a destination")
            if hop_index == 3:
                raise ValueError("Website redirect chain exceeded the inspection limit")
            current = urljoin(current, location)
        if response is None:
            raise ValueError("Website request did not produce a final response")
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
        if urlparse(response.url).scheme != "https":
            findings.append("Page is served without HTTPS transport protection.")
        title = text.split("<title>", 1)[1].split("</title>", 1)[0].strip() if "<title>" in lowered and "</title>" in lowered else ""
        return {"final_url": response.url, "status_code": response.status_code, "redirects": hops, "title": title[:200], "findings": findings, "content_length": len(body), "sample": text[:2000]}
    finally:
        if response is not None:
            response.close()
        session.close()
