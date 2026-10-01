import ipaddress
import json
import os
import ssl
import socket
import re
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import quote, urljoin, urlparse
from typing import Any

import requests
import tldextract
from requests.adapters import HTTPAdapter
from detection_engine import BRAND_DOMAINS

MAX_RESPONSE_BYTES = 1_000_000
MAX_CT_RESPONSE_BYTES = 512_000
RDAP_ENABLED = os.getenv("CYBERGUARD_ENABLE_RDAP", "false").lower() in {"1", "true", "yes"}
CT_ENABLED = os.getenv("CYBERGUARD_ENABLE_CT", "true").lower() in {"1", "true", "yes"}
TRUSTED_BRAND_VARIANTS = {
    "google": {"google.com", "google.co.in"},
    "sbi": {"sbi.co.in", "onlinesbi.sbi"},
    "amazon": {"amazon.com", "amazon.in"},
}


class _PageIdentityParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text = []
        self.identity_attributes = []
        self.form_actions = []
        self.credential_form = False
        self.in_title = False
        self.in_nonvisible_element = 0

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == "title":
            self.in_title = True
        if tag in {"script", "style", "noscript"}:
            self.in_nonvisible_element += 1
        if tag == "form":
            self.form_actions.append(attributes.get("action", ""))
        if tag == "input" and attributes.get("type", "").lower() == "password":
            self.credential_form = True
        for key in ("alt", "title"):
            if attributes.get(key):
                self.identity_attributes.append(attributes[key])
        if tag == "meta" and attributes.get("property", "").lower() == "og:site_name" and attributes.get("content"):
            self.identity_attributes.append(attributes["content"])

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False
        if tag in {"script", "style", "noscript"} and self.in_nonvisible_element:
            self.in_nonvisible_element -= 1

    def handle_data(self, data):
        if not self.in_nonvisible_element and data.strip():
            self.text.append(data.strip())
            if self.in_title:
                self.identity_attributes.append(data.strip())


def _registered_domain(hostname: str) -> str:
    extracted = tldextract.extract(hostname)
    return f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else hostname.lower().rstrip(".")


def analyze_page_identity(final_url: str, page_html: str) -> dict[str, Any]:
    parser = _PageIdentityParser()
    parser.feed(page_html)
    parser.close()
    page_domain = _registered_domain(urlparse(final_url).hostname or "")
    identity_text = " ".join(parser.text + parser.identity_attributes).lower()
    claimed_brands = []
    mismatches = []
    for brand, trusted_domain in BRAND_DOMAINS.items():
        if re.search(rf"\b{re.escape(brand)}\b", identity_text):
            claimed_brands.append(brand)
            trusted_hosts = TRUSTED_BRAND_VARIANTS.get(brand, {trusted_domain})
            if not any(page_domain == host or page_domain.endswith("." + host) for host in trusted_hosts):
                mismatches.append(brand)
    action_hosts = []
    for action in parser.form_actions:
        action_host = urlparse(urljoin(final_url, action)).hostname
        if action_host and _registered_domain(action_host) != page_domain:
            action_hosts.append(action_host)
    return {
        "credential_form": parser.credential_form,
        "claimed_brands": sorted(set(claimed_brands)),
        "brand_mismatches": mismatches,
        "cross_origin_form_actions": sorted(set(action_hosts)),
    }


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


def _certificate_details(hostname: str, address: str, port: int) -> dict[str, Any]:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((address, port), timeout=4) as connection:
            with context.wrap_socket(connection, server_hostname=hostname) as secure_connection:
                certificate = secure_connection.getpeercert()
        issued_timestamp = ssl.cert_time_to_seconds(certificate["notBefore"])
        expiry_timestamp = ssl.cert_time_to_seconds(certificate["notAfter"])
        now = datetime.now(timezone.utc).timestamp()
        issuer = ", ".join(f"{key}={value}" for group in certificate.get("issuer", ()) for key, value in group)
        return {
            "status": "verified",
            "verified": True,
            "issuer": issuer,
            "issued_at": datetime.fromtimestamp(issued_timestamp, timezone.utc).isoformat(),
            "expires_at": datetime.fromtimestamp(expiry_timestamp, timezone.utc).isoformat(),
            "age_days": max(0, int((now - issued_timestamp) // 86400)),
            "days_remaining": int((expiry_timestamp - now) // 86400),
        }
    except (KeyError, OSError, ssl.SSLError, ValueError):
        return {"status": "unavailable", "verified": False, "issuer": None, "issued_at": None, "expires_at": None, "age_days": None, "days_remaining": None}


def _domain_registration(domain: str) -> dict[str, Any]:
    if not RDAP_ENABLED:
        return {"status": "disabled", "available": False, "registered_at": None, "age_days": None}
    session = requests.Session()
    session.trust_env = False
    current = f"https://rdap.org/domain/{quote(domain, safe='')}"
    response = None
    try:
        for redirect_count in range(4):
            parsed = urlparse(current)
            if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
                raise ValueError("RDAP redirect must use a public HTTPS host")
            addresses = _safe_addresses(parsed.hostname)
            port = parsed.port or 443
            old_adapter = session.adapters.get("https://")
            session.mount("https://", _PinnedAddressAdapter(parsed.hostname, addresses[0], port))
            if old_adapter is not None:
                old_adapter.close()
            response = session.get(current, timeout=(3, 5), allow_redirects=False, stream=True, headers={"Accept": "application/rdap+json, application/json"})
            if response.is_redirect:
                location = response.headers.get("location")
                response.close()
                response = None
                if not location or redirect_count == 3:
                    raise ValueError("RDAP redirect chain could not be followed safely")
                current = urljoin(current, location)
                continue
            response.raise_for_status()
            body = bytearray()
            for chunk in response.iter_content(8192):
                body.extend(chunk)
                if len(body) > MAX_RESPONSE_BYTES:
                    raise ValueError("RDAP response exceeded the inspection size limit")
            registration_date = next((event.get("eventDate") for event in json.loads(body).get("events", []) if event.get("eventAction", "").lower() in {"registration", "registered"}), None)
            if not registration_date:
                return {"status": "missing_registration_event", "available": True, "registered_at": None, "age_days": None}
            registered_at = datetime.fromisoformat(registration_date.replace("Z", "+00:00"))
            age_days = max(0, (datetime.now(timezone.utc) - registered_at.astimezone(timezone.utc)).days)
            return {"status": "available", "available": True, "registered_at": registered_at.isoformat(), "age_days": age_days}
        raise ValueError("RDAP response did not resolve to a domain record")
    except (OSError, requests.RequestException, ValueError, json.JSONDecodeError):
        return {"status": "unavailable", "available": False, "registered_at": None, "age_days": None}
    finally:
        if response is not None:
            response.close()
        session.close()


def _certificate_transparency(domain: str) -> dict[str, Any]:
    if not CT_ENABLED:
        return {"status": "disabled", "available": False, "certificate_count": 0, "matching_names": []}

    hostname = domain.lower().rstrip(".")
    if not hostname or len(hostname) > 253 or not re.fullmatch(r"(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", hostname):
        return {"status": "invalid_domain", "available": False, "certificate_count": 0, "matching_names": []}

    providers = (
        (
            "crt.sh",
            "crt.sh",
            f"https://crt.sh/?q=%25.{quote(hostname, safe='')}&output=json",
            lambda record: record.get("name_value", "").splitlines() if isinstance(record.get("name_value"), str) else [],
        ),
        (
            "certspotter",
            "api.certspotter.com",
            f"https://api.certspotter.com/v1/issuances?domain={quote(hostname, safe='')}&include_subdomains=true&expand=dns_names",
            lambda record: record.get("dns_names", []) if isinstance(record.get("dns_names"), list) else [],
        ),
    )
    redirect_rejected = False
    for provider_name, provider_host, url, extract_names in providers:
        session = None
        response = None
        try:
            addresses = _safe_addresses(provider_host)
            session = requests.Session()
            session.trust_env = False
            session.mount("https://", _PinnedAddressAdapter(provider_host, addresses[0], 443))
            response = session.get(
                url,
                timeout=(3, 5),
                allow_redirects=False,
                stream=True,
                headers={"Accept": "application/json"},
            )
            if response.is_redirect:
                redirect_rejected = True
                continue
            response.raise_for_status()
            body = bytearray()
            for chunk in response.iter_content(8192):
                body.extend(chunk)
                if len(body) > MAX_CT_RESPONSE_BYTES:
                    raise ValueError("Certificate Transparency response exceeded the inspection size limit")
            records = json.loads(body)
            if not isinstance(records, list):
                raise ValueError("Certificate Transparency response was not a JSON list")
            matching_names = set()
            for record in records:
                if not isinstance(record, dict):
                    continue
                for name in extract_names(record):
                    if not isinstance(name, str):
                        continue
                    normalized = name.strip().lower().lstrip("*.").rstrip(".")
                    if normalized == hostname or normalized.endswith("." + hostname):
                        matching_names.add(normalized)
            return {
                "status": "available",
                "available": True,
                "provider": provider_name,
                "certificate_count": len(records),
                "matching_names": sorted(matching_names)[:100],
            }
        except (OSError, requests.RequestException, ValueError, json.JSONDecodeError):
            continue
        finally:
            if response is not None:
                response.close()
            if session is not None:
                session.close()
    return {
        "status": "redirect_rejected" if redirect_rejected else "unavailable",
        "available": False,
        "certificate_count": 0,
        "matching_names": [],
    }


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
        final_parsed = urlparse(response.url)
        page_identity = analyze_page_identity(response.url, text)
        tls_certificate = _certificate_details(final_parsed.hostname, addresses[0], final_parsed.port or 443) if final_parsed.scheme == "https" else None
        domain_registration = _domain_registration(final_parsed.hostname) if final_parsed.scheme == "https" else {"status": "not_applicable", "available": False, "registered_at": None, "age_days": None}
        certificate_transparency = _certificate_transparency(final_parsed.hostname) if final_parsed.scheme == "https" else {"status": "not_applicable", "available": False, "certificate_count": 0, "matching_names": []}
        if tls_certificate and tls_certificate["days_remaining"] is not None and tls_certificate["days_remaining"] <= 14:
            findings.append(f"TLS certificate expires in {tls_certificate['days_remaining']} days.")
        if domain_registration["age_days"] is not None and domain_registration["age_days"] <= 30:
            findings.append(f"Domain was registered recently ({domain_registration['age_days']} days ago).")
        if certificate_transparency["available"]:
            findings.append(f"Certificate Transparency returned {certificate_transparency['certificate_count']} certificate record(s) for this domain.")
        if page_identity["credential_form"] and page_identity["brand_mismatches"]:
            findings.append(f"Credential form claims brand identities hosted on an unrelated domain: {', '.join(page_identity['brand_mismatches'])}.")
        if page_identity["credential_form"] and page_identity["cross_origin_form_actions"]:
            findings.append("Credential form submits to a different registered domain.")
        return {"final_url": response.url, "status_code": response.status_code, "redirects": hops, "title": title[:200], "findings": findings, "content_length": len(body), "sample": text[:2000], "tls_certificate": tls_certificate, "domain_registration": domain_registration, "certificate_transparency": certificate_transparency, **page_identity}
    finally:
        if response is not None:
            response.close()
        session.close()
