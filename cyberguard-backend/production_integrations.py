from __future__ import annotations

import os
from typing import Any

import requests


class IntegrationNotConfigured(RuntimeError):
    pass


def _request(method: str, url: str, *, headers: dict[str, str] | None = None, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    response = requests.request(method, url, headers=headers or {}, json=payload, timeout=10)
    response.raise_for_status()
    return response.json() if response.content else {"status": "accepted"}


def _required(*names: str) -> list[str]:
    return [name for name in names if not os.getenv(name)]


def provider_status() -> dict[str, dict[str, Any]]:
    return {
        "cloudflare": {"configured": bool(os.getenv("CLOUDFLARE_API_TOKEN") and os.getenv("CLOUDFLARE_ZONE_ID"))},
        "siem": {"configured": bool(os.getenv("CYBERGUARD_SIEM_URL"))},
        "jira": {"configured": bool(os.getenv("CYBERGUARD_JIRA_URL") and os.getenv("CYBERGUARD_JIRA_TOKEN") and os.getenv("CYBERGUARD_JIRA_PROJECT"))},
        "servicenow": {"configured": bool(os.getenv("CYBERGUARD_SERVICENOW_URL") and os.getenv("CYBERGUARD_SERVICENOW_TOKEN"))},
        "microsoft_graph": {"configured": bool(os.getenv("CYBERGUARD_GRAPH_TOKEN"))},
        "okta": {"configured": bool(os.getenv("CYBERGUARD_OKTA_URL") and os.getenv("CYBERGUARD_OKTA_TOKEN"))},
        "edr": {"configured": bool(os.getenv("CYBERGUARD_EDR_URL") and os.getenv("CYBERGUARD_EDR_TOKEN"))},
        "secret_manager": {"configured": bool(os.getenv("CYBERGUARD_SECRET_MANAGER"))},
        "postgresql": {"configured": os.getenv("CYBERGUARD_DATABASE_URL", "").startswith(("postgresql://", "postgres://"))},
        "observability": {"configured": bool(os.getenv("CYBERGUARD_OTEL_ENDPOINT") or os.getenv("CYBERGUARD_METRICS_PUSH_URL"))},
    }


def create_ticket(payload: dict[str, Any]) -> dict[str, Any]:
    if os.getenv("CYBERGUARD_JIRA_URL"):
        missing = _required("CYBERGUARD_JIRA_TOKEN", "CYBERGUARD_JIRA_PROJECT")
        if missing:
            raise IntegrationNotConfigured(f"Missing Jira settings: {', '.join(missing)}")
        url = os.getenv("CYBERGUARD_JIRA_URL", "").rstrip("/") + "/rest/api/3/issue"
        body = {"fields": {"project": {"key": os.environ["CYBERGUARD_JIRA_PROJECT"]}, "summary": payload.get("summary", "CyberGuard security incident"), "description": payload.get("description", ""), "issuetype": {"name": os.getenv("CYBERGUARD_JIRA_ISSUE_TYPE", "Task")}}}
        result = _request("POST", url, headers={"Authorization": f"Bearer {os.environ['CYBERGUARD_JIRA_TOKEN']}", "Content-Type": "application/json"}, payload=body)
        return {"provider": "jira", "status": "created", "result": result}
    if os.getenv("CYBERGUARD_SERVICENOW_URL"):
        missing = _required("CYBERGUARD_SERVICENOW_TOKEN")
        if missing:
            raise IntegrationNotConfigured(f"Missing ServiceNow settings: {', '.join(missing)}")
        url = os.getenv("CYBERGUARD_SERVICENOW_URL", "").rstrip("/") + "/api/now/table/incident"
        result = _request("POST", url, headers={"Authorization": f"Bearer {os.environ['CYBERGUARD_SERVICENOW_TOKEN']}", "Content-Type": "application/json", "Accept": "application/json"}, payload={"short_description": payload.get("summary", "CyberGuard security incident"), "description": payload.get("description", ""), "urgency": str(payload.get("urgency", "2"))})
        return {"provider": "servicenow", "status": "created", "result": result}
    raise IntegrationNotConfigured("Configure Jira or ServiceNow before creating tickets")


def disable_identity(identity: str) -> dict[str, Any]:
    if os.getenv("CYBERGUARD_OKTA_URL"):
        missing = _required("CYBERGUARD_OKTA_TOKEN")
        if missing:
            raise IntegrationNotConfigured(f"Missing Okta settings: {', '.join(missing)}")
        url = os.getenv("CYBERGUARD_OKTA_URL", "").rstrip("/") + f"/api/v1/users/{identity}/lifecycle/suspend"
        result = _request("POST", url, headers={"Authorization": f"SSWS {os.environ['CYBERGUARD_OKTA_TOKEN']}", "Accept": "application/json"})
        return {"provider": "okta", "status": "suspended", "identity": identity, "result": result}
    if os.getenv("CYBERGUARD_GRAPH_TOKEN"):
        url = f"https://graph.microsoft.com/v1.0/users/{identity}"
        result = _request("PATCH", url, headers={"Authorization": f"Bearer {os.environ['CYBERGUARD_GRAPH_TOKEN']}", "Content-Type": "application/json"}, payload={"accountEnabled": False})
        return {"provider": "microsoft_graph", "status": "disabled", "identity": identity, "result": result}
    raise IntegrationNotConfigured("Configure Okta or Microsoft Graph before disabling identities")


def isolate_endpoint(endpoint_id: str) -> dict[str, Any]:
    missing = _required("CYBERGUARD_EDR_URL", "CYBERGUARD_EDR_TOKEN")
    if missing:
        raise IntegrationNotConfigured(f"Missing EDR settings: {', '.join(missing)}")
    url = os.getenv("CYBERGUARD_EDR_URL", "").rstrip("/") + "/endpoints/isolate"
    result = _request("POST", url, headers={"Authorization": f"Bearer {os.environ['CYBERGUARD_EDR_TOKEN']}", "Content-Type": "application/json"}, payload={"endpoint_id": endpoint_id, "reason": "CyberGuard prevention containment"})
    return {"provider": "edr", "status": "isolated", "endpoint_id": endpoint_id, "result": result}
