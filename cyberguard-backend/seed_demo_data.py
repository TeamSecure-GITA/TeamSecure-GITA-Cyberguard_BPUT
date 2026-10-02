# seed_demo_data.py
import os

import requests

API_URL = "http://127.0.0.1:8000/api/v1/analyze"
LOGIN_URL = "http://127.0.0.1:8000/api/v1/auth/login"

demo_scenarios = [
    {
        "name": "Scenario 1: Deepfake Authority Message",
        "category": "deepfake",
        "payload": "Voice clone of the finance director uses synthetic speech to request an urgent transfer."
    },
    {
        "name": "Scenario 2: Behavioural Account Takeover",
        "category": "ato",
        "payload": '{"failed_attempts": 12, "total_attempts": 15, "distinct_accounts": 8, "distinct_countries": 2, "impossible_travel": true, "new_device": true, "mfa_denials": 4}'
    },
    {
        "name": "Scenario 3: Look-alike URL and Contact Mismatch",
        "category": "url",
        "payload": "From: registrar@gmail.com urgently verify at https://micros0ft-login.xyz/auth?redirect=https://evil.example/login"
    }
]

def run_demo_seed():
    print("--- Seeding CYBERGUARD AI Engine Demo Data ---")
    password = os.getenv("CYBERGUARD_DEMO_ANALYST_PASSWORD", "")
    if not password:
        raise RuntimeError("Set CYBERGUARD_DEMO_ANALYST_PASSWORD to the configured analyst account password.")
    login = requests.post(LOGIN_URL, json={"username": "analyst", "password": password}, timeout=10)
    login.raise_for_status()
    token = login.json().get("access_token")
    if not token:
        raise RuntimeError("The configured analyst account did not return an access token.")
    headers = {"Authorization": f"Bearer {token}"}
    for scenario in demo_scenarios:
        response = requests.post(
            API_URL,
            json={"category": scenario["category"], "payload": scenario["payload"]},
            headers=headers,
            timeout=10,
        )
        response.raise_for_status()
        data = response.json()["assessment"]
        print(f"[SUCCESS] {scenario['name']}")
        print(f"          Risk Level: {data['risk_level']} ({data['risk_score']}%)")
        print(f"          XAI Explanation: {data['xai_explanation']}\n")

if __name__ == "__main__":
    run_demo_seed()