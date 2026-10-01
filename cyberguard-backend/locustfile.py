import os

from locust import HttpUser, between, task


class CyberGuardLoadUser(HttpUser):
    wait_time = between(1, 3)

    def on_start(self):
        username = os.getenv("CYBERGUARD_LOAD_TEST_USERNAME", "")
        password = os.getenv("CYBERGUARD_LOAD_TEST_PASSWORD", "")
        if not username or not password:
            raise RuntimeError("Set CYBERGUARD_LOAD_TEST_USERNAME and CYBERGUARD_LOAD_TEST_PASSWORD before running Locust.")
        response = self.client.post(
            "/api/v1/auth/login",
            json={"username": username, "password": password},
        )
        response.raise_for_status()
        self.token = response.json().get("access_token")
        if not self.token:
            raise RuntimeError("The configured load-test user did not return an access token.")
        self.headers = {"Authorization": f"Bearer {self.token}"}

    @task(3)
    def preview_phishing(self):
        self.client.post("/api/v1/analyze/preview", json={"category": "email", "payload": "Urgent verify credentials at https://secure-login.xyz"}, headers=self.headers)

    @task(1)
    def dashboard_metrics(self):
        self.client.get("/api/v1/dashboard/metrics", headers=self.headers)
