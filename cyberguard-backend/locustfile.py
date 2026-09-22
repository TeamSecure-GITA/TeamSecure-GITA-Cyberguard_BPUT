from locust import HttpUser, between, task


class CyberGuardLoadUser(HttpUser):
    wait_time = between(1, 3)

    def on_start(self):
        response = self.client.post("/api/v1/auth/login", json={"username": "analyst", "password": "analyst123"})
        self.token = response.json().get("access_token", "")
        self.headers = {"Authorization": f"Bearer {self.token}"}

    @task(3)
    def preview_phishing(self):
        self.client.post("/api/v1/analyze/preview", json={"category": "email", "payload": "Urgent verify credentials at https://secure-login.xyz"}, headers=self.headers)

    @task(1)
    def dashboard_metrics(self):
        self.client.get("/api/v1/dashboard/metrics", headers=self.headers)
