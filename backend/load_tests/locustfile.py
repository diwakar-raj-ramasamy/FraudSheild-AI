"""
FraudShield AI - Production Load and Stress Testing Suite (Locust)
Simulates realistic production traffic across:
  1. Browser Extension users performing live URL scans
  2. Browser Extension reporting threat detection events
  3. Security Analysts querying the Admin Dashboard and Metrics
  4. Administrators uploading forensic files for inspection
"""

import random
import uuid
from locust import HttpUser, task, between, events

TEST_URLS = [
    "https://google.com",
    "https://microsoft.com",
    "https://secure-banking-verify-account.login-auth-portal.com/update",
    "https://metamask-crypto-wallet-verify.online",
    "http://192.168.1.1/admin",
    "https://github.com",
    "https://paypal.com",
    "https://free-crypto-giveaway-airdrop.xyz/claim"
]

class BrowserExtensionUser(HttpUser):
    """Simulates active Chrome Browser Extension clients scanning URLs and reporting detections."""
    wait_time = between(0.1, 0.5)

    def on_start(self):
        self.device_pseudonym = f"ext-load-{uuid.uuid4().hex[:12]}"

    @task(5)
    def scan_url(self):
        url = random.choice(TEST_URLS)
        payload = {
            "url": url,
            "device_pseudonym": self.device_pseudonym,
            "page_title": f"Page Title for {url}",
            "dom_signals": {
                "has_password_field": random.choice([True, False]),
                "has_otp_field": random.choice([True, False]),
                "iframes_count": random.randint(0, 3)
            }
        }
        self.client.post("/api/scan/url", json=payload, name="/api/scan/url")

    @task(2)
    def report_detection(self):
        url = random.choice(TEST_URLS)
        payload = {
            "url": url,
            "device_pseudonym": self.device_pseudonym,
            "risk_score": random.randint(30, 95),
            "classification": random.choice(["CAUTION", "CRITICAL"]),
            "attack_types": ["PHISHING"]
        }
        self.client.post("/api/events/detection", json=payload, name="/api/events/detection")

    @task(1)
    def check_download(self):
        payload = {
            "file_name": random.choice(["invoice.pdf", "statement.exe.pdf", "report.xlsx", "payload.bat.docx"]),
            "download_url": "https://download-mirror.com/file",
            "device_pseudonym": self.device_pseudonym
        }
        self.client.post("/api/downloads/check", json=payload, name="/api/downloads/check")

class AdminDashboardUser(HttpUser):
    """Simulates SOC Analysts and Security Admins querying dashboards and metrics."""
    wait_time = between(0.5, 1.5)

    def on_start(self):
        # Authenticate as Analyst / Admin
        res = self.client.post("/api/auth/login", json={
            "email": "admin@fraudshield.ai",
            "password": "AdminSecurePassword2026!"
        })
        if res.status_code == 200:
            token = res.json().get("access_token")
            self.headers = {"Authorization": f"Bearer {token}"}
        else:
            self.headers = {}

    @task(4)
    def view_metrics(self):
        self.client.get("/api/metrics/overview", headers=self.headers, name="/api/metrics/overview")

    @task(3)
    def list_threats(self):
        self.client.get("/api/threats?limit=20&skip=0", headers=self.headers, name="/api/threats")

    @task(2)
    def list_campaigns(self):
        self.client.get("/api/campaigns?limit=20", headers=self.headers, name="/api/campaigns")

    @task(2)
    def list_alerts(self):
        self.client.get("/api/alerts?limit=20", headers=self.headers, name="/api/alerts")

    @task(1)
    def check_health(self):
        self.client.get("/health/ready", name="/health/ready")

