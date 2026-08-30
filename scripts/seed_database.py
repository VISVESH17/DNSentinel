"""
Seeds the database with realistic demo DNS traffic by calling the running
API's /api/dns/check endpoint repeatedly with a mix of benign and
malicious domains. Use this right before a live demo or judge walkthrough
so the dashboard has data to show immediately.

Prerequisite: the API must already be running:
    uvicorn backend.main:app --reload

Run with: python scripts/seed_database.py
"""
import random
import time

import httpx

API_BASE = "http://localhost:8000"

BENIGN_DOMAINS = [
    "google.com", "youtube.com", "wikipedia.org", "github.com",
    "stackoverflow.com", "amazon.com", "reddit.com", "netflix.com",
]

KNOWN_THREATS = [
    "malware-drop-93827.xyz", "c2-panel-relay.top",
    "phishing-login-verify-secure.click", "fake-bank-login-alert.work",
    "botnet-cnc-node7.tk",
]

DGA_LIKE = [
    "xj29akd9-login.com", "qw8z1x9v7k2.info", "kf83jd0alz19.biz",
    "zxq9plw3nfk7.xyz", "vb7mqz1x0plk9.top",
]

CLIENT_IPS = ["192.168.1.12", "192.168.1.34", "192.168.1.56", "10.0.0.21"]


def seed(n_requests: int = 60):
    with httpx.Client(timeout=10) as client:
        # Make sure threat feeds are synced first
        sync = client.post(f"{API_BASE}/api/threat/feeds/sync")
        print(f"Feed sync: {sync.json()}")

        all_domains = (
            BENIGN_DOMAINS * 4 + KNOWN_THREATS * 2 + DGA_LIKE * 2
        )
        random.shuffle(all_domains)

        for i in range(n_requests):
            domain = random.choice(all_domains)
            client_ip = random.choice(CLIENT_IPS)
            try:
                res = client.post(
                    f"{API_BASE}/api/dns/check",
                    json={"domain": domain, "client_ip": client_ip},
                )
                data = res.json()
                print(f"[{i+1}/{n_requests}] {domain:<40} -> {data.get('action', 'ERROR')}")
            except Exception as exc:
                print(f"[{i+1}/{n_requests}] {domain:<40} -> FAILED ({exc})")
            time.sleep(0.05)

    print("\nSeeding complete. Open frontend/dashboard.html to see the results.")


if __name__ == "__main__":
    seed()
