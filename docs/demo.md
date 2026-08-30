# DNSentinel — Live Demo Script

Adapted from the SIH260003 winning-playbook demo flow. Aim for ~5–7
minutes; rehearse the timing.

## Setup (before judges arrive)
1. `pip install -r requirements.txt`
2. `python scripts/train_model.py` (trains the DGA classifier)
3. `uvicorn backend.main:app --reload` (starts the API on :8000)
4. `python scripts/seed_database.py` (populates realistic demo traffic)
5. Open `frontend/dashboard.html` and `frontend/index.html` in two tabs

## Script

**1. Start with the threat, not the dashboard.**
Open `index.html`. Say: "Every DNS request in a network passes through
here before resolution." Type a normal domain (`google.com`) — show it
resolves instantly, ALLOW, risk score 0.

**2. Trigger a known threat-intel match.**
Type `malware-drop-93827.xyz` (already in `data/threat_feed.csv`).
Point out the response: BLOCK, sinkhole IP `10.10.10.10`, and the
`reasons` list showing exactly which indicator matched and why.

**3. Trigger DGA/ML detection on an unknown domain.**
Type a domain not in any feed, e.g. `zxq9plw3nfk7.xyz`. Show the ML
probability and entropy signal driving the score — "this was never in
a threat feed; our local model caught it from its structure alone."

**4. Show the dashboard.**
Switch to `dashboard.html`. Point out: total queries, block count,
the requests-over-time chart, and the top-blocked-domains table
populated by `scripts/seed_database.py`.

**5. Show the alerts page.**
Switch to `alerts.html`. Show that every ALERT/BLOCK decision is
logged with a timestamp, client IP and severity — the beginning of an
investigation workflow.

**6. Show performance.**
Mention the average latency stat on the dashboard: "sub-15ms decisions
because the live path never makes a remote call — threat feeds sync
asynchronously in the background."

**7. Close with what's next.**
"This MVP covers the core flow: DNS query → threat intel → ML → risk
score → block. The full roadmap adds STIX/TAXII ingestion, DNS
tunnelling detection via Isolation Forest, and passive PCAP/Zeek
investigation — all reusing this same risk engine."

## Judge-facing one-liner
"We're not building another blacklist. DNSentinel correlates known
threat intelligence with explainable ML, makes a fast policy decision
at the DNS control point, and shows exactly why."
