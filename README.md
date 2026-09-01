# DNSentinel

**AI-Powered DNS Threat Intelligence & Security Gateway**
SIH 2026 — Problem Statement SIH260003: *DNS Filtering Service using Threat Intelligence feeds and AI/ML Techniques*

DNSentinel sits between a client and normal DNS resolution, checks every
domain against threat-intelligence indicators and a local ML model, and
allows, monitors, alerts on, or blocks the request based on a combined
0–100 risk score — with a full explanation of why.

```
Client → DNSentinel → Threat Intel + ML Risk Engine → ALLOW / MONITOR / ALERT / BLOCK
```

## Project structure

```
SIH260003-DNS-Filtering/
├── README.md
├── requirements.txt
├── .gitignore
├── .env.example
├── backend/
│   ├── main.py                  # FastAPI app entrypoint
│   ├── api/                     # dns / threat / dashboard routes
│   ├── core/                    # config + risk engine
│   ├── dns/                     # query normalizer + resolver simulation
│   ├── threat_intelligence/     # feed loading + IOC lookup
│   ├── ml/                      # feature extraction, training, inference
│   ├── database/                # SQLAlchemy models + session
│   └── utils/                   # logging + validation
├── data/                        # threat feed + training CSVs
├── frontend/                    # plain HTML/CSS/JS dashboard (no build step)
├── tests/                       # pytest suite
├── scripts/                     # feed sync, model training, demo seeding
└── docs/                        # architecture, API reference, demo script
```

## Quickstart

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Train the DGA classifier (writes backend/ml/model.pkl)
python scripts/train_model.py

# 3. Start the API
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000

# 4. (Optional) Seed realistic demo traffic so the dashboard isn't empty
python scripts/seed_database.py
```

Then just open **one URL**:

```
http://localhost:8000/
```

This redirects straight into the single-page app (`frontend/index.html`) —
Analyzer, Dashboard, Alerts, Domains and Investigation are all behind one
URL, switched via client-side tabs with no page reloads. Sign-in (top
right) is shared across every tab.

`http://localhost:8000/docs` has the interactive Swagger API docs.

> The old multi-page frontend (separate `dashboard.html`, `alerts.html`,
> etc.) is kept for reference under `frontend/_legacy/` but isn't linked
> anywhere — the single-page app in `frontend/index.html` is the one to use.

## Running tests

```bash
pytest tests/ -v
```

## Advanced features (Phase 5+)

Beyond the MVP core flow, this repo also includes:

- **DNS tunnelling detection** — hybrid rule + IsolationForest anomaly
  detector over aggregated DNS sessions (`backend/detection/`)
- **Passive PCAP/Zeek analysis** — upload a Zeek `dns.log`, get scored
  sessions back (`POST /api/pcap/upload`); a sample log with a
  simulated tunnelling attack is included (`data/sample_zeek_dns.log`)
- **STIX 2.x threat-intel ingestion** — parses real STIX indicator
  objects (`POST /api/threat/feeds/sync-stix`, sample bundle in
  `data/stix_sample_bundle.json`)
- **JWT auth + role-based access control** — three demo roles (admin /
  analyst / viewer); see `docs/api.md` for credentials
- **Analyst feedback loop** — confirm or mark alerts as false-positive
  (`PATCH /api/alerts/{id}`) via the Alerts page

Try the tunnelling detector immediately:
```bash
python -m backend.detection.train_tunnel_model   # fits the IsolationForest baseline (already included)
```
Then open the single-page app (`http://localhost:8000/` or
`http://localhost:8000/app/index.html`), click **Sign in** (top right)
with `analyst/analyst123`, switch to the **Investigation** tab, and
upload `data/sample_zeek_dns.log` — it correctly flags the one
simulated attack session out of 68 total, with zero false positives.

## How a decision is made

1. **Normalize** the domain (TLD, subdomain depth, entropy, keywords) — `backend/dns/filter.py`
2. **Threat-intel check** against synced indicators — `backend/threat_intelligence/`
3. **ML/DGA scoring** via a locally-trained RandomForest classifier — `backend/ml/`
4. **Risk engine** combines all signals into a 0–100 score — `backend/core/risk_engine.py`
   - `0–29` SAFE → ALLOW
   - `30–59` SUSPICIOUS → MONITOR
   - `60–79` HIGH_RISK → ALERT
   - `80–100` MALICIOUS → BLOCK
5. **Resolve/sinkhole** and log the decision with full reasoning — `backend/dns/resolver.py`, `backend/database/models.py`

See `docs/architecture.md` for the full diagram and `docs/api.md` for
every endpoint.

## What this prototype simulates vs. what's real

This is a working MVP built for demo purposes, matching the SIH260003
solution blueprint's Phase 1–4 (DNS gateway → threat intel → database →
ML detection). It genuinely: extracts lexical features, trains a real
scikit-learn model, matches against real (locally-seeded) threat feeds,
computes an explainable risk score, and persists everything to a real
database queried by a real dashboard.

It does **not** yet include: a production DNS server on port 53
(resolution is simulated for portability — no root/socket privileges
needed to run the demo), STIX/TAXII live feed ingestion, DNS-tunnelling
detection, PCAP/Zeek passive analysis, or auth/RBAC. These are exactly
the Phase 5+ items in the original playbook — the architecture here is
built so each one plugs into the existing risk engine without a rewrite.
See `docs/architecture.md` for the gap table and `docs/demo.md` for a
ready-to-use live demo script.

## Team roles (per the playbook's 6-member split)

| Role | Owns |
|---|---|
| DNS / Network Engineer | `backend/dns/`, latency, future CoreDNS/DoH integration |
| Threat Intelligence Engineer | `backend/threat_intelligence/`, future STIX/TAXII |
| ML Engineer | `backend/ml/`, datasets, evaluation |
| Detection / DFIR Engineer | future DNS-tunnelling + PCAP/Zeek modules |
| Backend Engineer | `backend/api/`, `backend/database/`, `backend/core/risk_engine.py` |
| Frontend / DevOps Engineer | `frontend/`, Docker, deployment |
