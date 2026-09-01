# DNSentinel — Architecture

## Problem statement
SIH260003 — DNS Filtering Service using Threat Intelligence feeds and AI/ML Techniques.

## High-level flow

```
Client
  │
  ▼
DNS Check API (POST /api/dns/check)
  │
  ├─► Query Normalizer (backend/dns/filter.py)
  │      - lowercases/strips domain, extracts TLD, subdomain depth,
  │        entropy, suspicious keywords/TLD
  │
  ├─► Threat Intelligence Check (backend/threat_intelligence/threat_checker.py)
  │      - lookup against synced indicators (backend/database/models.py::ThreatIndicator)
  │      - indicators are loaded from data/*.csv via feed_loader.py
  │        (stand-in for a real STIX/TAXII sync job)
  │
  ├─► ML / DGA Detection (backend/ml/predict.py)
  │      - lexical feature extraction (backend/ml/feature_extractor.py)
  │      - RandomForest classifier trained via backend/ml/train.py
  │      - falls back to an explainable heuristic if no model is trained yet
  │
  ├─► Risk Engine (backend/core/risk_engine.py)
  │      - combines TI confidence + DGA probability + entropy anomaly
  │        + tunnelling indicators into a 0-100 score
  │      - maps score -> SAFE/SUSPICIOUS/HIGH_RISK/MALICIOUS
  │        -> ALLOW/MONITOR/ALERT/BLOCK
  │
  ├─► Resolver (backend/dns/resolver.py)
  │      - simulates resolution: real-looking IP on ALLOW,
  │        sinkhole IP (10.10.10.10) on BLOCK
  │
  └─► Persistence (backend/database/models.py)
         - DNSQuery, Detection, Domain, Alert rows written per request
         - powers the dashboard stats API (backend/api/dashboard_routes.py)
```

## Why this design

- **The live DNS path never calls a remote API.** Threat-intel feeds sync
  asynchronously (`POST /api/threat/feeds/sync`) into the local database;
  the check endpoint only ever reads from local SQLite. This keeps
  decision latency low and demoable without internet dependency.
- **ML inference is local and lightweight.** RandomForest (or XGBoost, per
  the original playbook) on ~10 lexical features runs in milliseconds
  with no GPU requirement.
- **Explainability is built in, not bolted on.** `RiskResult.reasons`
  lists exactly which signals contributed to a decision and by how much
  — this is what the frontend's analyzer page and the alerts page surface
  to a judge or SOC analyst.

## Advanced modules (Phase 5+)

Beyond the MVP core flow, this repo also implements:

- **DNS tunnelling detection** (`backend/detection/tunnel_detector.py`) —
  a hybrid detector combining explainable rule/threshold checks with an
  `IsolationForest` fitted on synthetic baseline "normal" session
  behaviour (`backend/detection/train_tunnel_model.py`). Works on
  aggregated `(client_ip, base_domain)` sessions, not single queries,
  matching the playbook's design. A ML-only flag with no corroborating
  rule flag is treated as too noisy to act on alone -- see the
  `suspected = is_anomaly and len(rule_flags) >= 1` logic in
  `TunnelAnomalyDetector.score()`.

- **Passive PCAP/Zeek analysis** (`backend/pcap/zeek_parser.py`,
  `POST /api/pcap/upload`) — parses Zeek's native tab-separated
  `dns.log` format, groups records into sessions, and runs them through
  the same tunnel detector. `data/sample_zeek_dns.log` contains 230
  synthetic DNS records: ~80 normal background queries plus a simulated
  150-query tunnelling attack (base32-encoded payloads in subdomains to
  a single attacker domain) — the detector correctly flags only that
  one session.

- **STIX 2.x ingestion** (`backend/threat_intelligence/stix_parser.py`,
  `POST /api/threat/feeds/sync-stix`) — parses real STIX 2.x `indicator`
  SDOs (domain-name/ipv4-addr/url patterns) from a bundle
  (`data/stix_sample_bundle.json`) and normalizes them into the same
  `ThreatIndicator` table the CSV feeds use. Swap `load_bundle_from_file`
  for a `taxii2-client` poll against a real TAXII collection once the
  team has server credentials -- the normalization and DB layer are
  identical either way.

- **JWT auth + RBAC** (`backend/auth/security.py`) — three demo roles
  (`admin`, `analyst`, `viewer`). Feed sync, PCAP upload, and alert
  status changes require `admin` or `analyst`; read-only alert/PCAP
  history is available to all three. See `docs/api.md` for demo
  credentials.

- **Analyst feedback loop** (`PATCH /api/alerts/{id}`) — analysts mark
  alerts `resolved` or `false_positive`. In a real deployment this
  feedback would be appended to the training dataset for the next
  DGA/tunnel model retrain (noted inline in `backend/api/alert_routes.py`).

## What's still a simulation vs. production-ready in this prototype

| Component | Prototype (this repo) | Full deployment |
|---|---|---|
| DNS resolution | Simulated in `resolver.py` (fake IP / sinkhole) | Real CoreDNS/Unbound integration, UDP port 53, DoH/DoT |
| Threat feeds | Static CSVs + a sample STIX bundle in `/data` | Live STIX/TAXII 2.x client polling a real collection on a scheduler |
| Database | SQLite | PostgreSQL + Redis hot cache |
| DNS tunnelling baseline | Synthetic "normal" sessions | Fitted on real captured baseline traffic (e.g. a clean period of Zeek logs) |
| Auth user store | In-memory demo users (3 accounts) | Real user table + hashed passwords + audit log |
| PCAP results storage | In-memory dict (resets on restart) | Persisted table, linked to the `detections`/`alerts` schema |

See the roadmap in the original SIH260003 playbook for further hardening
items (DoH/DoT, rate limiting, ClickHouse at scale, etc).

## Module-to-file map

| Playbook module | File(s) |
|---|---|
| DNS Gateway | `backend/dns/resolver.py`, `backend/api/dns_routes.py` |
| Query Normalizer | `backend/dns/filter.py` |
| Threat Intelligence Engine | `backend/threat_intelligence/feed_loader.py`, `feeds.py` |
| IOC Cache/Lookup | `backend/threat_intelligence/threat_checker.py` |
| DGA Detection | `backend/ml/feature_extractor.py`, `train.py`, `predict.py` |
| Risk Engine | `backend/core/risk_engine.py` |
| Policy Engine | Encoded inside `risk_engine.py::_classify` |
| SOC Dashboard | `frontend/index.html` (Dashboard tab), `backend/api/dashboard_routes.py` |
| Investigation & Feedback | `frontend/index.html` (Alerts/Investigation tabs), `frontend/js/app.js` (evidence shown via `reasons`) |
