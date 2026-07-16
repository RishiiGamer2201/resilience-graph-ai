# PRD — Resilience Graph AI

**Event:** ET AI Hackathon 2026 · **Problem Statement:** PS7 — AI-Driven Cyber Resilience for Critical National Infrastructure
**One-liner:** Detect low-and-slow attacks in real infrastructure logs, connect weak signals into an explainable MITRE ATT&CK attack chain, predict the attacker's next moves, name the likely actor, and recommend gated containment — cutting detection time from weeks to minutes.

---

## What To Build

An AI-augmented SOC (Security Operations Center) layer with **two engines** feeding a **shared spine**, presented through a **SOC Command Center** web app.

| Piece | What it does | Scoring axis |
|---|---|---|
| **Engine 1 — Real Detection** | Unsupervised anomaly / lateral-movement detection on real data (CIC-IDS2017, LANL, UNSW-NB15), evaluated against LANL's real red-team ground truth | Technical Excellence (20%) |
| **Engine 2 — Prediction + Attribution** | Predicts the attacker's next ATT&CK technique(s) (Markov, shipped) and ranks the likely APT group (transparent profile retrieval) | Innovation (25%) |
| **Shared spine** | normalize → correlate alerts into ONE incident → ATT&CK map → attack-path graph (choke points, blast radius) → confidence-gated SOAR | UX + Business Impact |
| **SOC Command Center** | FastAPI + React demo app: 6 screens, pre-cached data + 2 live model endpoints, audit-ready incident report | UX (15%) |

## Target Users

- **Primary (demo persona):** SOC analyst at a critical-infrastructure operator (power grid / government). Drowning in per-event alerts; needs one correlated incident story, the attack path, what's next, and what to do.
- **Secondary:** SOC lead / CISO — consumes the audit-ready incident report, MTTD metrics, and gated response recommendations.
- **Actual audience:** hackathon judges — every claim must survive an ML-literate Q&A (see honesty rules in [rules.md](rules.md)).

## Features

### Detection (Engine 1)
- Benign-only IsolationForest + autoencoder on CIC-IDS2017 flows (PR-AUC 0.570 best, lift over random + rule baselines).
- LANL lateral-movement detector: 7 behavioral auth features, **ROC-AUC 0.988** vs 702 real red-team events; NTLM-ablation robustness (0.929 behavioral-only).
- UNSW-NB15 second benchmark (ROC-AUC 0.829, official split preserved).

### Prediction & attribution (Engine 2)
- Next-technique prediction: first-order Markov over 199 ATT&CK group/campaign sequences + 4 manual CERT-In sequences. Top-3 38.6%; **4.7× the kill-chain-order baseline** (anti-circularity proof). LSTM kept as documented negative result.
- Actor attribution: transparent ranking over 172 ATT&CK group profiles (coverage 55% + Jaccard 20% + semantic similarity 25%), templated auditable justification. NOT a trained classifier.

### Shared spine
- 12-field common event schema (all datasets normalize into it).
- Correlation: 215 raw LANL events → 131 alerts → **1 incident** (alert-fatigue reduction).
- ATT&CK mapping with real technique descriptions (no hallucinated IDs).
- Attack-path graph: 94 hosts, pivot C17693, shortest path to crown jewel C2388, betweenness choke points, blast-radius = 93 hosts cut by isolating 1 node.
- Simulated SOAR: actions seeded from real ATT&CK mitigations, gated (low=monitor · medium=ticket · high=contain · critical-asset=human approval).

### Demo app (SOC Command Center)
- 6 screens: Overview · Live Incident (replay + live scoring) · Attack Graph · Threat Intel & Attribution (live prediction) · Models & Metrics · Data & Methodology. Plus aesthetic login splash (no real auth).
- Pre-cached JSON for everything; exactly **2 live endpoints** (`POST /api/score-event`, `POST /api/predict-next`) with silent cached fallback so the pitch never breaks.
- Audit-ready incident report (download .md / print) + MTTD weeks→minutes panel.
- Single-container deploy (Docker, Render free tier).

## Non-goals
- Real authentication, CRUD, multi-tenancy — splash screen only.
- Real SOAR execution — all response actions simulated and human-gated.
- Trained attribution classifier — retrieval only, stated openly.
- Processing full 70 GB LANL — streamed windowed extract only.

## Success criteria (demo-ready definition)
Real anomaly metric with baseline lift · sequence predictor with baseline comparison · attack-path graph to a critical asset · gated SOAR · replay dashboard with recorded fallback · one India scenario. (See Milestone 6 in [phases.md](phases.md) for what remains.)
