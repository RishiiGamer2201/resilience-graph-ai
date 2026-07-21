# PRD — Resilience Graph AI

> **Living document — update every working session.** Last updated: 2026-07-16.

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
- LANL lateral-movement detector: 7 behavioral auth features, **ROC-AUC 0.988** vs 702 real red-team events; NTLM-ablation robustness (0.906 behavioral-only).
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
- **Live analysis pipeline (`POST /api/analyze`)** — pick a shipped scenario or upload a CSV event log; the backend scores **every event** with the real IsolationForest, correlates into one incident, maps ATT&CK, builds the attack graph, gates SOAR, attributes an actor, and predicts the next technique — all computed per request. Every screen renders the live result; a topbar pill shows LIVE vs SAMPLE. Judges can feed their own data.
- **8 screens:** **Analyze Log** · Overview · **Attackers** (all 104 compromised accounts; open one → its own scoped incident) · Live Incident (replay + SSE stream + live event scoring) · Attack Graph (click-a-host, account filter, focused exposure subgraphs) · Threat Intel & Attribution (live prediction) · **Threat Radar** · Models & Metrics · Data & Methodology. Plus login splash (no real auth).
- **Scenarios:** the full LANL red-team campaign (104 accounts, one machine — C17693 — carrying 670/702 events), a single-account view, a synthetic **AIIMS-style hospital ransomware** and **CBSE-style exam-board breach** (concrete India CNI), plus an upload-to-prove-it's-live sample.
- **Campaign-wide, not one account** — the graph computes blast radius / choke points / crown-jewels-at-risk across **all** attacker pivots; crown jewels are a stated heuristic (hosts the most accounts depend on), never a fabricated label.
- The committed sample cache is itself a **real live analysis** of a shipped LANL red-team log — sample and live use the identical pipeline. Live model widgets keep a silent cached fallback so the pitch never breaks.
- **Threat Radar (external CTI)** — free, purpose-built intel feeds (CISA KEV, CISA advisories, The Hacker News, BleepingComputer; optional AlienVault OTX / ThreatFox behind free keys) mapped to real ATT&CK techniques and **cross-referenced with the incident you're investigating** ("same technique / same tactic / mentions your attributed actor"). Cached at build time + live refresh. Closes the loop: outside world → your infrastructure.
- Audit-ready incident report (download .md / print) + MTTD panel (detection latency measured from the log; industry dwell cited, not asserted).
- Single-container deploy (Docker, Render free tier).

## What is NOT faked (the anti-"hardcoded" guarantee)
Every number on screen is either computed live from the analysed log or a labelled citation. Anomaly scores come from the real IsolationForest; the incident/graph/attribution/prediction are the actual spine output; MTTD is measured from timestamps. Change the input and the output changes.

## Non-goals (deliberate scope boundaries, not shortcuts)
- **No social-media scraping (Facebook / Instagram / X / Google results).** Evaluated and rejected: it violates those platforms' terms and is actively blocked; "tracking an attacker" from public posts is person-level attribution that risks naming the wrong people; and nothing external can be "stopped" from a dashboard. The Threat Radar uses legitimate CTI feeds built for programmatic use instead — same intent, defensible execution.
- **Threat Radar is enrichment, not prevention.** It informs and (simulated) alerts; it does not block, take down, or contact anyone.
- **Real SOAR execution** — there is no live infrastructure to isolate hosts on, so response actions are simulated and human-gated. Standard for a demo; clearly labelled, never worded as real execution.
- **Real authentication** — single-analyst demo; login is a splash, no credentials to fake or leak (team decision, 2026-07-16).
- **Trained attribution classifier** — attribution is transparent profile retrieval, stated openly (a trained actor classifier would overclaim on this data).
- **Full 70 GB LANL at runtime** — a committed windowed extract + tiny scenario CSVs; the app never needs the raw corpus.

## Success criteria (demo-ready definition)
Real anomaly metric with baseline lift · sequence predictor with baseline comparison · attack-path graph to a critical asset · gated SOAR · replay dashboard with recorded fallback · one India scenario. (See Milestone 6 in [phases.md](phases.md) for what remains.)
