# Phases — nextATT&CKs

> **Living document — update every working session.** Last updated: 2026-07-16.

Project broken into phases. Detailed task-level checklist with acceptance criteria lives in [research/claude/implementation_plan.md](research/claude/implementation_plan.md) — this file is the at-a-glance view. Statuses as of 2026-07-16.

| Phase | Name | Status |
|---|---|---|
| 0 | Repo & environment | ✅ done |
| 1 | Data foundation | ✅ done |
| 2 | Engine 1 — real detection | ✅ done |
| 3 | Engine 2 — prediction & attribution | ✅ done (CERT-In **4/4 verified**; Mobile ATT&CK added → 918 techniques) |
| 4 | Shared spine | ✅ done |
| 5 | SOC Command Center app | ✅ done (8 screens) |
| 6 | Deploy | ✅ done (Render blueprint; docker build verified) |
| 8 | De-hardcode → live pipeline | ✅ done (merged to main) |
| 9 | Threat Radar (external CTI) | ✅ done (merged to main) |
| 10 | Campaign view · India scenarios · drift-proof metrics | ✅ done (merged to main) |
| 7 | Pitch & submission | ⏳ OPEN — current phase |

---

## Phase 0 — Repo & environment ✅
venv (Python 3.10.11), `requirements.txt`, repo skeleton, `src/schema.py` frozen, `.gitignore` for the 11 GB of data.

## Phase 1 — Data foundation ✅
- CIC-IDS2017: 2.83M → 2.30M clean flows, 77 features, day column (`prep_cicids.py`).
- LANL: streamed 519M lines → 11.2M-row red-team window, 702 labeled malicious (`prep_lanl.py`).
- ATT&CK: STIX → lookups pickle, 794 techniques / 172 groups (`parse_attack.py`).
- Schema + normalizers round-trip both datasets (`normalize.py`).

## Phase 2 — Engine 1: real detection ✅
- Baselines first (random + packet-rate rule) → IsolationForest (PR-AUC 0.473, 3.1× random) → autoencoder (best, PR-AUC 0.570).
- LANL lateral movement: ROC-AUC **0.988**, TPR@5%FPR 96.6%, NTLM ablation 0.906.
- UNSW-NB15 second benchmark: ROC-AUC 0.829.

## Phase 3 — Engine 2: prediction & attribution ✅ (one loose end)
- 199 auto sequences + 4 manual CERT-In (report-ordered, TEST-only).
- Embeddings sanity-passed; predictor bake-off → **Markov shipped** (top-3 38.6%, 4.7× kill-chain baseline; LSTM honest negative result).
- Attribution: 172 profiles, transparent scoring + justification.
- ⏳ **Loose end:** CERT-In sequence mappings unverified (0/4) — team must verify before quoting manual numbers in the pitch.

## Phase 4 — Shared spine ✅
Correlation (215 events → 1 CRITICAL incident, U66@DOM1) → ATT&CK mapping (T1550.002 pass-the-hash) → 94-host attack graph (pivot C17693, crown jewel C2388, blast radius 93) → gated SOAR. Driver: `run_spine.py`.

## Phase 5 — SOC Command Center ✅
- 5.1 FastAPI + frozen JSON contract + `build_cache.py` ✅
- 5.2 Design tokens light+dark (`theme.css`) ✅
- 5.3 React app: 6 screens + login splash ✅
- 5.4 Hero screens: incident replay + live scorer · force-graph + live predictor ✅
- 5.5 Integration + live→cached fallback, full stack verified ✅
- 5.6 Audit-ready incident report + MTTD panel ✅

## Phase 6 — Deploy ✅
Single-container Dockerfile (SPA baked in, slim deps), `render.yaml` blueprint, deploy artifacts force-added to git.

## Phase 8 — De-hardcode → live pipeline 🔄
Teammate flagged the app "looks hardcoded." It wasn't fake data (cache came from real runs) but it *behaved* statically — one baked incident, only 2 live endpoints, plus a few genuinely fabricated UI bits. Fix: a live analysis pipeline + honest UI. Full task detail + findings in [research/claude/dehardcode_plan.md](research/claude/dehardcode_plan.md). Branch: `remove-hardcode`.

- [x] **8.1 Live engine** — `src/shared/live_analyze.analyze_events()` runs the whole spine on any event log; `views.py` shares transforms with the cache; MTTD computed from timestamps.
- [x] **8.2 API** — `POST /api/analyze`, `/analyze/upload`, `GET /api/scenarios`; sample cache is now a real analysis of a shipped LANL log.
- [x] **8.3 Frontend** — Analyze Log screen (scenario picker + CSV upload), `AnalysisProvider` so live results override the sample, LIVE/SAMPLE topbar pill.
- [x] **8.4 Fabricated bits removed** — invented sparklines → real anomaly-score trend; MTTD dwell is a cited comparison; incident prose + login templated/relabelled.
- [x] **8.5 Deploy config** — slim deps + Dockerfile updated (docker build still to be confirmed on a Docker host / Render).
- [ ] **8.6 (stretch) streaming replay** — SSE per-event scoring on the Live Incident screen.

## Phase 9 — Threat Radar (external CTI / OSINT) 🔄
Asked: could we OSINT social media to track attackers and stop attacks? Assessed: **no** — scraping Meta/X/Google violates their terms and is blocked, person-level attribution from posts is irresponsible, nothing external can be "stopped" from a dashboard, and real alerts to real orgs are out of scope. **Built instead:** an External Threat Radar on legitimate free CTI feeds, mapped to ATT&CK and cross-referenced with the live incident. Branch: `threat-radar`. Detail: `research/claude/dehardcode_plan.md` successor plan.

- [x] **9.1** `src/shared/osint.py` — CISA KEV + CISA advisories + The Hacker News + BleepingComputer (all **no key**); OTX/ThreatFox optional behind free keys. Stdlib-only, each feed isolated. 40 items.
- [x] **9.2** ATT&CK mapping (explicit IDs + 70 curated aliases + name match, all validated) — recon/resource-dev names excluded after they false-positived on ordinary prose.
- [x] **9.3** Relevance vs the incident: technique / tactic / attributed-actor, reported separately.
- [x] **9.4** `POST /api/threat-radar` (+ live `refresh`, cache fallback) · cached at build time.
- [x] **9.5** Threat Radar screen: feed status, technique chips, match explanations, simulated gated sector alert.
- [x] **9.6** 11 tests (17 repo-wide), docs, docker build verified.

## Phase 7 — Pitch & submission ⏳ CURRENT
- [ ] Deck with the 4 honesty rules stated explicitly (sequence split · real-data metrics · baseline lift · SOAR simulated)
- [ ] Backup demo video (in case live fails)
- [ ] 30-second hook rehearsed (the demo sentence)
- [ ] Judge Q&A prep: circularity, synthetic-data honesty, scale-to-production path
- [ ] Architecture diagram polished for a slide
- [ ] Verify CERT-In sequences (unblocks India-scenario claims)
- [x] India scenarios: AIIMS ransomware + CBSE exam-board breach (shipped, selectable)
- [ ] (stretch) One-page concept-note handout

### Demo storyboard (3 min — drives the pitch)
1. **0:00** Splash → Overview: "attackers dwell for weeks; here's our SOC brain."
2. **0:30** Live Incident replay on real LANL data → ONE incident → pass-the-hash. *Live: score an event on stage.*
3. **1:15** Attack Graph: path to the database; isolating 1 host cuts 93.
4. **2:00** Threat Intel: attribute actor; *live: predict next move.*
5. **2:30** Models & Methodology: "ROC 0.988 on genuine red-team data, honest baselines, no accuracy theater." Weeks → minutes.
