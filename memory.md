# Memory — living project state

> **Living document — update every working session** (human or AI). Last updated: 2026-07-16. First thing an agent reads to get current. Newest log entries on top. Companion docs: [prd.md](prd.md) · [architecture.md](architecture.md) · [rules.md](rules.md) · [phases.md](phases.md) · [design.md](design.md).

---

## Current focus
**Phase 7 — Pitch & submission.** All build phases done and merged to `main`: live `/api/analyze` pipeline, campaign + per-account views, Attackers screen, Threat Radar (India-first CTI), Mobile ATT&CK + verified CERT-In, AIIMS/CBSE India scenarios, drift-proof metrics, docker verified. Remaining: deck, backup video, judge Q&A prep, one-pager. Deploys to Render from `main` (autoDeploy).

## Currently being worked on
| File / area | Who | What |
|---|---|---|
| docs | Claude | README (mermaid + new-device setup), architecture (mermaid), all md refreshed |
| pitch | team | deck, backup video, Q&A prep (Phase 7) |

## What has been completed
- ✅ **M0–M1** env + data foundation (CICIDS 2.30M flows · LANL 11.2M-row red-team window · ATT&CK lookups · frozen schema).
- ✅ **M2 Engine 1**: CICIDS anomaly (AE PR-AUC 0.570 best) · LANL lateral movement **ROC 0.992**, TPR@1%FPR 87.7% (the moat; autoencoder shipped) · UNSW 0.829.
- ✅ **M3 Engine 2**: 199+4 sequences · embeddings · **interpolated Markov shipped** (top-3 38.1%, 5.4× kill-chain baseline; LSTM/biLSTM/2nd-order honest negatives) · attribution over 172 profiles.
- ✅ **M4 spine**: 215 events → 208 alerts → 9 incidents (U66@DOM1) · 94-host graph, pivot C17693 → C2388 · gated SOAR. `run_spine.py` end-to-end.
- ✅ **M5 app**: FastAPI (7 cached GETs + 2 live POSTs) · React 6 screens + splash · live widgets that fail visibly rather than fabricating a score · incident report (.md/print) + MTTD panel · full stack verified running.
- ✅ **Deploy**: single-container Dockerfile + `render.yaml`; runtime artifacts force-added to git.
- ✅ Docs scaffold: prd/architecture/rules/phases/design/memory (2026-07-16).
- ✅ **Finalist surface** (branch `finalist/furnish-nextattack`): cited evidence index (1,545 chunks, BM25 + exact-ID boost, recall@5 0.857) · deterministic vulnerability prioritisation (KEV × criticality × graph reachability) · digital-twin counterfactual with operational cost · server-side RBAC + approval policy · hash-linked tamper-evident audit chain · bounded 7-node workflow with node timings · 11-stage explainability trace · PS7 scoreboard read from `reports/metrics.json` · guarded outbound HTTP (allowlist + SSRF + redirect re-validation). Tests 31 → 152. Docs: 4 ADRs, threat model, cost ledger, runbook, demo script, judge Q&A.
- ✅ **Live analysis pipeline** (branch `remove-hardcode`): `src/shared/live_analyze.py` + `views.py`; `POST /api/analyze` + `/analyze/upload` + `GET /api/scenarios`; Analyze Log screen + `AnalysisProvider`; sample cache is now a real analysis of a shipped LANL log; fabricated UI bits removed; deploy config updated. 6 pytest checks green.

## Open items / blockers
- ✅ **CERT-In sequences verified (4/4)** — quoted top-3 is 10.0% (real reported ordering), published alongside 38.1% on the auto-ordered set.
- ✅ 30-sec hook, click-by-click script and judge Q&A: `docs/demo/`. Backup video linked in the README.
- ⏳ **No LICENSE file** — owner decision, flagged in CONTRIBUTING.md and docs/operations/cost-and-limits.md. Without one the repo is all-rights-reserved by default.
- ⏳ **No rate limiting** on the API — fine for a demo, recorded as residual risk in docs/security/threat-model.md.
- 🟢 Stretch: India scenario replay (AIIMS/CBSE-styled), one-page handout.

## Known caveats (do not lose these)
- **Threat Radar "relevant to your incident" is legitimately EMPTY** with the demo LANL incident: it's auth-based (T1550.002/T1110 = lateral-movement/credential-access) while public feeds are vuln/malware-dominated (initial-access/execution/impact). Verified not a bug — a synthetic T1190/T1486 incident scores 7 hits. The screen explains this honestly. Don't "fix" it by loosening matching.
- **Threat Radar optional keys:** `OTX_API_KEY`, `ABUSECH_AUTH_KEY` (both free signups). Without them those 2 sources are skipped; the 4 no-key sources still deliver 40 items. abuse.ch/ThreatFox now 401s without a key (policy changed).
- Attribution "100% top-1" is near-trivial by construction — never headline it; demo with 3–4 observed techniques.
- Manual (real-ordered) prediction is much harder than auto (10.0% vs 38.1% top-3) — prediction is a supporting feature; lean the pitch on Engine 1 + attribution.
- `requirements-deploy.txt` pins scikit-learn **1.7.2** to match the pickled models — bump only together with re-training.
- Live endpoints need local `models/` — otherwise UI silently shows "cached" badge (by design).
- **Live analysis uses FIXED score_ref calibration**, so the demo scenario now shows 208 alerts (was 131 offline with batch min/max scaling). Intentional — consistent across uploads + matches /score-event. Pivot C17693, 215 events unchanged.
- **MTTD**: 2 h on the synthetic scenarios, still "immediate" on the LANL exports because
  that window starts at the pivot host. It read "immediate" everywhere until the
  calibration fix, for a bad reason: every event alerted, so the first log line was
  always a detection and time-to-detect was necessarily zero. The weeks it is compared
  against remains a *cited* Mandiant dwell (~10 d), labelled a citation, not our claim.
- **The Dockerfile never copied `models/ae_lanl.npz`** — the deployed container silently fell back to the IsolationForest and scored differently from the build we measured. Fixed, and `scripts/check_dockerfile.py` now fails if a required runtime artifact is not COPYed or is excluded by `.dockerignore`. That check needs no Docker daemon.
- **`views.SCORECARD` had drifted** to LANL ROC 0.988 (the IsolationForest we stopped shipping) against a measured 0.992. It reads `reports/metrics.json` now, and a test fails if it drifts again.
- **ATT&CK mapping coverage was 37.5%**: a flagged authentication that was neither a failure nor a first-time host got no technique at all. Anomalous successful logins now map to T1078 Valid Accounts, gated on the alert score. Coverage 100%.
- **`rank_candidates` recomputed betweenness centrality per candidate** — 5.9 s on the impact node, when it only needs reachability. The full 7-node investigation now measures **242 ms p50 / 1928 ms p95** (`reports/ps7_eval.md`); the p95 is dominated by the 2,732-event LANL campaign scenario.
- **The SPA read `incident.users_involved`** while the view exposed `accounts_involved`, rendering "0 accounts" instead of crashing. The view carries both now, and `tests/test_ui_contract.py` asserts every key the screens dereference — that file is the type system across a boundary with no TypeScript.
- **MTTR stays Not measured** while every action is simulated. Do not let anyone put a number on that card.
- **Default auth is authorisation WITHOUT authentication** (`X-Role` header) — deliberate, so a judge can switch roles with no signup, and `/api/capabilities` says so. `NEXTATTACK_ROLE_TOKENS` switches to bearer tokens.
- **The audit chain is session-scoped and in memory.** Free hosts have an ephemeral filesystem; never imply it persists.

## Session log (newest first)
| Date | Who | What changed |
|---|---|---|
| 2026-08-18 | Claude | `finalist/furnish-nextattack`: PS7 finalist pass. Cited evidence with hashed/dated sources; vulnerability prioritisation; digital twin; RBAC + approval; audit chain; bounded 7-node workflow; explainability trace; PS7 scoreboard; guarded outbound HTTP. New Investigation and Scoreboard screens on the existing token system (no Tailwind, no TS migration, no map — ADR 0004). Four real bugs found and fixed on the way (see caveats). 31 → 152 tests. Full docs set under `docs/`, including four ADRs and a threat model. |
| 2026-07-16 | Claude | Docs refresh: README rewritten (mermaid diagram + new-device setup for teammates), architecture.md → mermaid, prd/phases/memory updated. Verified docker build + slim-venv run. Merged `threat-radar` → `main` (fast-forward). |
| 2026-07-16 | Claude | India scenarios: AIIMS + CBSE (config-driven generator). TGT/non-host artifacts filtered from crown jewels. Alert-queue "review path" deep-links to the focused subgraph. Data & Methodology updated (918 techniques, 5.4×, verified CERT-In). |
| 2026-07-16 | Claude | Campaign view: all 104 accounts (was 1); Attackers screen; graph node-click + account filter + focused exposure subgraphs; multi-pivot blast radius; crown jewels derived (not the fabricated middle-of-list pick). Many bug fixes from user testing. |
| 2026-07-16 | Claude | E2.2b CERT-In: teammate verified 4/4 real advisories. Added Mobile ATT&CK bundle (lookups 794→918) for the Android-trojan sequence; regenerated embeddings (CPU, GPU busy) + predictor. Manual top-3 now 10.0%, anti-circularity 5.4×. |
| 2026-07-16 | Claude | Threat Radar (India-first CTI + technique bridge + alert queue), IST timestamps, drift-proof metrics store. Merged de-hardcode live pipeline to main. |
| 2026-07-16 | Claude | `threat-radar`: External Threat Radar — free CTI feeds → ATT&CK → cross-referenced with the live incident; simulated gated alerts. Social scraping assessed + rejected (ToS/ethics/no control surface) |
| 2026-07-16 | Claude | `remove-hardcode`: live `/api/analyze` pipeline, Analyze screen, killed fabricated UI, deploy config, docs updated (Phases 0–5 of the de-hardcode plan) |
| 2026-07-16 | Claude | Added docs scaffold: prd.md, architecture.md, rules.md, phases.md, design.md, memory.md |
| 2026-07-11 | team | Render blueprint + single-container deploy; M5.6 report + MTTD panel; M5 frontend verified |
| 2026-07-10 | team | Two-engine decision memo + final pipeline locked; M0–M4 executed |
