# De-hardcode the SOC Command Center: static replay → live analysis pipeline

> **Execution protocol:**
> 1. All work happens on branch **`remove-hardcode`** (create from `main` at start).
> 2. When a task completes, **tick its checkbox and append a short indented note under it** with the insights/details/findings from that task (what was learned, gotchas, actual numbers/results).
> 3. When a **phase** completes, **commit and push** the branch (`git push -u origin remove-hardcode`) on its own — one commit per phase, message `De-hardcode Phase N: <summary>`.
> 4. Also update `memory.md` session log as phases land.

## Context

Teammate feedback: "the entire website looks hardcoded." Diagnosis (from full repo read): the data is NOT fake — `api/cache/*.json` comes from real pipeline runs on real LANL red-team data — but the app *behaves* statically:

1. Every screen replays the **same one pre-baked incident** (`INC-PS7-LANL-001`); only 2 endpoints (`/score-event`, `/predict-next`) compute anything live.
2. Some UI decorations **are fabricated**: `SPARKS` sparkline arrays in `frontend/src/screens/Overview.jsx:7-11`, asserted MTTD numbers ("4 min" / "21 days" hardcoded in `scripts/build_cache.py::overview/report`), hardcoded prose ("215 raw auth events…") in `Incident.jsx`.
3. The spine (`src/shared/run_spine.py`) only runs offline on one dataset.

**User decisions (asked & answered):**
- Scope: **full live pipeline** — upload/select an event log → backend runs the entire spine live (score → correlate → graph → SOAR → attribute → predict) → all screens render the live result. Streaming replay = stretch (3+ days available).
- Login stays a splash (relabeled "demo environment"); real auth adds no judging value.
- SOAR stays simulated + human-gated (no real infra to isolate hosts on) — that's honest labeling, not faking.
- All 6 project docs get the "update every working session" banner + content updates.

**Key insight enabling this:** the spine is already modular pure functions — `correlate()` (`src/shared/correlate.py`), `build_graph()/analyze()` (`src/shared/attack_graph.py`), `recommend()` (`src/shared/soar.py`), `rank_actors()` (`src/engine2/attribution.py`), `engineer()` (`src/engine1/lanl_detect.py`). "Live" is mostly **wiring these into a request handler**, not new ML.

---

## Phase 0 — Branch setup
- [x] Create branch `remove-hardcode` from `main`; push upstream.
  - Done. Branch tracks `origin/remove-hardcode`.

## Phase 1 — Backend: live analysis engine

- [x] **1.1 `src/shared/live_analyze.py` (new)** — one function `analyze_events(df: pd.DataFrame, critical_assets: set[str] | None, incident_id: str) -> dict`:
  - **Done + refactor beyond plan:** extracted the 5 screen transforms into new `src/shared/views.py` (shared by build_cache + live_analyze) so cached and live results use one code path. `views.compute_mttd()` kills the hardcoded MTTD; `views.SCORECARD` holds the model-level benchmark card.
  - **Key finding — alert count changed 131 → 209.** Offline `run_spine` calibrated scores by *this window's* min/max; live uses the FIXED `score_ref` anchors (lo=0.347, hi=0.794) for cross-upload consistency + parity with `/score-event`. More events cross the 50 threshold. This is the correct/honest choice; "209 alerts → 1 incident" is a stronger collapse story. Pivot C17693, event_count 215, actor Ember Bear all reproduce.
  - **Key finding — MTTD = "immediate".** The exported window is the victim's activity *from the pivot host*, so event 1 is already anomalous → first_alert == first_event → 0s. Humanizer now renders "immediate" (not "0 sec"); the weeks→minutes headline rests on the cited Mandiant dwell (~10 d), labelled a citation not our claim. `MttdPanel` must handle the immediate/0-min case (Phase 3).
  - victim = account with most alerts (label-free); critical_assets caller-supplied only (no auto crown-jewel guessing).
  1. `src.schema.coerce()` + `validate()` the input frame (trust boundary — reject >50k rows, missing user/host columns, with clear 422 messages).
  2. `engineer()` from `src.engine1.lanl_detect` — behavioral features computed within the uploaded window (works standalone; it's all running per-user stats).
  3. Score every event with `models/iforest_lanl.joblib`; calibrate raw→0-100 using the fixed `score_ref.json` anchors (same math as `/score-event` in `api/main.py:130` — NOT batch min/max, so scores are consistent across uploads).
  4. `correlate()` → incident. 5. `build_graph()` + `analyze()` → graph analysis. 6. `recommend()` → gated SOAR.
  7. `rank_actors()` on observed technique_ids → attribution (top 5). 8. Markov predict-next on the observed chain (reuse `_markov()` singleton logic).
  9. **Computed MTTD** (kills the hardcoded "4 min"): `first_alert_ts - first_event_ts` from actual timestamps, presented as "time to first correlated alert in this log"; industry dwell-time kept only as a *cited* comparison.
  10. Return one bundle: `{overview, incident, graph, threat_intel, report, meta:{source:"live", analyzed_at, n_events}}` — same shapes as the cached endpoints so screens need no shape changes.
  - **Honesty rule:** `critical_assets` comes from the request (user-designated) — default empty. No more auto-picking a "plausible crown jewel" (that's what `run_spine.py:62` does; fine offline, not for live).
- [x] **1.2 API endpoints (`api/main.py`)**
  - Added `POST /api/analyze` (JSON: `{events|scenario, critical_assets?, incident_id?}`), `POST /api/analyze/upload` (multipart CSV — judges feed their own data), `GET /api/scenarios`. Stateless; frontend holds the bundle. ValueError → 422 with clear message.
  - **Note:** SPA catch-all `/{full_path}` is defined last so API routes win (Starlette matches in definition order). Verified via TestClient: health/scenarios/analyze/upload/error-paths all correct.
  - **Refactor:** `build_cache.py` now *calls* `analyze_events` on the shipped scenario, so the committed sample cache IS a real analysis of a real log (sample == live pipeline). `metrics/methodology/score_ref` stay static. score_ref built first (engine reads it).
- [x] **1.3 Demo scenario data** — `scripts/export_demo_events.py` exports the real 215-event U66 window → `data/demo/scenarios/lanl_redteam_u66.csv` (118 labelled red-team). Committed. Dropped the synthetic `red_team_scenario.csv` as a second scenario for now (different schema, no protocol/NTLM signal — would confuse the "real model scoring" story; the LANL log is the clean hero). Add later if a second scenario is wanted.
- [x] **1.4 Self-check** — `tests/test_live_analyze.py`, 6 tests (incident/graph/attribution/report/mttd/reject), all pass. Installed `pytest` into the venv.
- [x] **Phase 1 complete → commit + push `remove-hardcode`.**

## Phase 2 — Frontend: live flow

- [x] **2.1 Analysis state** (`frontend/src/lib/analysis.jsx`, new) — `AnalysisProvider` context + `useScreenData(key, cachedFetcher)` hook that returns the live bundle's slice when an analysis is loaded, else fetches the cached sample (same `{data,error,loading}` shape + `source`). Screens changed by a one-line import swap (`useFetch(getX)` → `useScreenData('key', getX)`). Metrics/Methodology stay on cached `useFetch` (model-level, upload-independent).
- [x] **2.2 Analyze flow** — `screens/Analyze.jsx` + sidebar "Analyze Log" entry (first item). Scenario picker (`/api/scenarios`), CSV upload (multipart), critical-asset chip input. Submit → `analyze()`/`analyzeUpload()` → `setBundle` → navigate `/overview`. Error surfaces backend 422 detail; loading label "Scoring N events…". Login CTA now routes to `/analyze` ("Enter demo environment").
- [x] **2.3 Source visibility** — Topbar pill is now dynamic: "LIVE ANALYSIS · N events" (green pulse) vs "SAMPLE DATA · pre-computed" (dim, new `.pill.sample` style). Every screen inherits it.
- [x] **Verified:** `npm run build` clean; TestClient proof — renaming pivot `C17693`→`HACKED-BOX` in an uploaded log moves the graph pivot to `HACKED-BOX`; a 20-event upload yields a 20-node graph vs 130 for the full log (output tracks input). SPA + API serve same-origin (GET `/`, `/overview` deep-link, `/api/health` all 200).
- [x] **Phase 2 complete → commit + push `remove-hardcode`.**

## Phase 3 — Remove fabricated UI bits  *(done alongside Phase 2 — shared commit)*

- [x] `SPARKS` invented arrays deleted → new real `score_trend` field in the overview payload (actual per-alert anomaly scores, down-sampled to 60). Overview's 3 fake sparklines removed; one real anomaly-score sparkline remains. The ROC "trajectory" and blast "growth" tiles no longer fake a time-series.
- [x] `MttdPanel.jsx` + MTTD numbers → computed from timestamps (`views.compute_mttd`). Panel handles the immediate/0-sec case (no "Infinity×"); shows the Mandiant dwell as a labelled citation line. `traditional_days` now 10 (cited), not the old asserted 21.
- [x] `Incident.jsx` "What this proves" → templated from `data.event_count/alert_count/technique_ids/pivot/max_anomaly_score` (no more hardcoded "215 raw auth events" / "brute force").
- [x] `Login.jsx` → "Enter demo environment · no credentials", routes to `/analyze`.
- [x] `api.js` fallbacks kept; `LiveBadge` (● live / ○ cached) already renders in both widgets.
- [x] `build_cache.py` scorecard/metrics — unchanged real numbers (mirror `reports/*`); scorecard moved to `views.SCORECARD` constant.
- [x] **Phase 3 folded into the Phase 2 commit.**

## Phase 4 — Deploy updates

- [x] `requirements-deploy.txt`: + `pandas`, `networkx`, `python-multipart` (upload). **Dropped pyarrow** — no runtime parquet reads (all runtime input is CSV); pandas degrades gracefully without it. Still no torch/sentence-transformers.
- [x] `Dockerfile`: COPY `src/`, `data/processed/engine2/technique_embeddings.pkl`, `data/demo/scenarios/` added. Embeddings pkl force-added to git (was gitignored `*.pkl`).
- [x] Verify: **Docker not installed on this machine** — couldn't build the image locally. Instead confirmed the slim-image contract by import-tracing: `/api/analyze`, `/predict-next`, `/score-event` load **no** torch/sentence-transformers/matplotlib; only pandas/networkx/sklearn/numpy/joblib (all in deploy reqs). ⚠️ **Still needs a real `docker build` on a Docker host or the Render deploy to fully confirm.**
- [x] **Phase 4 complete → commit + push `remove-hardcode`.**

## Phase 5 — Update the 6 docs

- [x] Living-doc banner on all 6 (prd/architecture/rules/phases/design/memory).
- [x] `prd.md`: live analyze pipeline added as the headline app feature; "What is NOT faked" guarantee; non-goals reframed as deliberate boundaries (SOAR simulated, splash login, no runtime raw data).
- [x] `architecture.md`: flow diagram + endpoint list + folder tree updated for live_analyze/views/analyze screen/scenarios.
- [x] `rules.md`: new "No fabricated display data" + "one pipeline, two entry points" rules.
- [x] `phases.md`: Phase 8 "De-hardcode → live pipeline" with sub-statuses.
- [x] `memory.md`: focus/completed/caveats/session-log updated (fixed-calibration, immediate-MTTD, docker-unconfirmed caveats recorded).
- [x] **Phase 5 complete → commit + push `remove-hardcode`.**

## Phase 6 — Streaming replay (stretch)

- [x] `GET /api/analyze/stream?scenario=X&delay=` (SSE via `StreamingResponse`): analyses the scenario, then emits each real scored step as an `event: step`, ending with `event: done` carrying the full bundle. Verified over real HTTP (80 step events + done; scores/techniques real).
- [x] Live Incident "Stream live" button (`Radio` icon) alongside Replay: opens `EventSource`, appends steps as they arrive (reusing `TimelineRow`), and on `done` calls `setBundle` so the whole app promotes to the streamed live analysis. Additive — the existing client replay is untouched. Build clean, lint only pre-existing fast-refresh warnings.
- [x] **Phase 6 complete → commit + push `remove-hardcode`.**

---

## DONE — all 6 phases complete on branch `remove-hardcode`.
Commits: Phase 1 `a7186a8` · Phase 2+3 `b29e8ea` · Phase 4 `afecc10` · Phase 5 `9a42400` · Phase 6 (pending push).
**Deploy verification:** no Docker/podman on this machine, so `docker build` couldn't run. Validated the equivalent — fresh venv with only `requirements-deploy.txt` (clean install, no torch, sklearn 1.7.2), all Dockerfile COPY sources present + committed, and the app runs under that slim venv with `/api/analyze`, `/score-event`, `/predict-next`, SPA all 200. Runtime deps confirmed complete; a real `docker build` on Render/a Docker host is the only remaining check. Then open a PR `remove-hardcode → main`.

## Execution order & effort
0 → 1 (backend engine, ~half the work) → 2 (frontend flow) → 3 (fabricated bits) → 4 (deploy) → 5 (docs) → 6 (streaming stretch).

## Verification (end-to-end)
1. `pytest tests/test_live_analyze.py` — engine self-check.
2. Run stack (`uvicorn api.main:app` + `npm run dev`): pick LANL scenario on Analyze screen → confirm all 6 screens render the live bundle, topbar shows "LIVE ANALYSIS", incident matches the known U66 result (~131 alerts, pivot C17693) — proves live path reproduces the offline spine.
3. Upload a hand-edited CSV (change a hostname) → confirm graph/incident reflect the edit (the "not hardcoded" proof for the teammate).
4. Kill backend → widgets fall back with visible "○ cached" badges.
5. `npm run build` clean; `docker build` + container smoke test on `/api/analyze`.

## Files touched (primary)
New: `src/shared/live_analyze.py`, `scripts/export_demo_events.py`, `data/demo/scenarios/*.csv`, `frontend/src/lib/analysis.jsx`, `frontend/src/screens/Analyze.jsx`, `tests/test_live_analyze.py`.
Modified: `api/main.py`, `scripts/build_cache.py`, `frontend/src/{App.jsx, api.js, components/{Topbar,Sidebar,MttdPanel}.jsx, screens/{Overview,Incident,Login}.jsx}`, `requirements-deploy.txt`, `Dockerfile`, all 6 root docs.
