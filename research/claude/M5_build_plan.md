# Milestone 5 — Demo App Build Plan (SOC Command Center)

**Status:** PLAN (locked in principle, awaiting "Start building"). Not app code.
**Stack:** **FastAPI** (Python, serves ML + spine) + **React (Vite)** frontend.
**Framing:** an AI-augmented **SOC Command Center** for critical infrastructure.

---

## 1. Principles (decided)
- **Pre-cached + 2 live moments.** Everything renders from pre-computed JSON (never fails);
  exactly two endpoints run live for interactivity.
- **Robustness first.** Any live call that errors silently falls back to its cached value.
- **Every screen backed by REAL output** — no stub features.
- **Agents build, Claude verifies** every piece before merge.
- **Theme:** light default + dark toggle, via CSS-variable design tokens.

## 2. The six screens
| # | Screen (nav label) | Shows | Data source |
|---|---|---|---|
| 1 | **Overview / Command Center** | headline stats: MTTD weeks→minutes, open incident, severity, model scorecard (LANL ROC 0.988, CICIDS PR-AUC) | cached `/api/overview` |
| 2 | **Live Incident** ⭐ | event-by-event replay of the real LANL U66 incident → anomaly score → ATT&CK chain → predicted next → gated SOAR. **Live event-scoring widget here.** | cached `/api/incident` + live `/api/score-event` |
| 3 | **Attack Graph** ⭐ | interactive 94-host graph, pivot C17693, path to crown-jewel C2388, choke point, blast radius | cached `/api/graph` |
| 4 | **Threat Intel & Attribution** | ATT&CK technique mapping + ranked APT actor attribution + next-technique prediction. **Live prediction widget here.** | cached `/api/threat-intel` + live `/api/predict-next` |
| 5 | **Models & Metrics** | Engine 1/2 eval tables, PR curves, baseline-lift, the honest ablations | cached `/api/metrics` |
| 6 | **Data & Methodology** | 4 datasets + what each feeds; the honesty notes (benign-only, no-accuracy, circularity fix, NTLM ablation, CERT-In verification) | cached `/api/methodology` |

⭐ = spend 70% of polish here (the "wow" screens).
Plus a **Login splash** (aesthetic only, no auth) → click "Enter as Analyst" → Overview.

## 3. Design system (for `ui-designer` to spec both themes)
- **Base:** charcoal/navy (dark) · off-white/light-grey (light). Never pure black/white.
- **Layout:** left sidebar nav + top bar (theme toggle, incident clock) + card-based content grid.
- **Severity palette (tuned per theme):** critical=red, high=orange, medium=amber, low=blue, normal=grey.
  Reserve red/orange for genuine severity only. No neon.
- **Typography:** one clean sans (e.g. Inter), monospace for hostnames/technique IDs.
- **Tokens:** CSS custom properties (`--bg`, `--surface`, `--text`, `--sev-critical`, …) with
  `[data-theme="dark"]` / `[data-theme="light"]` overrides. Toggle flips the attribute.
- **Recommendation:** default light (team preference); **present the live demo in dark** (graph + severity pop hardest).

## 4. API contract (FastAPI — freeze this FIRST)
Base: `/api`. All GET responses are pre-computed JSON snapshots regenerated from our pipeline.

| Method | Endpoint | Live? | Response (shape sketch) |
|---|---|---|---|
| GET | `/overview` | cached | `{mttd, incidents_open, severity, scorecard:{lanl_roc, cicids_prauc, unsw_roc}}` |
| GET | `/incident` | cached | `{incident_id, severity, alert_count, event_count, steps:[{t,user,src,dst,score,tactic,technique,technique_id,explanation,is_alert}], attack_chain, technique_ids}` |
| GET | `/graph` | cached | `{nodes:[{id,critical}], edges:[{from,to,technique,tactic,score}], analysis:{entry_host,paths_to_critical,choke_points,blast_radius_size,recommended_isolation}}` |
| GET | `/threat-intel` | cached | `{mapping:[{technique_id,tactic,technique,explanation}], attribution:[{actor,score,coverage,justification}]}` |
| GET | `/metrics` | cached | `{engine1:{cicids,lanl,unsw}, engine2:{predictor_table, embeddings}}` (the report tables as JSON) |
| GET | `/methodology` | cached | `{datasets:[…], honesty_notes:[…]}` |
| POST | `/score-event` | **LIVE** | in: `{is_fail,new_dst_for_user,new_src_for_user,user_distinct_dst_sofar,user_fail_rate_sofar,dst_rarity,is_ntlm}` → out: `{anomaly_score, severity}` (loads `models/iforest_lanl.joblib`) |
| POST | `/predict-next` | **LIVE** | in: `{technique_ids:[…]}` → out: `{predictions:[{technique_id,name,rank}]}` (loads `models/next_technique_markov.pkl`) |

- A `scripts/build_cache.py` regenerates all cached JSON from the existing reports/models
  (so the API just serves files; nothing computes at request time except the 2 live routes).
- **Fallback:** frontend wraps live calls in try/catch → on error, show the cached example result + a subtle "cached" badge.

## 5. Repo layout (added when building)
```
api/            FastAPI app (imports from src/), uvicorn entrypoint
  main.py
  cache/        pre-computed *.json (gitignored if large, else committed)
frontend/       Vite + React app
  src/ components/ screens/ theme/
scripts/build_cache.py
```
`.gitignore` additions: `node_modules/`, `frontend/dist/`, `api/__pycache__/`.

## 6. Agent task breakdown (sequenced; Claude verifies each)
1. **Claude (inline):** FastAPI skeleton + `build_cache.py` + freeze the JSON contract (so real shapes exist). *Do first.*
2. **`ui-designer`:** design tokens (light+dark) + component/screen mockups matching §3. *Parallel-safe.*
3. **`frontend-developer`:** Vite+React app, theme system, the 6 screens + login splash, consuming the API. *After 1 & 2.*
4. **`frontend-developer` / Claude:** the two ⭐ screens (graph viz + live widgets) — highest polish.
5. **Claude:** integration, wire live endpoints, fallback logic, verify end-to-end, demo dry-run.

*Session-quota note:* fire agents sequentially, not all at once; Claude writes tight specs so cold starts don't waste budget.

## 7. Demo storyboard (3 min — drives everything)
1. **(0:00)** Splash → Overview. "1.59M incidents/yr; attackers dwell for weeks. Here's our SOC brain."
2. **(0:30)** Live Incident replay — anomalies light up on real LANL data → correlate into ONE incident → Pass-the-Hash. *Live: score an event on stage.*
3. **(1:15)** Attack Graph — the path to the citizen database appears; one host to isolate cuts 93 hosts of blast radius.
4. **(2:00)** Threat Intel — attribute the actor; *live: predict the next move.*
5. **(2:30)** Models & Methodology — "and it's real: ROC 0.988 on genuine red-team data, honest baselines, no accuracy theater." Weeks → minutes.

## 8. Risks & mitigations
| Risk | Mitigation |
|---|---|
| Live demo fails | pre-cached fallback on every live call; recorded video backup |
| Scope creep (CRM breadth) | 6 screens only; 2 ⭐ get the polish; no auth/CRUD |
| Agent session limits | sequence agents; tight specs; Claude fills gaps inline |
| Theme severity colors wash out | tokens tuned per theme; ui-designer specs both |
| Graph lib perf | 94 nodes is small; pre-layout positions in cache |

---
*Locked decisions from the M5 planning discussion (2026-07-11). Build begins on "Start building".*
