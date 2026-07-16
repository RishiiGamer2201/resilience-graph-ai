# Memory — living project state

> **Living document — update every working session** (human or AI). Last updated: 2026-07-16. First thing an agent reads to get current. Newest log entries on top. Companion docs: [prd.md](prd.md) · [architecture.md](architecture.md) · [rules.md](rules.md) · [phases.md](phases.md) · [design.md](design.md).

---

## Current focus
**Phase 8 — De-hardcode → live pipeline** (branch `remove-hardcode`). Teammate said the site "looks hardcoded"; built a real `/api/analyze` pipeline so every screen renders live spine output on any uploaded log. Phases 1–5 of the plan done; streaming replay (8.6) is the remaining stretch. Then back to Phase 7 (pitch/deck/video, CERT-In verification).

## Currently being worked on
| File / area | Who | What |
|---|---|---|
| docs (6) | Claude | living-doc banners + live-pipeline updates (Phase 5 of remove-hardcode plan) |
| streaming replay | Claude | SSE per-event scoring — stretch, not started |

## What has been completed
- ✅ **M0–M1** env + data foundation (CICIDS 2.30M flows · LANL 11.2M-row red-team window · ATT&CK lookups · frozen schema).
- ✅ **M2 Engine 1**: CICIDS anomaly (AE PR-AUC 0.570 best) · LANL lateral movement **ROC 0.988** (the moat) · UNSW 0.829.
- ✅ **M3 Engine 2**: 199+4 sequences · embeddings · **Markov shipped** (top-3 38.6%, 4.7× kill-chain baseline; LSTM honest negative) · attribution over 172 profiles.
- ✅ **M4 spine**: 215 events → 1 CRITICAL incident (U66@DOM1) · 94-host graph, pivot C17693 → C2388 · gated SOAR. `run_spine.py` end-to-end.
- ✅ **M5 app**: FastAPI (7 cached GETs + 2 live POSTs) · React 6 screens + splash · live widgets with cached fallback · incident report (.md/print) + MTTD panel · full stack verified running.
- ✅ **Deploy**: single-container Dockerfile + `render.yaml`; runtime artifacts force-added to git.
- ✅ Docs scaffold: prd/architecture/rules/phases/design/memory (2026-07-16).
- ✅ **Live analysis pipeline** (branch `remove-hardcode`): `src/shared/live_analyze.py` + `views.py`; `POST /api/analyze` + `/analyze/upload` + `GET /api/scenarios`; Analyze Log screen + `AnalysisProvider`; sample cache is now a real analysis of a shipped LANL log; fabricated UI bits removed; deploy config updated. 6 pytest checks green.

## Open items / blockers
- ⏳ **CERT-In sequences unverified (0/4)** — `data/manual/cert_in_sequences.json`, guide in `data/manual/README.md`. Blocks quoting manual-eval numbers (top-3 8.7%) and India-scenario claims.
- ⏳ Deck, backup demo video, 30-sec hook, judge Q&A prep (see phases.md → Phase 7).
- 🟢 Stretch: India scenario replay (AIIMS/CBSE-styled), one-page handout.

## Known caveats (do not lose these)
- Attribution "100% top-1" is near-trivial by construction — never headline it; demo with 3–4 observed techniques.
- Manual (real-ordered) prediction is much harder than auto (8.7% vs 38.6% top-3) — prediction is a supporting feature; lean the pitch on Engine 1 + attribution.
- `requirements-deploy.txt` pins scikit-learn **1.7.2** to match the pickled models — bump only together with re-training.
- Live endpoints need local `models/` — otherwise UI silently shows "cached" badge (by design).
- **Live analysis uses FIXED score_ref calibration**, so the demo scenario now shows ~209 alerts (was 131 offline with batch min/max scaling). Intentional — consistent across uploads + matches /score-event. Pivot C17693, 215 events unchanged.
- **MTTD is "immediate"** on the demo log (attacker's first pivot event is already anomalous). Weeks→minutes headline rests on the *cited* Mandiant dwell (~10 d), labelled a citation not our claim.
- **Docker build not yet confirmed** for the new deploy config (no Docker on the build machine) — verify on Render or a Docker host before relying on it.

## Session log (newest first)
| Date | Who | What changed |
|---|---|---|
| 2026-07-16 | Claude | `remove-hardcode`: live `/api/analyze` pipeline, Analyze screen, killed fabricated UI, deploy config, docs updated (Phases 0–5 of the de-hardcode plan) |
| 2026-07-16 | Claude | Added docs scaffold: prd.md, architecture.md, rules.md, phases.md, design.md, memory.md |
| 2026-07-11 | team | Render blueprint + single-container deploy; M5.6 report + MTTD panel; M5 frontend verified |
| 2026-07-10 | team | Two-engine decision memo + final pipeline locked; M0–M4 executed |
