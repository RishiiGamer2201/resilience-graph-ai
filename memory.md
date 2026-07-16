# Memory — living project state

> **Update this file every working session** (human or AI). It is the first thing an agent reads to get current. Keep newest entries at the top of the log. Companion docs: [prd.md](prd.md) · [architecture.md](architecture.md) · [rules.md](rules.md) · [phases.md](phases.md) · [design.md](design.md).

---

## Current focus
**Phase 7 — Pitch & submission.** Build is complete (pipeline + app + deploy). Remaining work is deck, backup video, Q&A prep, and verifying the CERT-In manual sequences.

## Currently being worked on
| File / area | Who | What |
|---|---|---|
| — | — | nothing in flight; docs scaffold just added |

## What has been completed
- ✅ **M0–M1** env + data foundation (CICIDS 2.30M flows · LANL 11.2M-row red-team window · ATT&CK lookups · frozen schema).
- ✅ **M2 Engine 1**: CICIDS anomaly (AE PR-AUC 0.570 best) · LANL lateral movement **ROC 0.988** (the moat) · UNSW 0.829.
- ✅ **M3 Engine 2**: 199+4 sequences · embeddings · **Markov shipped** (top-3 38.6%, 4.7× kill-chain baseline; LSTM honest negative) · attribution over 172 profiles.
- ✅ **M4 spine**: 215 events → 1 CRITICAL incident (U66@DOM1) · 94-host graph, pivot C17693 → C2388 · gated SOAR. `run_spine.py` end-to-end.
- ✅ **M5 app**: FastAPI (7 cached GETs + 2 live POSTs) · React 6 screens + splash · live widgets with cached fallback · incident report (.md/print) + MTTD panel · full stack verified running.
- ✅ **Deploy**: single-container Dockerfile + `render.yaml`; runtime artifacts force-added to git.
- ✅ Docs scaffold: prd/architecture/rules/phases/design/memory (2026-07-16).

## Open items / blockers
- ⏳ **CERT-In sequences unverified (0/4)** — `data/manual/cert_in_sequences.json`, guide in `data/manual/README.md`. Blocks quoting manual-eval numbers (top-3 8.7%) and India-scenario claims.
- ⏳ Deck, backup demo video, 30-sec hook, judge Q&A prep (see phases.md → Phase 7).
- 🟢 Stretch: India scenario replay (AIIMS/CBSE-styled), one-page handout.

## Known caveats (do not lose these)
- Attribution "100% top-1" is near-trivial by construction — never headline it; demo with 3–4 observed techniques.
- Manual (real-ordered) prediction is much harder than auto (8.7% vs 38.6% top-3) — prediction is a supporting feature; lean the pitch on Engine 1 + attribution.
- `requirements-deploy.txt` pins scikit-learn **1.7.2** to match the pickled models — bump only together with re-training.
- Live endpoints need local `models/` — otherwise UI silently shows "cached" badge (by design).

## Session log (newest first)
| Date | Who | What changed |
|---|---|---|
| 2026-07-16 | Claude | Added docs scaffold: prd.md, architecture.md, rules.md, phases.md, design.md, memory.md |
| 2026-07-11 | team | Render blueprint + single-container deploy; M5.6 report + MTTD panel; M5 frontend verified |
| 2026-07-10 | team | Two-engine decision memo + final pipeline locked; M0–M4 executed |
