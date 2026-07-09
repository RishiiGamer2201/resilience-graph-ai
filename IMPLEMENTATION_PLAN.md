# Resilience Graph AI — End-to-End Implementation Plan

**PS7 · ET AI Hackathon 2026 · v1.0 (2026-07-10)**
Spec: [research/claude/final_pipeline.md](research/claude/final_pipeline.md) · Owners: M1 vision/graph · M2 anomaly · M3 NLP/KG · M4 data/UI

**Legend:** `[ ]` todo · `[x]` done · 🔴 blocker for others · ⭐ scoring-critical · Each task lists **(owner · deliverable)**

---

## Phase 0 — Team alignment & repo hygiene 🔴

- [ ] Team sign-off on two-engine architecture (real anomaly layer, NOT synthetic stub) — say it out loud in the group (all · decision noted in shared doc)
- [ ] Agree file ownership: teammates edit DOCX, code lives in this repo, `final_pipeline.md` is canonical spec (all)
- [ ] `git init` + first commit of current state; create `.gitignore` excluding `data/raw/`, `data/processed/`, `*.pkl` (M4 · git repo)
- [ ] Create `requirements.txt` (pandas, pyarrow, scikit-learn, torch, sentence-transformers, networkx, streamlit, plotly, mitreattack-python) + verify everyone's env installs it (M4 · requirements.txt)
- [ ] Freeze common event schema as code (M4 · `src/schema.py`) 🔴

## Phase 1 — Data foundation 🔴 *(everything is blocked until this is done)*

### CICIDS-2017
- [ ] Unzip `MachineLearningCSV.zip` → `data/processed/cicids2017/` (M4)
- [ ] Clean: strip column whitespace, drop/clip `Inf`/`NaN`, dedupe rows, unify label names (M4 · `src/data/cicids_clean.py`)
- [ 