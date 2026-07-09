# Resilience Graph AI

**ET AI Hackathon 2026 · PS7 — AI-Driven Cyber Resilience for Critical National Infrastructure**

> We detect low-and-slow attacks in real infrastructure logs, connect weak signals into an
> explainable MITRE ATT&CK attack chain, predict the attacker's next moves, name the likely
> actor, and recommend gated containment — cutting detection time from weeks to minutes.

---

## What this is

An AI-augmented SOC layer built around **two engines**:

| Engine | Scores | What it does |
|---|---|---|
| **Engine 1 — Real Detection** | Technical Excellence | Anomaly / lateral-movement detection on **real data** (CIC-IDS2017 + LANL), scored against LANL's red-team ground truth |
| **Engine 2 — Prediction + Attribution** | Innovation | Predicts the attacker's next ATT&CK technique(s) and ranks the likely APT group |

Both feed a shared spine: normalize → correlate into one incident → ATT&CK map → attack-path graph → gated SOAR → Streamlit replay dashboard.

## The plan (read these first)

| Doc | Purpose |
|---|---|
| [research/claude/final_pipeline.md](research/claude/final_pipeline.md) | **Canonical build spec** — the architecture we're building |
| [research/claude/implementation_plan.md](research/claude/implementation_plan.md) | **Task checklist** — milestones, owners, acceptance criteria |
| [research/claude/decision_memo.md](research/claude/decision_memo.md) | Why two engines; the corrections to the original plan |
| [ET_Hackathon_2026_Analysis.md](ET_Hackathon_2026_Analysis.md) | Problem-statement analysis & scoring |
| [research/codex/](research/codex/) | Earlier PS6/PS7 research notes |

## Repo layout

```
data/
  raw/         # datasets — NOT in git (11 GB). Download per data/README.md
  processed/   # cleaned/model-ready — NOT in git (regenerated)
  demo/        # tiny demo scenario + outputs — tracked
research/       # planning docs (claude/ + codex/)
src/            # code (demo_ps7_pipeline.py today; engine1/engine2/shared/app to come)
```

## Getting started (for teammates)

```bash
git clone <this-repo-url>
cd ET_HACK_26
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt        # (added in Milestone 0)
```

**Then download the datasets** — they're not in git. Follow [data/README.md](data/README.md); it lists every source, what to download, and where to put it. All four are free/public.

Run the current demo pipeline (scripted mock, for narrative):
```bash
python src/demo_ps7_pipeline.py
```

## Datasets (all public / free)

| Dataset | Use | Source |
|---|---|---|
| CIC-IDS2017 | anomaly detection + metrics | unb.ca/cic/datasets/ids-2017.html |
| LANL Cyber | lateral movement + red-team ground truth | csr.lanl.gov/data/cyber1 |
| MITRE ATT&CK (Enterprise + ICS) | technique mapping + sequences | github.com/mitre-attack/attack-stix-data |
| UNSW-NB15 | second benchmark | research.unsw.edu.au/projects/unsw-nb15-dataset |

## Team & workflow

4-person team (M1 vision/graph · M2 anomaly · M3 NLP/KG · M4 data/MLOps/UI). See owner split in the implementation plan.

**Branching:** work on feature branches (`git checkout -b m2/anomaly-baseline`), open PRs into `main`. Avoid committing directly to `main` so nobody's work gets overwritten.

---
*Not affiliated with ET Edge / MITRE. Uses public datasets under their respective licenses.*
