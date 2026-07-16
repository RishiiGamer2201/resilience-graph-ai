# Architecture — Resilience Graph AI

> **Living document — update every working session.** Last updated: 2026-07-16.

## App flow

```
                    ┌──────────────────────────────────────────┐
                    │           DATA FOUNDATION                │
                    │ CIC-IDS2017 · LANL · UNSW-NB15 · ATT&CK  │
                    │ (raw ~11 GB, NOT in git — data/README.md)│
                    └──────────────┬───────────────────────────┘
          ┌────────────────────────┴─────────────────────────┐
          ▼                                                  ▼
┌─────────────────────────┐                  ┌──────────────────────────────┐
│ ENGINE 1 — DETECTION    │                  │ ENGINE 2 — PREDICT+ATTRIBUTE │
│ prep_* → benign-only    │                  │ parse_attack → sequences →   │
│ IsolationForest / AE    │                  │ embeddings → Markov predictor│
│ (CICIDS·LANL·UNSW)      │                  │ → actor attribution          │
└───────────┬─────────────┘                  └──────────────┬───────────────┘
            │ anomaly scores                                │ next-technique + actor
            ▼                                               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ SHARED SPINE: schema → normalize → correlate (1 incident) → ATT&CK map   │
│ → attack-path graph (choke points, blast radius) → gated SOAR            │
│ Driver: src/shared/run_spine.py → data/demo/spine_incident_full.json     │
└───────────────────────────────┬──────────────────────────────────────────┘
                                ▼
┌──────────────────────────────────────┐   src/shared/live_analyze.py
│ src/shared/live_analyze.analyze_events│◀── score→correlate→graph→SOAR
│  (the WHOLE spine, per request)       │    →attribute→predict, live
└───────────────┬──────────────────────┘
                │ (build_cache calls it on the shipped scenario →
                │  the committed sample cache IS a live analysis)
                ▼
        ┌───────────────────────────────────────────────┐
        │ scripts/build_cache.py → api/cache/*.json     │  (offline, committed sample)
        └───────────────────────┬───────────────────────┘
                                ▼
        ┌───────────────────────────────────────────────┐
        │ api/main.py (FastAPI)                         │
        │  · cached GETs (sample: overview/incident/…)  │
        │  · GET /scenarios                             │
        │  · POST /analyze, /analyze/upload  ◀ LIVE     │
        │  · POST /score-event, /predict-next  ◀ LIVE   │
        │  · serves frontend/dist in production         │
        └───────────────────────┬───────────────────────┘
                                ▼
        ┌───────────────────────────────────────────────┐
        │ React SPA (Vite) — SOC Command Center         │
        │ Login → Analyze Log → 6 screens               │
        │ AnalysisProvider: live bundle overrides sample│
        │ topbar pill: LIVE ANALYSIS vs SAMPLE DATA     │
        └───────────────────────────────────────────────┘
```

**Key principle:** the app is genuinely live — `POST /api/analyze` runs the entire spine on whatever event log you give it. The cached GETs serve a *sample* that is itself a real analysis of a shipped LANL red-team log (built by `build_cache.py` calling the same `analyze_events`). The frontend prefers a loaded live bundle over the sample (`lib/analysis.jsx` `useScreenData`); the 2 model widgets keep a cached fallback so a dropped backend never blanks the pitch.

## Runtime topology

- **Local dev:** uvicorn on :8000 + Vite dev server on :5173 (proxies `/api` → :8000).
- **Production:** single Docker container — FastAPI serves both `/api` and the built SPA (same origin, no CORS). Deployed via `render.yaml` (Render free tier). `$PORT` injected by host.
- Deploy needs only slim deps (`requirements-deploy.txt`: fastapi, uvicorn, sklearn, numpy, joblib — no torch/pandas). Runtime artifacts force-added to git past `.gitignore`: `models/iforest_lanl.joblib`, `models/next_technique_markov.pkl`, `data/processed/mitre_attack/attack_lookups.pkl`, `api/cache/*.json`.

## Folder and file structure

```
ET_HACK_26/
├── api/
│   ├── main.py                 # FastAPI: cached GETs + live /analyze,/score-event,/predict-next + SPA
│   └── cache/*.json            # sample payloads = a real analysis of the shipped log (committed)
├── scripts/
│   ├── build_cache.py          # rebuilds sample cache by running analyze_events on the scenario
│   └── export_demo_events.py   # exports the real 215-event LANL log → data/demo/scenarios/*.csv
├── tests/
│   └── test_live_analyze.py    # self-check for the live pipeline
├── src/
│   ├── schema.py               # 12-field common event schema (single source of truth)
│   ├── demo_ps7_pipeline.py    # early scripted mock (narrative only, superseded)
│   ├── engine1/
│   │   ├── prep_cicids.py      # CIC-IDS2017 clean → flows.parquet
│   │   ├── prep_lanl.py        # stream 7.2GB auth.txt.gz → red-team window parquet
│   │   ├── prep_unsw.py        # official UNSW split clean
│   │   ├── anomaly.py          # CICIDS IsolationForest + autoencoder eval
│   │   ├── lanl_detect.py      # THE MOAT: behavioral features, ROC 0.988
│   │   └── eval_unsw.py        # 2nd benchmark eval
│   ├── engine2/
│   │   ├── build_sequences.py  # 199 auto + manual CERT-In sequences
│   │   ├── build_embeddings.py # MiniLM technique embeddings
│   │   ├── build_predictor.py  # Markov (shipped) vs LSTM vs baselines
│   │   └── attribution.py      # transparent actor ranking
│   └── shared/
│       ├── parse_attack.py     # ATT&CK STIX → attack_lookups.pkl
│       ├── normalize.py        # dataset → common schema
│       ├── correlate.py        # alerts → ONE incident (S2)
│       ├── attack_mapper.py    # event → ATT&CK technique (S3)
│       ├── attack_graph.py     # networkx host graph, choke points (S4)
│       ├── soar.py             # gated response actions (S5)
│       ├── views.py            # `full` incident → per-screen payloads + computed MTTD
│       ├── live_analyze.py     # analyze_events(): the whole spine, per request (LIVE)
│       └── run_spine.py        # S2→S5 driver on real LANL incident (offline)
├── frontend/                   # Vite + React 19 SPA
│   ├── vite.config.js          # dev proxy /api → :8000
│   └── src/
│       ├── App.jsx             # router; Graph/Metrics lazy-loaded
│       ├── api.js              # API client + live→cached fallback
│       ├── theme.css           # design tokens (see design.md)
│       ├── index.css           # component styles
│       ├── lib/                # theme.jsx, useFetch.js, format.js, analysis.jsx (live bundle ctx)
│       ├── components/         # Layout, Sidebar, Topbar, Card, widgets, report
│       └── screens/            # Login, Analyze, Overview, Incident, Graph, ThreatIntel, Metrics, Methodology
├── data/
│   ├── raw/                    # datasets, gitignored (~11 GB) — see data/README.md
│   ├── processed/              # parquet/pkl, gitignored (attack_lookups.pkl + embeddings force-added)
│   ├── demo/
│   │   ├── scenarios/*.csv     # committed real event logs for /api/analyze (1-click)
│   │   └── spine_incident*.json# offline spine output (tracked)
│   └── manual/                 # hand-curated CERT-In sequences + guide
├── models/                     # gitignored; lanl iforest + markov force-added for deploy
├── reports/                    # generated eval reports (md) — the evidence trail
├── research/                   # planning docs: claude/ (canonical) + codex/ (early notes)
├── Dockerfile                  # 2-stage: node build → python slim runtime
├── render.yaml                 # Render blueprint
├── requirements.txt            # full pipeline deps (torch, pandas, ...)
└── requirements-deploy.txt     # slim API-only deps
```

## Tech stack

| Layer | Choice | Why |
|---|---|---|
| ML | scikit-learn (IsolationForest), PyTorch (AE/LSTM comparisons only) | unsupervised benign-only training; honest > fancy — Markov/IForest shipped |
| Embeddings | sentence-transformers all-MiniLM-L6-v2 | pretrained, no fine-tuning, 384-d |
| Graph | networkx | shortest path, betweenness, reachability at 94-node scale |
| Data | pandas + pyarrow (parquet) | streamed LANL extract, day-split CICIDS |
| API | FastAPI + uvicorn | serves cache + 2 live model endpoints + SPA |
| Frontend | React 19 + Vite 8, react-router 7, recharts, react-force-graph-2d, lucide-react | fast build, lazy-split heavy libs |
| Styling | plain CSS with custom-property tokens, light/dark via `data-theme` | no CSS framework needed |
| Deploy | Docker (2-stage) on Render free tier | one container, one URL |
| Python | 3.10.11 pinned | library compatibility (team decision) |
