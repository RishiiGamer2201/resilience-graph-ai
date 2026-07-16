# Rules — what to use, what to avoid

> **Living document — update every working session.** Last updated: 2026-07-16.

Working rules for humans and AI agents (Claude/Codex) on this repo. These encode decisions already made — do not relitigate them mid-hackathon.

---

## What to use

### Libraries (already installed — never add new deps without team sign-off)
- **pandas / pyarrow / numpy** — all data work. Parquet for processed data.
- **scikit-learn** — IsolationForest is the shipped detector. Pin **1.7.2** for anything that unpickles `models/*.joblib` (version mismatch breaks deploys).
- **networkx** — all graph work.
- **sentence-transformers** (all-MiniLM-L6-v2) — embeddings. Build-time only, never in the deploy image.
- **torch** — comparison models only (AE, LSTM). Build-time only.
- **FastAPI + uvicorn** — API. **React 19 + Vite** — frontend.
- Frontend UI deps: `react-router-dom`, `recharts`, `react-force-graph-2d`, `lucide-react`. That's the full list — no MUI/Tailwind/axios/etc.

### Patterns
- **Schema first:** every dataset normalizes into the 12-field schema in `src/schema.py`. Import from there; never redefine columns.
- **No fabricated display data:** every number or series shown in the UI must trace to the current analysis bundle (live or the sample-of-a-real-log cache) or be a labelled citation. No invented arrays (the old `SPARKS`), no asserted metrics. If you need a new display value, compute it in `src/shared/views.py` so cache and live share one code path.
- **One pipeline, two entry points:** offline `build_cache.py` and live `/api/analyze` both call `src/shared/live_analyze.analyze_events` → `views.*`. Don't duplicate transform logic; add it to `views.py`.
- **Pre-cache the sample, compute the rest live:** cached GETs are the landing *sample* (a real analysis of the shipped scenario). New per-screen data = a field in `views.py`, surfaced through both. Genuinely live paths: `/analyze`, `/analyze/upload`, `/score-event`, `/predict-next`.
- **Fallbacks on live calls:** any frontend live call wraps in try/catch and degrades to a cached/deterministic result (`frontend/src/api.js` pattern) with a "cached" badge.
- **Theme through tokens:** components style via CSS custom properties from `theme.css` (`var(--accent)` etc.). Never hardcode a color in a component.
- **Reports as evidence:** every pipeline script writes a markdown report to `reports/`. Numbers in the pitch/UI must trace to a report.
- **Windows-friendly commands:** `./.venv/Scripts/python.exe -m <module>` form, documented in each script's docstring.

## What to avoid

### ML honesty (judges will probe these — non-negotiable)
- **Never report accuracy** for the detectors. 85/15 (CICIDS) and 0.006% prevalence (LANL) make it meaningless. Use PR-AUC, TPR@fixed-FPR, ROC-AUC.
- **Never train on attack labels.** Engine 1 is benign-only/unsupervised; labels are for evaluation ONLY. SMOTE/resampling = N/A by design.
- **Never show a lone metric** — always lift over baselines (random + rule; Markov vs kill-chain-order for the predictor).
- **Never headline "100% attribution"** — the profile-retrieval eval is near-trivial by construction. Demo with 3–4 observed techniques only.
- **Never quote the CERT-In manual-sequence numbers** until `verified: true` in `data/manual/cert_in_sequences.json` (currently 0/4).
- **No temporal leakage:** CICIDS splits by day, UNSW keeps official split, sequences split at sequence level. Keep it that way.
- **SOAR is simulated** — every action stays gated; critical-asset actions always "requires human approval". Never word it as real execution.

### External intel (Threat Radar)
- **Legitimate CTI feeds only.** No scraping Facebook/Instagram/X/Google — violates their terms, gets blocked, and person-level attribution from posts is irresponsible. Use feeds built for programmatic access (CISA KEV/advisories, security RSS, OTX/ThreatFox with free keys).
- **Free keys stay optional.** Any source needing a key must skip cleanly and report itself as skipped — the demo works with zero signups.
- **Precision over recall in ATT&CK mapping.** A wrong technique on screen is worse than none. Never keyword-match reconnaissance/resource-development technique names (generic English nouns → false positives). Validate every ID against `attack_lookups`.
- **Radar is enrichment, never prevention.** Alerts are simulated + human-gated like SOAR. Zero matches is a legitimate, honest result — display it, don't manufacture hits.
- **Stdlib-only fetching** (`urllib`/`xml.etree`) so the deploy image gains no dependencies.

### Boundaries for AIs / LLM features
- **No hallucinated ATT&CK IDs:** technique names/descriptions/mitigations come from `attack_lookups.pkl` (parsed real STIX). Any LLM/RAG explanation layer must be constrained to IDs that exist in the lookups.
- **AI agents:** read before editing; grep callers before changing a function; verify (build/run) before claiming done. Agents build, a human or Claude verifies before merge.
- **Don't touch verified numbers** in `api/cache/`, `reports/`, or the README without rerunning the pipeline that produces them.
- **Don't commit straight to `main`** — feature branches (`m2/anomaly-baseline` style) + PRs.

### Engineering
- **No new dependencies** for what a few lines or an installed dep can do.
- **No heavy deps in the deploy image** (`requirements-deploy.txt` stays torch/pandas-free; unpickling sklearn models is all the runtime needs).
- **Never fully decompress LANL `auth.txt.gz`** (~70 GB) — stream it (`prep_lanl.py` pattern).
- **Don't commit data/models** — gitignored. The 4 deploy artifacts already force-added are the only exception.
- **No accuracy theater in the UI** — screens show the same honest metrics as the reports.

## Error handling
- Pipeline scripts: fail loudly with actionable messages (missing artifact → name the command to run, see `attribution.load_artifacts`).
- Bonus/optional paths (autoencoder, plots): guarded try/except that skips with a printed reason — never break the primary deliverable.
- API: cached endpoint missing → HTTP 503 with "run scripts.build_cache" hint.
- Frontend: `useFetch` surfaces errors as `ErrorBox`; live widgets silently fall back (see above).
- Bad data rows: coerce, don't crash (`schema.coerce` falls back to string dtype).
