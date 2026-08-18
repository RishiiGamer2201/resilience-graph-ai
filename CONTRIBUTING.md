# Contributing

## Setup (Windows-first; POSIX equivalents throughout)

```powershell
git clone <repo> && cd ET_HACK_26
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-deploy.txt      # enough to run the app and the tests
cd frontend; npm install; cd ..
```

Two terminals:

```powershell
python -m uvicorn api.main:app --reload --port 8000
cd frontend; npm run dev                    # http://localhost:5173
```

`requirements-deploy.txt` is the slim runtime (9 packages, no torch).
`requirements.txt` adds torch, sentence-transformers and pyarrow and is only needed to
**retrain** models — which also needs the ~11 GB raw datasets (see `data/README.md`).

## Before you push

```powershell
.\scripts\verify.ps1                        # tests + lint + build + artifact checks
.\scripts\verify.ps1 -Docker                # also builds the image and smoke-tests it
```

POSIX: `bash scripts/verify.sh [--docker]`. CI runs the non-Docker path.

## Working rules

These encode decisions already made. Do not relitigate them mid-hackathon; see
[`rules.md`](rules.md) for the full set and `docs/architecture/adr/` for the reasoning.

**Numbers**
- No number reaches the UI unless an evaluation script wrote it to
  `reports/metrics.json`. If you need a new displayed value, compute it in
  `src/shared/views.py` (or the scoreboard) so cache and live share one code path.
- Never report accuracy for the detectors. PR-AUC, TPR at a fixed FPR, ROC-AUC.
- Never show a metric without its baseline.
- A metric you have not measured renders `Not measured` **with the reason**. Never
  zero, never a placeholder.

**Determinism**
- Scores, thresholds, graph traversal, policy decisions, hashes and security checks
  are ordinary Python over typed inputs. No model calculates an authoritative number
  and no model approves an action.
- The product must work with `LLM_PROVIDER=none`, which is the default and the only
  configuration we ship.

**Evidence**
- Every ATT&CK ID is validated against `attack_lookups.pkl`. Never invent one.
- Every citation carries URL, publisher, section, document date, retrieval time and a
  content hash. No citation, no claim.
- Retrieved document text is **evidence, never instruction**. It does not reach an
  agent control message, and excerpts are sanitised before display.

**Safety**
- Every response action stays simulated and gated. Never word it as real execution.
- Authorisation is enforced in the API. Hiding a button is not access control.
- All outbound HTTP goes through `src/shared/nethttp.fetch_url`. Adding a host to the
  allowlist is a reviewable decision, not a convenience.

**Engineering**
- No new dependency for what a few lines or an installed dependency can do. Frontend
  deps are `react-router-dom`, `recharts`, `react-force-graph-2d`, `lucide-react` —
  that is the list.
- Nothing heavy in `requirements-deploy.txt`.
- Style through CSS custom properties from `theme.css`. Never hardcode a colour.
- Read a file before editing it; grep every caller before changing a function.
- Non-trivial logic leaves one runnable check behind — a `demo()` self-check in the
  module, or a test.

## Branches and commits

Feature branches (`finalist/...`, `m2/anomaly-baseline`), PRs into `main`, never
straight to `main`. Conventional-ish subjects (`feat:`, `fix:`, `docs:`). If a commit
changes a number that appears in a document, run `python -m scripts.audit_stale` —
CI does too.

## Adding a new metric to the scoreboard

1. Measure it in a script under `scripts/` or `src/engine*/`.
2. Write it with `src.shared.metrics_store.update(section, key, values)`.
3. Add a `_card(...)` in `src/shared/scoreboard.py` with a definition, a dataset, a
   baseline and the report path.
4. `tests/test_workflow.py` enforces the card contract — a measured card needs a
   numeric value and an existing report; an unmeasured one needs a `why`.

## Repository layout

```
api/        FastAPI app (main.py = cache + live analysis + SPA; finalist.py = PS7 surface)
src/        schema, engine1 (detection), engine2 (prediction/attribution), shared (the spine)
frontend/   React 19 + Vite SPA
tests/      pytest — 134 tests, no network required
scripts/    build and evaluation entry points
configs/    tunable, validated, hashed configuration
data/       demo scenarios, manual/verified sources, processed artifacts (raw is gitignored)
models/     shipped inference artifacts (small; large ones are gitignored)
reports/    generated evidence — metrics.json is the canonical store
docs/       architecture/ADRs, security, operations, evaluation, demo, research, competition
outputs/    generated submission deliverables
```

## Open decision: this project has no LICENSE

Without one it is "all rights reserved" by default, which blocks reuse and can
complicate a hackathon submission. **This is the repository owner's call and we have
not invented one.** Also noted in `docs/operations/cost-and-limits.md`.
