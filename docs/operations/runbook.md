# Runbook

Operating the demo: warm-up, degraded states, and what to do when something is off.

---

## Pre-demo warm-up (do this every time, ~5 minutes)

### Local (recommended — no network, no cold start)

```powershell
# 1. backend
.\.venv\Scripts\Activate.ps1
python -m uvicorn api.main:app --port 8000

# 2. frontend, second terminal
cd frontend; npm run dev
```

Or one container, exactly what deploys:

```powershell
docker build -t nextattacks .
docker run --rm -p 8000:8000 nextattacks     # http://localhost:8000
```

### Checklist

| # | Check | Expected |
|---|---|---|
| 1 | `GET /api/readiness` | `"ready": true`, `missing_required: []`, `degraded_optional: []` |
| 2 | `GET /api/capabilities` | `degraded: []`, `keys_required: []`, `llm.provider: "none"` |
| 3 | `GET /api/health` | `cache_built: true`, `evidence_index: true` |
| 4 | Open `/investigate`, run AIIMS once | all seven stages `ok`, total under ~1 s |
| 5 | Press **Reset demo** | audit chain back to 1 record, screen cleared |
| 6 | Role picker | set to **Analyst** |
| 7 | Theme | match the projector (light usually reads better) |
| 8 | Browser zoom | 110–125% for a room; the layout is responsive |

The first run is always the slowest — it pays for pandas/sklearn imports and the
evidence index load. **Always run once and reset before presenting.**

### On Render (only if you must demo the hosted URL)

Free services spin down after 15 minutes idle and take about a minute to wake
(`docs/research/free-tier-and-stack.md`).

1. Open the URL **3 minutes before** you present and leave the tab open.
2. Watch for the wake-up page; wait for `/api/readiness` to return `ready: true`.
3. Run the AIIMS investigation once to warm the process, then reset.
4. **Do not** set up a keep-alive pinger. The 750 monthly instance-hours are the
   price of that behaviour, and gaming it is against the tier's intent.

---

## Degraded states — what the UI shows and what it means

`/api/capabilities` is the source of truth; the investigation screen renders a banner
listing anything degraded.

| Symptom | Meaning | Fix |
|---|---|---|
| `detection: degraded` | `models/ae_lanl.npz` missing; scoring fell back to the IsolationForest, which catches materially fewer red-team events at 1% FPR | restore the file; it is committed and copied by the Dockerfile |
| `evidence: unavailable` | index not built | `python -m scripts.build_evidence_index` (`--no-network` works offline) |
| Evidence stage `skipped` | same as above; conclusions ship **uncited and say so** | as above |
| `sample_cache: missing` | cached GETs 503 | `python -m scripts.build_cache` |
| `metrics: unavailable` | `/api/scoreboard` 503 | `python -m scripts.eval_ps7` and `python -m scripts.eval_retrieval` |
| Threat Radar `source: cache` | live refresh failed or was not requested | expected offline; not part of the demo |
| Scoreboard card says `Not measured` | **not a fault.** MTTR and event→technique precision are undefined for this system and say why | nothing |
| `auth_mode: demo-headers` | roles are declared, not authenticated | expected; set `NEXTATTACK_ROLE_TOKENS` for bearer tokens |

**A degraded state is never hidden.** The rule is that the investigation still
completes and each stage reports what it could not do — losing the evidence
retriever must not lose the detection. That behaviour is tested
(`tests/test_workflow.py::test_a_broken_optional_stage_degrades_rather_than_erasing_the_case`).

---

## Rebuilding artifacts

Nothing below is needed to run the app. Run it to regenerate evidence.

```powershell
python -m scripts.build_evidence_index      # evidence corpus (fetches CISA KEV)
python -m scripts.build_evidence_index --no-network   # offline: ATT&CK + CERT-In only
python -m scripts.build_cache               # api/cache/*.json (the landing sample)
python -m scripts.eval_ps7 --runs 3         # PS7 operational metrics
python -m scripts.eval_retrieval            # retrieval gold set
python -m scripts.make_results_md           # RESULTS.md from the metrics store
python -m scripts.audit_stale               # fail if any doc cites a stale number
```

Retraining the models needs the full dependency set and the ~11 GB raw datasets —
see the root `README.md`.

---

## Verification before a commit or a demo

```powershell
.\scripts\verify.ps1            # backend tests + frontend lint/build + artifact checks
.\scripts\verify.ps1 -Docker    # additionally builds the image and smoke-tests the container
```

POSIX equivalent: `bash scripts/verify.sh` (add `--docker`).

---

## Troubleshooting

**`cache 'overview' not built` (503).** Run `python -m scripts.build_cache`.

**`evidence index missing`.** Run `python -m scripts.build_evidence_index`.

**403 on an approval.** Working as intended. Check the role picker; an analyst cannot
approve a crown-jewel action. The refusal is also written to the audit chain.

**422 "this action requires a written reason".** Working as intended.

**Frontend shows sample data after an investigation.** The bundle is set on success
only; check the browser console for the API error, and check `/api/readiness`.

**Audit chain shows `BROKEN`.** Either you are looking at a deliberately tampered
export (the "Prove tamper-evidence" button), or something genuinely went wrong —
export it and check `verification_problem`, which names the first bad record.

**Analysis is slow on the first run.** Expected: imports plus the evidence index.
Warm it before presenting.

**Port already in use.** Something is still running from an earlier session; pick
another port with `--port 8001`, and remember the Vite dev proxy targets `8000`.
