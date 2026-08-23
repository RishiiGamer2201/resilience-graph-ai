# Cost, limits and what is actually optional

The required path costs **₹0 / $0**, needs **no credit card**, **no API key** and
**no cloud account**, and runs entirely offline after a clone. This page says exactly
what that buys and where the edges are.

Provider facts are sourced and dated in
[`docs/research/free-tier-and-stack.md`](../research/free-tier-and-stack.md).
`as_of: 2026-08-18`. **Nothing here is free forever** — re-check before the finale.

---

## Required components — all local, all free

| Component | What it is | Cost | Credential | Network | Fails how |
|---|---|---|---|---|---|
| FastAPI + Uvicorn | API + serves the built SPA | $0 | none | none | fails to boot; `/api/readiness` names the missing artifact |
| React 19 + Vite build | the SPA | $0 | none | npm install at build time | build fails loudly in CI |
| `models/ae_lanl.npz` | shipped detector, 5 KB, NumPy inference | $0 | none | none | falls back to the IsolationForest and `/api/capabilities` reports `degraded` |
| `next_technique_markov.pkl` | next-technique predictor | $0 | none | none | `/api/predict-next` errors; the rest of the investigation stands |
| `attack_lookups.pkl` | parsed ATT&CK STIX (918 techniques) | $0 | none | none | required; readiness fails |
| `evidence/index.json.gz` | 1,545 cited chunks, 474 KB | $0 | none | none | evidence node reports `skipped`, conclusions ship uncited and say so |
| `rag_corpus/corpus.jsonl` | 3,692-chunk corpus, 3.8 MB, input to the optional vector store | $0 | none | none | semantic retrieval unavailable; lexical answers instead |
| `api/cache/*.json` | a real analysis of a shipped log, used as the landing sample | $0 | none | none | cached GETs return 503 with a rebuild hint |
| `configs/vuln_priority.json` | prioritisation weights | $0 | none | none | fails loudly on load (validated) |
| `reports/metrics.json` | canonical metrics the scoreboard reads | $0 | none | none | `/api/scoreboard` returns 503 |

**Total runtime footprint:** ~9 Python packages, no torch, no GPU, no database.
Container image builds from `python:3.10-slim` + `node:20-slim` build stage.

**Measured resource use for the demo** (laptop CPU, no GPU, warm process):

| Work | Time |
|---|---|
| Full seven-node investigation, AIIMS scenario (125 events) | ~221 ms |
| Full seven-node investigation, LANL campaign (2,732 events) | ~1780 ms |
| p50 / p95 across all shipped scenarios | 242 ms / 1928 ms |
| Pipeline at the documented 50,000-event cap | 2.19 s |
| Evidence index in memory | 474 KB gzipped on disk, ~6 MB tokenised |

---

## Optional components — every one degrades cleanly

| Component | What it adds | Cost | Credential | If absent |
|---|---|---|---|---|
| Threat Radar live refresh | fresh CTI from CISA KEV / advisory + news RSS | $0 | none | serves the bundled snapshot, labelled `source: cache` |
| AlienVault OTX | subscribed pulses | $0 | free `OTX_API_KEY` | source reports itself skipped |
| ThreatFox (abuse.ch) | IOC feed | $0 | free `ABUSECH_AUTH_KEY` | source reports itself skipped |
| Bearer-token auth | real tokens instead of declared roles | $0 | `NEXTATTACK_ROLE_TOKENS` | demo-header mode, labelled as such in `/api/capabilities` |
| NVD CVSS enrichment | a severity factor for prioritisation | $0 | NVD API key for volume | CVSS shows `unknown`, the factor drops out, confidence falls |
| Local Ollama | reworded explanations | $0 | none, but a local model download | deterministic templates, which are the default product |
| Semantic retrieval | MiniLM + ChromaDB over 3,692 chunks; recall@5 1.00 vs 0.80 lexical | $0 | none, but `pip install -r requirements.txt` (pulls torch) and one corpus build | falls back to the bundled lexical index; `/api/capabilities` reports `evidence.backend` |

**No component is paid. No component is required.** `/api/capabilities` enumerates
the live state of every one of them and the UI shows a degraded banner.

---

## Hosting the demo

### Render free web service — our default

| Limit | Value | What we do about it |
|---|---|---|
| Spins down after 15 min idle | ~1 min cold start | Manual pre-demo warm-up (see the [runbook](runbook.md)) and a recorded backup. **We do not add keep-alive traffic** — that is what the hour budget prices |
| 750 instance-hours / workspace / month | shared across free services | One service. A single always-on service would use ~730 h, so this is tight by design; expect it to sleep |
| Ephemeral filesystem | writes lost on redeploy/restart/spin-down | Nothing is written. The audit chain is in-memory and exportable, and the UI says so |
| Free Postgres expires 30 days after creation | — | We use no database |
| Outbound bandwidth counted | suspension or billing over the included amount | Demo transfers a few MB; the SPA is ~110 KB gzipped |

### Local — the cheapest and most reliable option

`docker build -t nextattacks . && docker run --rm -p 8000:8000 nextattacks`, or the
two-terminal dev setup in the root `README.md`. No account, no network, no cold
start. **This is the recommended way to demo.**

### Considered and not adopted

- **Vercel Hobby** for a static SPA mirror: adds CORS and a second warm-up for no
  gain, and Hobby is restricted to non-commercial personal use.
- **Supabase**: free projects pause after a week of inactivity.
- **Neo4j AuraDB Free**: pauses after 72 hours of inactivity.
- **Railway**: not re-verified in this pass — do not call it free until someone reads
  the current terms and records the date in the research doc.

---

## Licences

| Thing | Licence | Obligation |
|---|---|---|
| MITRE ATT&CK STIX data | Apache 2.0 | attribution — carried in the README footer and every citation |
| CISA KEV | US Government work, public domain | none |
| CERT-In advisories | linked, transcribed by an analyst, marked `verified` | attribution + link |
| CIC-IDS2017 / LANL / UNSW-NB15 | respective dataset licences (see `data/README.md`) | research use; raw data is **not** committed |
| Python and JS dependencies | permissive (MIT/BSD/Apache) | standard notices |
| **This repository** | **not yet chosen** | **Owner decision outstanding — see below** |

> **Open decision: this project has no LICENSE file.** Without one it is
> "all rights reserved" by default, which blocks reuse and can complicate a
> hackathon submission. This is the owner's call to make, not ours; we have not
> invented one. Flagged in `CONTRIBUTING.md` too.
