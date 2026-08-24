> **Status: written 2026-08-23, against the state of `main` at commit 5a05dc4.**
> Parts of the evaluation section are now out of date on purpose: several defects
> it identifies were fixed on `harden/phase-1-integrity` immediately afterwards
> (the out-of-distribution calibration, the correlation rewrite, the NTLM
> conclusion, the fabricated frontend scores, the unmeasured decay constant).
> The competitive analysis, the market sizing and the roadmap are unaffected and
> are the reason this document is kept.

# nextATT&CKs / Resilience Graph AI -- Evaluation + Product PRD

> **Product PRD (v2).** Supersedes [prd.md](prd.md), which is the hackathon-scoped PRD
> ("Actual audience: hackathon judges"). This document evaluates the shipped system against
> product and business criteria, then specifies what the platform must become.
> Written 2026-08-14. Every defect cited was read at `file:line` or executed.

## Context

This repository is a 13-day, 93-commit, 2-identity
hackathon build (2026-07-10 → 2026-07-22) targeting **ET AI Hackathon 2026 · PS7 --
AI-Driven Cyber Resilience for Critical National Infrastructure**. It ships a real
trained anomaly detector, a real Markov next-technique predictor, a real ATT&CK STIX
corpus, a networkx attack-path graph, a live full-pipeline `POST /api/analyze`, and a
10-screen React SOC console.

The ask: (1) brutally honest evaluation of the current state, (2) a full PRD to make
this a grand, scalable product and a real startup, (3) a reasoned verdict on moving to
a **multi-agent** architecture and a **graph-first** architecture.

Stated constraints from the user: must be *simultaneously* the best hackathon entry
(where most competitors will ship thin GPT/Claude wrappers) **and** a credible startup --
because startup-grade depth is what makes the Business Impact axis (25% of the rubric)
survive scrutiny. Deployment must adapt to every customer type. Team: **2-4 people,
unfunded**. Beachhead: user asked me to pick the best one; I pick below and justify it.

**Verification note:** every defect below was read at `file:line` or executed. The three
strongest findings (Dockerfile model omission, the fake-score fallback, the no-op
correlator) were each independently confirmed by reading the source directly.

---

## VERDICT

The engineering is **more honest than the pitch**, and the pitch is **more finished than
the product**. `reports/` would survive an adversarial ML review; `PITCH_DECK.md` would
not, and every discrepancy runs in the pitch's favour. Meanwhile the deployed container
runs the *wrong model* on the *wrong calibration scale* because one 5 KB filename is
missing from a `COPY` line.

Three things are true at once:

1. **The ML is real.** Benign-trained autoencoder, exported to NumPy so the container
   needs no torch. Interpolated Markov with deleted interpolation, paired-bootstrap
   gated, with a published negative result. That is better discipline than most
   production ML teams show.
2. **The product is a demo that cannot fail -- by design, and that is the danger.** There
   is a hand-written arithmetic formula in the frontend that impersonates the ML detector
   when the API errors. An adversarial judge who pulls the network sees the demo keep
   working. That single fact, if discovered on stage, ends the pitch.
3. **It is not a product.** No persistence, no auth, no tenancy, no ingest, no real
   response execution, no entity baselines, and a live ATT&CK vocabulary of **three
   techniques**. The gap to product is not polish -- it is four missing subsystems.

The good news: the thing this repo accidentally does better than every funded competitor
is **zero-integration time-to-value** -- CSV in, full attack-path analysis out, no agents,
no SIEM connector, runs air-gapped. Dropzone/Prophet need your SIEM + EDR + IAM before
they say anything. That asymmetry is the only defensible wedge available to 2-4 unfunded
people, and it is already built. The strategy below is built on it.

---

# PART A -- EVALUATION

## A1. What is genuinely good (protect this)

| Asset | Where | Why it matters |
|---|---|---|
| **Benign-only autoencoder + NumPy export** | `src/engine1/lanl_detect.py:110-140`, `src/shared/detector.py:112-119` | Trains in torch offline, ships as plain weight matrices. Hand-rolled forward pass. Slim container, no GPU, air-gap friendly. Genuinely clever and directly reusable in the real product. |
| **Piecewise-log calibration** | `src/shared/detector.py:68-86` | benign p50→0, benign **p99→50** (the 1% FPR line), hi→100. Fixed anchors, not batch min/max, so scores are comparable across inputs. Sophisticated thinking. |
| **Interpolated Markov predictor** | `src/shared/predictor.py:70-88` | Real deleted interpolation `l2·P(t\|prev,last) + l1·P(t\|last) + l0·P(t)`, honest `frequency-fallback` label, paired bootstrap (2,000 resamples, 96%) gating promotion. LSTM lost and was **published as a negative result**. |
| **Real ATT&CK corpus** | `src/shared/parse_attack.py` (182 lines) | Genuine STIX parse: 918 techniques, 771 with mitigations, 175 groups, 59 campaigns. Every emitted ID is validated against it -- no hallucinated IDs. |
| **Attribution labelled as retrieval** | `src/engine2/attribution.py:1-9,177` | Explicitly *not* a classifier. `0.55·coverage + 0.20·jaccard + 0.25·semantic` over real 384-d MiniLM vectors, and the eval docstring warns about its own circularity unprompted. |
| **`tests/` (31 tests, 331 lines)** | `tests/test_live_analyze.py`, `test_osint.py` | Exact-value regression tests that lock real past bugs: score-pegging (`:35-43`), the 4-pivot fix (`:166`), ISO-8601 crash (`:107-117`), cross-screen consistency (`:171-178`). This is burned-hands testing, not coverage theatre. |
| **Honesty discipline in `reports/`** | `reports/*.md`, `rules.md` | Refuses to report accuracy. Publishes the rule baseline as **worse than random** (ROC 0.25). Publishes **PR-AUC 0.0082** beside ROC 0.992. Publishes recall **0.000** on all Web Attack families. Publishes the NTLM ablation. Very few repos do any of this. |
| **Per-feed isolated OSINT** | `src/shared/osint.py:441-448` | Real `urllib` calls to CISA KEV, CISA advisories, ET CISO, THN, BleepingComputer. One dead feed degrades gracefully. Actively rejects HTML masquerading as RSS (`:334-336`) -- and documents that CERT-In has no working feed. |
| **Theming** | `frontend/src/theme.css`, `lib/theme.jsx`, `Graph.jsx:325` | Full light/dark token sets, `prefers-reduced-motion` honoured in **both** CSS and JS, `cssVar()` feeds the canvas so the force graph re-themes. The most professional part of the frontend. |
| **Zero-integration ingest** | `api/main.py:325-355`, `src/shared/live_analyze.py` | CSV or JSON rows → full spine → every screen. No agent, no connector, no SIEM. **This is the strategic asset and nobody labelled it as one.** |

## A2. Critical defects -- ranked, P0 first

### P0-1 · The deployed container runs the retired model on the wrong calibration scale
`Dockerfile:21` copies only `iforest_lanl.joblib` and `next_technique_markov.pkl`.
`models/ae_lanl.npz` (**5,062 bytes, tracked in git**) is simply not on the COPY line.

Trace: `detector.available()` → `False` → `_load()` → `None` → `raw_scores()` falls
through to the **IsolationForest** (`detector.py:105-110`). Measured TPR@1%FPR **51.4%,
not 87.7%**.

It compounds: `anchors()` also reads the `.npz`, returns `None`, so calibration falls back
to committed `api/cache/score_ref.json` -- which contains **autoencoder reconstruction-error
anchors** (`p99: 0.042`, `"detector": "autoencoder"`) applied to **IsolationForest scores**.
Different quantity, different scale. **Every 0-100 severity number the live demo shows is
calibrated against the wrong distribution.** `/api/health` returns `{ok: true}` without
ever touching the detector.

Meanwhile `Analyze.jsx:58` asserts *"Every event is scored by the real benign-trained
autoencoder."* The only accurate label in the deployed build is the one that looks like a
bug: `LiveScoreWidget.jsx:157` -- `Isolation-Forest · LANL model`.

**Fix: add `models/ae_lanl.npz` to `Dockerfile:21`. One word. Highest value change in the repo.**

### P0-2 · A hand-written formula impersonates the ML model on the frontend
`frontend/src/api.js:2-3` states the intent: *"the two LIVE POSTs fall back to a cached
example result on any error, so the demo never breaks mid-pitch."*

`api.js:91-107`:
```js
(features.new_dst_for_user ? 28 : 0) + (features.is_ntlm ? 28 : 0)
  + (features.is_fail ? 12 : 0) + …
```
Same `{anomaly_score, severity}` shape as the real endpoint. Only tell is a small
`○ cached` dot. `api.js:112-118` does the same for predictions -- five hardcoded ATT&CK IDs
served as model output.

And `LiveScoreWidget.jsx:34-55`: the **"Why this score?" panel is a client-side rule
engine**, not model attribution -- prose reverse-engineered over the same inputs, presented
as explainability.

This is the highest-credibility-risk item in the repo. It is not fraud (it is labelled,
faintly), but a judge who disconnects the backend and watches the score still appear will
conclude the whole thing is fake. **Fix: on failure, show a visible degraded state. Never
synthesise a score.**

### P0-3 · The "correlation engine" performs no correlation
`src/shared/correlate.py:19`:
```python
SESSION_GAP = 3600   # seconds; a >1h silence starts a new session
```
`grep -rn SESSION_GAP` across the entire repo returns **that one line**. Never read. The
docstring at `:7-8` claims *"Groups alerts by user + session."* It does neither: it sorts
by timestamp, loops every row, and returns **one incident containing the whole DataFrame**.

So the headline **"2,732 events → 1,243 alerts → 1 incident"** -- quoted in `PITCH_DECK.md`,
`BRIEF.md`, `EXPLAINER.md` and the demo script -- is arithmetically true because the
function is hardcoded to return exactly one incident for any input. Feed it two unrelated
attacks a month apart: one "incident."

### P0-4 · The live ATT&CK vocabulary is three techniques
`attack_mapper.py:24-34` is a 9-entry dict. But the live path never reaches most of it --
`infer_lanl_event_type()` (`:69-83`) is a 5-branch if/else returning exactly four strings,
and `correlate.py:42` prefers it whenever engineered columns exist, **which is always** in
`live_analyze`.

Net: every incident the product can produce has a technique vocabulary of
**{T1110, T1550.002, T1021}**. Exfiltration, Collection, Discovery and Initial Access are
structurally unreachable. The "attack chain" the UI draws is a re-skin of three booleans.

Downstream consequence: the Threat Radar's flagship "where am I exposed?" cross-reference
**structurally returns zero matches on the default state** -- I verified `relevance>0 count: 0`
across all 40 items -- and `ThreatRadar.jsx:233-241` contains a **hardcoded paragraph
pre-explaining why there are no matches**. ~90 lines of alert-queue/approve/draft-advisory
UI is unreachable.

### P0-5 · There is no behavioural baseline -- the core UEBA premise is missing
`lanl_detect.py:53-76` recomputes every "behavioural" feature from **whatever DataFrame you
just uploaded**:
```python
df["new_dst_for_user"] = (~df.duplicated(["user","destination_host"])).astype("int8")
dc = df["destination_host"].value_counts()
df["dst_rarity"] = (-np.log(df["destination_host"].map(dc) / total))
```
`total` is the uploaded file's row count. There is no profile store, no history, no DB. So
"rarity" and "fan-out" mean something completely different in a 30-row CSV than in the
2,732-row window the detector was calibrated on.

Measured (executed, not inferred):

| Input | Events | Alerts | Precision |
|---|---|---|---|
| 30 identical routine Kerberos auths, same user, same host pair, all success | 30 | **30 (100%)** | -- |
| `lanl_campaign_all.csv` | 2,732 | 1,243 (45%) | 0.53 |
| `aiims_ransomware.csv` | 125 | **125 (100%)** | **0.28** |
| `cbse_exam_breach.csv` | 127 | **127 (100%)** | **0.29** |

**The product's own two flagship India demos flag every single event.** Thirty byte-identical
benign events score 58-69, all above the alert line of 50.

### P0-6 · Precision at the headline operating point is ~0.5%
`reports/lanl_redteam_detection.md:29` -- at 1% FPR: **616 true positives against 112,212
false positives**. `:22` -- **PR-AUC 0.0082**. Both are in the report; neither is in the
pitch. The deck's entire problem framing is alert fatigue, and it never converts its own
operating point into alerts-per-day. That is the first question any SOC buyer asks.

Real LANL prevalence is **0.0063%** (11.2M events, 702 malicious). The demo scenarios run at
**~26% prevalence** -- a ~4,000× inflated base rate. ROC-AUC 0.992 is real for the paper and
close to meaningless for the product.

### P0-7 · The NTLM ablation says the opposite of what the deck concludes
`reports/lanl_redteam_detection.md:34-36`: 100% of red-team auths are NTLM vs ~6% benign.
Remove `is_ntlm` and **TPR@1%FPR collapses 87.7% → 22.8%** -- a 74% relative drop from
dropping one trivially evadable protocol flag (the attacker just uses Kerberos).

The report states this. `PITCH_DECK.md:194` reports only the ROC number that hides it
(0.906) with the note *"not a protocol crutch."* **It is a crutch.** This is the single most
misleading item in the docs, and an ML-literate judge will find it in one question.

### P0-8 · Hardcoded metrics on the Overview screen and in the "audit-ready" report
`src/shared/views.py:35-40`:
```python
SCORECARD = [
  {"name": "LANL lateral movement", "metric": "ROC-AUC", "value": 0.988, ...},
  {"name": "Next-technique (Markov)", "metric": "top-3", "value": 0.386, ...},
]
```
`0.988` is the retired IsolationForest (`metrics.json` says **0.992**). **`0.386` appears in
no report and no `metrics.json`** -- the real values are 0.365 and 0.381. It is a
third-generation orphan with no source. Repeated at `views.py:319` and printed into the
downloadable report via `IncidentReport.jsx:24`.

`PITCH_DECK.md:268` claims *"Eval scripts write reports/metrics.json; the UI reads it --
**drift impossible**."* `rules.md:22`: *"No fabricated display data."* Both false for this
screen. `build_cache.py:50-54` already does it correctly -- `views.py` just bypasses it.
And `DEMO_SCRIPT.md:52` points a camera at it: *"here are our model scores, from honest testing."*

### P0-9 · Frontend fabrications that survive a live upload
- `Incident.jsx:53` -- `new EventSource(streamUrl('lanl_redteam_u66'))`. **"Stream live" is
  hardwired to one scenario name.** Upload a bank CSV, click Stream live, watch it stream
  the LANL log over your incident.
- `Incident.jsx:127-133` -- "What this means" is a hand-written narrative asserted for *any*
  log: *"The account appears to reuse stolen authentication material…"*
- `Layout.jsx:7,9` -- hardcoded persona `Grid operator · DOM1` and incident `INC-PS7-LANL-001`
  while every payload says `INC-PS7-LANL-CAMPAIGN`.
- `MttdPanel.jsx:3-5,32` -- the comment admits the chart lies: *"Proportional bars would make
  'ours' invisible… so we use fixed emphasis widths"* → `width="3%"` hardcoded.
- `Analyze.jsx:70` -- card headed `Sample scenarios · 1-click, **real data**` lists the
  fabricated `aiims_ransomware` and `cbse_exam_breach` unlabelled beside the real LANL log.

### P1 · Correctness and robustness
- `main.py:349` -- `raw = await file.read()` with **no size limit**; `MAX_ROWS = 50_000` is
  checked in `live_analyze.py:61` only *after* pandas has parsed the whole file. A 2 GB CSV
  OOMs the container. `MAX_ROWS` is imported into `main.py:287` and never used.
- `main.py:358-386` -- `analyze_stream` is `async def` but calls blocking
  `analyze_events(pd.read_csv(...))` at `:372`, **blocking the event loop** for the entire
  analysis. (The sync endpoints are fine -- FastAPI threadpools them.)
- `main.py:80` -- `CORSMiddleware(allow_origins=["*"], allow_methods=["*"])`.
- No error boundary anywhere in the frontend. Live crash paths: `Graph.jsx:102-103`
  (`Math.min(...[])` → `Infinity`), `Metrics.jsx:42` (`Math.max(...[])` → `-Infinity`),
  `IncidentReport.jsx:10` (unguarded `.toUpperCase()`).
- `useFetch.js:18` -- `useEffect` with empty dep array + eslint-disable. No cache, no dedupe,
  no retry. `Graph.jsx:132`, `Attackers.jsx:16`, `ThreatRadar.jsx:154-156` each independently
  refetch; `/graph` is a **350 KB** payload that ThreatRadar POSTs all 484 edges of straight
  back to the server on every mount.
- **Fresh clone is dead on arrival.** `.gitignore` excludes `data/processed/*`, `models/*`,
  `*.pkl`, `*.joblib`; `views.py:18` calls `load_artifacts()` at module scope, so the API
  500s on import. The image only builds on a machine that already ran the offline pipeline.
  Nothing is retrainable from the repo alone.
- `testsprite_tests/` -- 22 generated scripts, **zero result artifacts**, and at least one
  encodes a wrong expectation (`TC006:44-49` asserts 422 for empty `technique_ids`; the
  endpoint returns 200 with a `frequency-fallback`). The claims "29 tests" (README says 27,
  code has 31) and "TestSprite 14/15" are unverifiable.

### A2b · The scaling chart measures a fixed-size graph
`scripts/make_scaling_chart.py:44-51` concatenates `lanl_campaign_all.csv` to itself with
offset timestamps. The tell is sitting in the JSON: `hosts` is **473 at 2,732 events and
still 473 at 50,000**. A graph pipeline whose node count never grows is not being scaled --
shortest-path, betweenness and the correlation join are all pinned at campaign size while
only the per-event scoring loop grows. The script's docstring labels this honestly; the
deck does not. Real measured single-process throughput is ~20k events/s with a `MAX_ROWS`
ceiling of 50,000 and every result discarded on response.

## A3. Structural gaps -- why this is a demo, not a product

Grepped across `src api scripts requirements*.txt Dockerfile render.yaml` for
kafka/redis/celery/sqlalchemy/postgres/sqlite/mongo/neo4j: **one hit, and it is a sentence
in a Word-doc generator.**

| Missing | Consequence |
|---|---|
| **Any persistence** | Every analysis is discarded when the response is sent. No case history, no baselines, no learning, no audit trail. The Threat Radar alert queue is React `useState` -- refresh and every approval evaporates. |
| **Auth / tenancy / RBAC** | Not one `Depends()`. No org/user/tenant concept. `Login.jsx` is a 23-line button. Unsellable to anyone. |
| **Ingest** | Data arrives only as a JSON body or a multipart CSV. `/api/analyze/stream` is **not** streaming ingest -- it computes everything synchronously up front then dribbles precomputed steps with `asyncio.sleep(0.15)`. The docstring admits it paces "the on-stage reveal." |
| **Real response execution** | `soar.py` is 89 lines of dict construction. Six hardcoded action strings. No EDR, firewall, IAM, ticketing, webhook, or subprocess call. Correctly labelled `⚠️ SIMULATED`. |
| **Any LLM or agent** | Zero. Grepped openai/anthropic/langchain: nothing. PS7 explicitly lists *"Agentic AI / Multi-Agent Systems"* as suggested tech and weights Innovation at 25%. |
| **IT/OT correlation** | The PS7 challenge text says *"correlate weak IT/OT signals."* IT auth logs only. ICS ATT&CK is parsed for lookups; no OT telemetry, no Modbus/DNP3/PROFINET. |
| **Vulnerability prioritisation** (PS7 bullet 4) | Never built. NVD is never called -- it appears only as a link URL at `osint.py:314`. |
| **Digital twin** (PS7 bullet 5) | Never built. |
| **Compliance story** | Grepped every `.md` for `CERT-In 6-hour|DPDP|ISO 27001|SOC 2|air-gap|on-prem|GeM|empanel|NCIIPC`: the **6-hour incident-reporting directive is never mentioned once**. Neither is on-prem -- despite the architecture being unusually well suited to it. The strongest deployment story in the repo is never told. |
| **Data provenance** | Zero bytes of LANL / CIC-IDS / UNSW in the repo. Every headline metric rests on files that cannot be verified from this checkout. |

Also descoped from the original plans and never built: attack-path **GNN**
(`research/codex/ps7.md` §11.4), **Neo4j** knowledge graph, **RAG + LLM** explanation layer
(§15), LANL **dns/flows/proc** streams (downloaded, never used -- the root cause of the
3-technique ceiling), and mapping/correlation/response **metrics** (§13.2-13.4 -- so there is
no ATT&CK-accuracy number because nothing measures ATT&CK accuracy).

## A4. Claim-vs-evidence ledger

**Backed by a regenerable report:** LANL ROC 0.992 / TPR 87.7%@1%FPR / behavioural-only
0.906 · CIC-IDS PR-AUC 0.570 · UNSW ROC 0.829 · Markov top-3 38.1% vs kill-chain 7.1%
(5.4×) · CERT-In non-circular top-3 10.0% · attribution retrieval 100% · 918 techniques /
205 sequences.

**Claimed in pitch docs with no report at all** -- these are the numbers the deck, the demo
video and the brief *lead with*, and they trace only to `api/cache/*.json` (a real run, so
not fabricated, but not regenerable evidence):
`2,732 → 1,243 → 1` · `104 accounts` · `473 hosts / 484 movements / 4 pivots` ·
**"isolate C17693 → cuts 463 hosts"** (the deck's self-declared killer line) ·
`16 crown jewels / 469 exposure` · `670 of 702` · `T1566.001 → T1566.002 @ 52.5%` ·
`29 tests` · `TestSprite 14/15`.

This violates the project's own `rules.md:27`: *"Numbers in the pitch/UI must trace to a
report."* The one spine report that exists (`reports/spine_incident.md`) is **two
generations stale** -- 215 events, 94 hosts, IsolationForest.

**Contradictions, all quotable, none reconciled:**

| Claim | Value A | Value B |
|---|---|---|
| LANL ROC-AUC | `metrics.json:14` **0.992** (AE) | `overview.json:90`, `report.json:94`, `views.py:36,319` **0.988** (IF) |
| Next-technique top-3 | `metrics.json:36` **0.381** | `overview.json:108` **0.386** -- source: nowhere |
| Shipped detector | `metrics.json:17` Autoencoder | `LiveScoreWidget.jsx:157` Isolation-Forest; `Dockerfile:21` ships only the IF |
| Incident ID | payloads: `INC-PS7-LANL-CAMPAIGN` | `Layout.jsx:9`: `INC-PS7-LANL-001` |
| Prediction vocab | `prediction_eval.md:3` 566 | `sequences.md:5` 622 |

**"Weeks → minutes" is a citation minus a tautology.** `overview.json`: `ours_seconds: 0`,
`"immediate"`. `memory.md:39` admits why -- the exported window *starts at the pivot host*, so
event 1 is already an alert. `views.py:26-30` correctly labels the 10-day figure a Mandiant
citation. Then `README.md:8` and `PITCH_DECK.md:40` headline the compression anyway.

**Attribution theatre.** `report.json:47-50` names **"Ember Bear"** at *"100% coverage."*
`threat_intel.json` shows the top five at 0.753 / 0.556 / 0.555 / 0.555 / 0.552 -- APT28,
Aquatic Panda, Wizard Spider and APT41 separated by **0.001**, on three techniques
(pass-the-hash, brute force, remote services) that hundreds of groups use. Naming one actor
off that margin is not attribution, and `attribution_eval.md:3` concedes the 100% only
measures recovering a group from a subset of its own profile -- which cannot fail.

**Credit where due:** the honesty is real and unusual. `EXPLAINER.md:564-569` volunteers four
things the team caught themselves fabricating, including a "crown jewel" that *"was literally
the middle element of a list, presented as a finding."* `scripts/audit_stale.py` exists purely
to hunt the team's own stale figures. `ET_Hackathon_2026_Analysis.md:305` records that the
team's own pre-project scoring ranked **PS7 fourth (3.88)** with *"Risk: High (domain)"*.
That is a level of self-criticism almost no hackathon repo has.

---

# PART B -- STRATEGY DECISIONS (the load-bearing calls)

## B1. Beachhead -- I pick, and here is the reasoning

You said "everyone, but the best." Serving everyone from day one with 2-4 unfunded people is
how this dies. So: **one product, one architecture, a deliberate three-step sales sequence.**

Rejected, with reasons:
- **Global mid-market SaaS.** Dropzone ($57.4M, 100+ customers, **85+ integrations**),
  Prophet ($41M, Accel/Bain + Amex/Citi Ventures), plus CrowdStrike Charlotte AI, Microsoft
  Security Copilot, Google SecOps/Gemini and SentinelOne Purple AI all shipped agentic SOC
  tooling at RSAC 2026. AI-native security took **$4.1B in Q1 2026 alone, +47% YoY**. The
  competitive axis there is integration surface. You cannot win a connector war unfunded.
- **India gov/CNI direct, first.** Highest mission fit, matches PS7, strongest long-term
  moat -- and a 12-18 month tender cycle, CERT-In empanelment (231 orgs hold that gate),
  NCIIPC requirements, and on-prem field engineering. You will run out of money before the
  first PO. This is the *lighthouse*, not the beachhead.
- **MSSP/SI channel, first.** Solves distribution but demands multi-tenancy, SLAs and
  maturity on day one, and squeezes margin. Correct as **step 2**, wrong as step 1.

**Chosen beachhead: Indian BFSI + regulated enterprise, entered through a paid
zero-integration Attack-Path Assessment.**

Why this specific wedge:
1. **It is the only motion that needs no integration surface** -- the axis where you cannot
   be outspent. Customer exports 30-90 days of auth/VPN/AD logs; you return a graph, an
   attack-path report, a ranked choke-point list and a blast-radius model. Time to value:
   one day. Dropzone needs your SIEM, EDR and IAM before it says anything.
2. **The repo already does this.** `POST /api/analyze` + the graph + the printable report
   *are* the assessment deliverable. You are ~4 weeks from a saleable service, not 12 months
   from a saleable platform.
3. **It generates revenue that funds the platform, and telemetry that builds the moat.**
   Every assessment is a labelled graph from a real estate -- the one dataset no competitor
   has and no foundation model can commoditise.
4. **RBI/SEBI pressure + the CERT-In 6-hour reporting directive** create urgency without a
   tender. BFSI buys pilots on a PO.
5. It is the natural on-ramp to both other segments: the same engine, same graph, same
   report. CNI is the same product with an air-gap flag. MSSPs are the same product with
   tenancy.

**Sequence:** assessment (paid, 2-6 weeks each) → continuous monitoring subscription on the
same graph → MSSP/SI wholesale → CNI/gov with a reference customer and a compliance dossier
already in hand.

**One thing to fix immediately, free:** the CERT-In 6-hour reporting directive is mentioned
**zero times** in the entire repo. It is the single cheapest, strongest business hook
available -- it converts "detection speed" from a nice-to-have into a **statutory obligation**
for every body corporate, intermediary, data centre and government org in India, with no size
exemption. A "CERT-In 6-Hour Report" button that auto-drafts the incident notification from
the graph is a one-week build and the most quotable business slide you can own.

## B2. Deployment -- one codebase, two planes

You want it to fit everyone. That is achievable, but only with the split declared up front,
because retrofitting it later is a rewrite.

**Local data plane / remote control plane.**

- **Data plane** (always customer-side): ingest, normalisation, entity baselines, the graph,
  detection, correlation, response execution. Never phones home with telemetry. Ships as one
  container + one embedded database. Runs air-gapped.
- **Control plane** (cloud, optional): threat intel bundles, detection-content updates, model
  artifacts, licensing, cross-tenant benchmarks, the agent layer when the customer permits it.
- **Air-gap mode**: control-plane artifacts ship as a **signed offline bundle** (ATT&CK
  snapshot, KEV/NVD snapshot, model weights, detection content) that an operator sideloads.
  The repo already proves this pattern works -- `threat_radar.json` is exactly a committed
  intel snapshot with graceful degradation.
- **SaaS mode**: the same data plane, run by you, one instance per tenant, tenant ID on every
  row. *Not* software-only isolation for regulated buyers -- namespace-per-tenant.
- **LLM boundary is a config flag, not an architecture:** `frontier | self-hosted | none`.
  Air-gapped CNI gets a local model or a fully deterministic mode. **Every agentic feature
  must degrade to a deterministic path** -- this is a hard requirement, not a nice-to-have,
  because it is what makes one product sellable to all four segments.

The existing build is accidentally well-positioned for this: single container, no GPU,
stdlib-only networking, NumPy inference. **Say so out loud** -- it is a genuine differentiator
against every cloud-native competitor, and it is currently unmentioned.

## B3. Multi-agent -- YES, but only above the funnel choke point

Brutally honest, both directions.

**Why the naive version is wrong.** "Multi-agent" as the whole architecture is the fastest
way to lose an ML-literate Q&A and the fastest way to a product that cannot be operated.
The 2026 research is unambiguous: agentic workflows suffer **compounding failure** (one bad
routing decision cascades through every downstream step, and failures start mid-run, not at
the final response), make **3-10× more LLM calls** than a chatbot, and stall on **lack of
trace-level visibility** (named in McKinsey's 2026 report as a top reason agent rollouts
fail). Meanwhile VCs have concluded generic LLM-wrapper startups are dead -- *"the AI moat is
not the model."*

**The economics settle where agents can live.** Run the numbers for a mid-size estate at
~1M events/day:

| Placement | Volume/day | Even at ~200 tok/item | Verdict |
|---|---|---|---|
| Agents on **events** | 1,000,000 | ~200M tokens/day | Absurd. Cost and latency both fatal. |
| Agents on **alerts** (45% rate as built) | 450,000 | ~90M tokens/day | Still absurd. |
| Agents on **entity-days** (post-baseline) | ~500-2,000 | manageable | Viable for enrichment. |
| Agents on **incidents** | ~10-50 | ~50k tok each = ~2.5M/day | **This is where agents belong.** |

**So: deterministic below the choke point, agentic above it.** Not a compromise -- it is the
correct architecture, and it is also the *better pitch*, because "we know exactly where an
LLM is allowed to touch our pipeline, and why" is what separates you from the wrapper
projects you are worried about.

**Tier 0-1 -- deterministic, no LLM.** Normalise → per-entity behavioural scoring against a
persistent baseline → graph update → risk aggregation → candidate incident formation. Must be
fast, reproducible, cheap, replayable, and identical on every run. An LLM here buys nothing
and costs everything.

**Tier 2 -- the agent layer** (input: O(10-50) incidents/day, already reduced):

| Agent | Job | Constraint |
|---|---|---|
| **Investigator** | Gather evidence by querying the graph and event store. Build a timeline. | Tool calls only over a fixed tool surface. No free-form SQL. Every claim carries an evidence ID. |
| **Attributor** | RAG over ATT&CK groups, CERT-In advisories, KEV/NVD. Rank candidates. | Must emit a **calibrated distribution with margins**, and must refuse to name one actor when the top-5 are separated by 0.001 -- exactly the failure in `report.json:47-50` today. |
| **Critic** | Adversarially try to **refute** the Investigator's hypothesis. | Defaults to "refuted" under uncertainty. This is the reliability mechanism, not decoration. |
| **Response Planner** | Propose a containment plan. | Emits **structured actions only**, validated against a schema, then against the policy engine. Never prose that a human interprets as authority. |

**Tier 3 -- deterministic policy engine holds the trigger. Non-negotiable.** No LLM ever
executes an action. The planner *proposes*; a deterministic engine evaluates blast radius,
asset criticality, business hours and change freeze, then either auto-executes inside a
pre-approved envelope or escalates to a human. Every action signed, logged, reversible, with
a recorded rollback. PS7's evaluation focus explicitly demands *"full auditability of every
automated action taken"* -- this is how you earn that sentence instead of asserting it.

**Concretely for the hackathon:** this design lets you claim a multi-agent system *and*
survive the "so what stops your LLM from hallucinating a host isolation?" question with a
one-sentence answer. Most competitors will not have one.

## B4. Graph -- YES, and make it the system of record

Currently the graph is a **derivative**: built after correlation, only from alerts, rebuilt
per request from scratch, thrown away on response. 473 nodes in memory. `betweenness_centrality`
over the whole graph (`attack_graph.py:71`) -- fine at 473 nodes, dead at 100k.

**It should be the substrate everything else is a query against.** A persistent, temporal,
heterogeneous property graph: identities, hosts, processes, credentials, services, OT assets,
CVEs, controls, ATT&CK techniques -- continuously updated from telemetry, with time on every
edge.

Why this is the right bet and not just architecture aesthetics:

1. **It unifies all five PS7 bullets into one substrate instead of five features.** Anomaly
   detection = anomalous edge/subgraph. Attribution = subgraph-to-TTP-pattern match.
   Vulnerability prioritisation = "which CVE sits on a path to a crown jewel" (a query, not
   a new module -- and it closes PS7 bullet 4, currently unbuilt). Digital twin = simulate on
   the graph (PS7 bullet 5, currently unbuilt). Response = cut the minimum edge set.
2. **It is the moat.** Nobody else has your customer's graph, and no foundation model can
   commoditise it. This is the "vertical AI with proprietary data" pattern that survives
   while horizontal wrappers do not. Every assessment you sell deepens it.
3. **The research supports graph-native lateral-movement detection** over flat feature models
   -- CyberGFM (graph foundation models, Jan 2026), HetGLM, LONGAN. Your current 7 flat
   features per row are the weakest form of this.
4. **It makes the name true.** The repo is called `resilience-graph-ai` and the graph is
   currently the thinnest layer in it.

**Honest costs and the lazy path.** Don't buy Neo4j, and don't build a GNN first.

- **Storage:** the truth is an append-only event/edge store. Start with **Postgres**
  (Timescale if volume demands) -- an `edges` table with `(src, dst, type, technique, t, tenant)`
  plus recursive CTEs covers path queries for a long time. For the on-prem single-binary case,
  **Kùzu** (embedded graph DB, SQLite-for-graphs) is the strongest fit and keeps the
  one-container deployment story intact. **Choose based on a measured query, not a diagram.**
- **Algorithms:** betweenness over the full graph does not scale. Use **scoped subgraphs**
  (blast radius from confirmed pivots, k-hop neighbourhoods) and **approximate/incremental**
  centrality. `igraph` over a scoped subgraph beats networkx over everything.
- **Learning:** a GNN is Phase 3, not Phase 1. Graph *features* (fan-out, path novelty,
  neighbourhood rarity, credential reuse degree) fed to the existing autoencoder will get you
  most of the lift for a fraction of the work. Ship that first.

## B5. The moat, stated plainly

Not the model. Not the LLM. Four things, in order of durability:
1. **Per-customer graph + baselines** -- deepens monthly, non-portable, non-commoditisable.
2. **Zero-integration + air-gap capability** -- a structural advantage over every cloud-native
   competitor, and mandatory for the segments they cannot serve.
3. **India regulatory fit** -- CERT-In 6-hour drafting, NCIIPC alignment, DPDP-safe data
   handling, CERT-In empanelment as a channel gate you eventually pass through.
4. **Auditability** -- every automated action signed, logged, reversible. The thing regulated
   buyers actually sign for, and the thing agentic competitors are weakest on.

---

# PART C -- TARGET ARCHITECTURE

```
INGEST            batch CSV/JSON (day 1) → syslog/S3/Elastic/Splunk pull (P2) → streaming (P3)
                  Normalise to OCSF-aligned schema. Extend src/schema.py; keep the alias
                  coercion layer, it is already good.
      ↓
ENTITY BASELINE   PERSISTENT per-user / per-host / per-service profiles with sufficient
[NEW -- P0]        history + cold-start policy. Fixes P0-5. Without this nothing else is real.
      ↓
GRAPH STORE       Temporal heterogeneous property graph. System of record. Append-only edges.
[NEW -- core]      Postgres/Timescale (SaaS) | Kùzu (single-binary on-prem).
      ↓
DETECTION         Existing autoencoder + graph features (fan-out, path novelty, neighbourhood
                  rarity, credential-reuse degree). Multi-signal, no single evadable flag
                  (fixes P0-7). Per-entity, per-window.
      ↓
RISK AGGREGATION  Score ENTITIES over time windows, not events. This is what collapses the
[NEW -- P0]        45% alert rate to something a SOC can run. Fixes P0-6.
      ↓
CORRELATION       Real temporal + graph-connectivity clustering into MANY incidents.
[REWRITE]         Replaces the no-op in correlate.py. Fixes P0-3.
      ↓
TECHNIQUE MAPPING Detection-content library (Sigma-style rules over the normalised schema)
[REWRITE]         + evidence-based mapping to ATT&CK. Target 40+ techniques across 8 tactics,
                  each with a measured precision. Fixes P0-4. Requires the LANL
                  dns/flows/proc streams that were downloaded and never used.
      ↓
─────────────── CHOKE POINT: O(10-50) incidents/day ───────────────
      ↓
AGENT LAYER       Investigator · Attributor · Critic · Response Planner.
[NEW]             Structured output enforced. Tool-call-only. Evidence IDs on every claim.
                  Degrades to deterministic templates when LLM is unavailable/disallowed.
      ↓
POLICY ENGINE     Deterministic. Blast-radius + criticality + time-window gates.
[NEW]             No LLM in the execution path. Ever.
      ↓
ACTION EXECUTION  Real connectors (EDR isolate, IAM disable, firewall block, ticket) behind
[NEW]             one Action interface. Every action signed, logged, reversible, rollback
                  recorded. Replaces the 89-line string generator in soar.py.
      ↓
SURFACES          SOC console (rebuild from the existing screens) · CERT-In 6-hour report
                  drafter · Assessment PDF · API · digital-twin simulator (P3)
```

Cross-cutting from day one: tenant ID on every row · immutable audit log · secrets management ·
signed offline bundles · `/health` that actually verifies the model loaded (fixes the P0-1
blind spot).

---

# PART D -- PRD

## D1. Product

**One-liner.** A behavioural graph of your estate that finds low-and-slow attackers in the
logs you already have, shows the exact path to your crown jewels, and contains it under
policy you control -- deployable air-gapped, auditable end to end.

**Positioning.** Not an "AI SOC analyst" (crowded, funded, integration-gated). An **exposure
and attack-path intelligence layer** with autonomous investigation on top. The graph is the
product; the agents are the interface to it.

## D2. Personas & jobs-to-be-done

| Persona | Job | Success looks like |
|---|---|---|
| SOC analyst (L1/L2) | "Give me one story, not 1,200 alerts, and show me why." | Opens an incident, sees the timeline with evidence links, accepts or rejects in under 5 min. |
| SOC lead / CISO | "What is my real exposure, and what do I fix first?" | Ranked choke-point list with blast radius. Board-ready exposure trend. |
| Compliance officer | "File CERT-In within 6 hours, defensibly." | Auto-drafted notification with a complete evidence trail. |
| IT/OT ops | "Don't take my plant down." | Every action gated by blast radius; OT assets flagged no-auto-action by default. |
| MSSP analyst (P2) | "Run 40 clients from one console." | Tenant switcher, cross-tenant triage queue. |

## D3. Requirements

**P0 -- credibility floor (nothing ships without these)**
- R1 `Dockerfile:21` ships `ae_lanl.npz`; `/api/health` verifies which detector actually loaded
  and refuses to start on a calibration/detector mismatch.
- R2 Delete `api.js:91-118` fallbacks. On failure, visible degraded state. **Never synthesise
  a score.** Same for `LiveScoreWidget.jsx:34-55` -- relabel as "rule-based reasoning," not
  model explanation.
- R3 Delete `views.py:35-40` and `:319`; read from `metrics.json` like `build_cache.py:50-54`
  already does. Add the drift check to `audit_stale.py`.
- R4 Persistent entity baselines + cold-start policy. **Acceptance: 30 identical benign
  events produce 0 alerts.**
- R5 Real correlation (temporal + graph connectivity) producing many incidents. Delete
  `SESSION_GAP` or use it. **Acceptance: two unrelated attacks a month apart → 2 incidents.**
- R6 Entity-level risk aggregation. **Acceptance: alert rate < 1% of events on a realistic-
  prevalence log; a stated alerts-per-day figure at the shipped operating point.**
- R7 Multi-signal detection with no single evadable dominant feature. **Acceptance: ablate any
  one feature, TPR@1%FPR drops < 20% relative** (today NTLM ablation costs 74%).
- R8 Fix `Incident.jsx:53` hardwired scenario, `:127-133` asserted narrative, `Layout.jsx:7,9`
  fake persona/ID, `MttdPanel.jsx:32` misleading bars, `Analyze.jsx:70` unlabelled synthetic
  scenarios.
- R9 Streaming upload with a size limit **before** parse; `analyze_stream` off the event loop;
  CORS allowlist; one error boundary.
- R10 Reproducible from a clone: bootstrap script fetches/builds artifacts, or artifacts ship
  via LFS. `views.py` must not `load_artifacts()` at import.

**P1 -- product floor (before any paying customer)**
- R11 Auth (OIDC/SAML), RBAC (analyst / lead / admin / read-only), API keys.
- R12 Tenancy: tenant ID on every row, namespace-per-tenant for regulated buyers.
- R13 Persistence: incidents, cases, baselines, graph, actions, audit log.
- R14 Immutable audit log: who/what/when/why for every automated and human action.
- R15 Detection-content library: 40+ techniques, 8+ tactics, **each with a measured
  precision on labelled data.** This is the number that replaces "no hallucinated IDs."
- R16 CERT-In 6-hour report drafter.
- R17 Real action connectors behind one interface: EDR isolate, IAM disable, firewall block,
  ticket create. Dry-run mode default. Rollback recorded for every action.
- R18 Policy engine: blast-radius thresholds, criticality gates, change-freeze windows,
  OT-no-auto-action default.

**P2 -- scale & differentiation**
- R19 Agent layer (Investigator / Attributor / Critic / Planner) with structured output,
  evidence IDs, and a deterministic fallback path.
- R20 Attribution that emits a calibrated distribution and **refuses to name an actor at low
  margin.**
- R21 Continuous ingest: syslog, S3, Elastic, Splunk pull.
- R22 Vulnerability prioritisation as a graph query: KEV/NVD × asset inventory × path-to-crown-jewel.
- R23 Graph features into detection (before any GNN).
- R24 MSSP multi-tenant console.

**P3 -- platform**
- R25 Digital twin / attack simulation on the graph (PS7 bullet 5; BAS market is $1.29B in
  2026 growing 22.9% CAGR -- a real adjacent line).
- R26 OT/ICS telemetry: Modbus, DNP3, PROFINET; IT↔OT correlation across the graph.
- R27 Graph learning (GNN / graph foundation model) once labelled graph data exists.
- R28 Streaming architecture, horizontal workers.

## D4. Non-goals (explicit)

Not a SIEM -- sit beside one. Not an EDR -- consume its telemetry. No log-volume pricing --
that is the incumbents' weakness, don't copy it. No social-media/OSINT person-tracking (the
existing `prd.md:59` rejection is correct and well-argued -- keep it). No autonomous action
outside a pre-approved envelope, ever. No claimed metric without a regenerable report.

## D5. Metrics that matter

**Product:** TPR@fixed-FPR on realistic prevalence · **alerts per analyst per day** ·
precision at the shipped operating point · ATT&CK mapping precision per technique ·
incidents-per-real-attack (correlation quality) · MTTD measured against a real baseline, not
a citation · % of playbook steps auto-executed · rollback rate.

**Business:** paid assessments closed · assessment → subscription conversion · net revenue
retention · time-to-first-value (target: < 1 day) · graph coverage per customer (the moat
metric).

**Two metrics to stop quoting immediately:** ROC-AUC as a headline (PR-AUC 0.0082 is the
honest descriptor) and "weeks → minutes" (a citation minus a measured zero).

---

# PART E -- ROADMAP (2-4 people, unfunded)

## Phase 0 -- Credibility hardening · ~1 week · do this first regardless of everything else

Purpose: make the *existing* demo unbreakable and unimpeachable. Highest return per hour in
the entire plan.

1. `Dockerfile:21` + `ae_lanl.npz` + a `/health` that verifies the loaded detector. *(minutes)*
2. Delete the fake-score fallbacks (`api.js:91-118`); visible degraded state instead.
3. Delete `views.py:35-40`, `:319`; read `metrics.json`; extend `audit_stale.py` to catch
   0.988/0.386.
4. Fix the frontend fabrications (R8). Label AIIMS/CBSE as synthetic.
5. Fix upload size-before-parse, event-loop block, CORS, error boundary.
6. Regenerate `reports/spine_incident.md` so every headline operational number
   (2,732/1,243/473/463/469/670) traces to a regenerable report, per your own `rules.md:27`.
7. **Rewrite the honesty slide as a strength.** Lead with PR-AUC 0.0082, the 112,212 FPs, the
   NTLM 87.7%→22.8% collapse, and the per-upload-baseline flaw -- *then* state exactly how the
   architecture fixes each. A team that finds its own worst numbers before the judges do wins
   the technical room. Hiding them and getting caught loses it outright.
8. Reconcile `PITCH_DECK.md`, `prd.md`, `rules.md`, `phases.md` (all stale end to end;
   `PPT_CHANGES.md` fixed the slides and left the source docs).

## Phase 1 -- Make the core real · 6-8 weeks

Persistent store (Postgres) · entity baselines + cold start (R4) · entity risk aggregation
(R6) · real correlation (R5) · graph as system of record · detection content to 20+ techniques
using the **already-downloaded** LANL dns/flows/proc streams · graph features into detection ·
multi-signal ablation gate (R7).

**Exit criterion: 30 identical benign events → 0 alerts, and a defensible alerts-per-day
number at the shipped operating point.** Until that holds, nothing else matters.

## Phase 2 -- Make it sellable · 6-8 weeks

Auth + RBAC + tenancy + audit log (R11-R14) · CERT-In 6-hour drafter (R16) · Assessment
report generator (productise the existing printable report) · dry-run action connectors
(R17) · policy engine (R18) · air-gap offline bundle.

**Exit: first paid assessment delivered.**

## Phase 3 -- Differentiate · 8-10 weeks

Agent layer with Critic (R19) · calibrated attribution that refuses low-margin calls (R20) ·
continuous ingest (R21) · vulnerability prioritisation as a graph query (R22) · MSSP tenancy
(R24).

**Exit: first monitoring subscription; first MSSP conversation.**

## Phase 4 -- Platform · ongoing

Digital twin (R25) · OT/ICS (R26) · graph learning (R27) · streaming (R28) · CERT-In
empanelment · ISO 27001 / SOC 2.

## Hackathon-specific note

If a finale is still ahead: **Phase 0 + the architecture story from Part B/C is the entry.**
Do not attempt Phase 1 for a demo. The winning move against a field of GPT-wrapper projects
is not more features -- it is (a) a working system with honestly stated limits, (b) an
articulated reason your LLM is *forbidden* from touching 99.99% of the pipeline, and (c) a
business model with a statutory hook (CERT-In 6-hour) rather than a market-size slide. That
is Innovation + Business Impact + Technical Excellence in one narrative, and it is
substantially cheaper than building anything new.

---

# PART F -- BUSINESS MODEL & GTM

**Pricing.** Avoid per-GB -- it is the incumbents' structural weakness (Splunk ~$1,000/GB/day/yr
at 50 GB/day; Sentinel ~$4.30/GB; Splunk ES adds $20-40/GB/day on top). Per-endpoint is now
the dominant AI-SOC model at **$8-25/endpoint/month** ($25-45 platform-tied), with mid-market
flat retainers at **$5k-25k/month**. India will not bear US pricing.

Three lines:
1. **Attack-Path Assessment** -- fixed fee per engagement. Cash now, no integration, builds
   the graph, generates the case study. This is your entry product.
2. **Continuous monitoring** -- per-identity or per-asset tiers, India-adjusted. Land on the
   assessment's graph.
3. **MSSP/OEM wholesale** -- per-tenant licence.

**Market context (for the deck, cited not asserted).** India cybersecurity market ~$6.6-11.9B
in 2026 → ~$22.9B by 2033 (~9.8% CAGR). 231 CERT-In-empanelled organisations gate government
procurement. Over 70% of Indian government entities on end-of-life IT. CERT-In handled 1.59M
incidents in 2023. BAS/digital-twin adjacency $1.29B → $3.61B by 2031. Global AI-native
security took $4.1B in Q1 2026 (+47% YoY).

**Competitive honesty.** You lose on integration breadth (Dropzone: 85+ integrations) and on
distribution (CrowdStrike, Microsoft, Google, SentinelOne all ship agentic SOC natively). You
win on: zero-integration time-to-value, air-gap capability, India regulatory fit, graph-native
exposure analysis, and auditability. **Never compete on "our AI triages alerts."** That is
already commoditised by the platform vendors and is being given away for free inside Falcon
and Defender.

---

# PART G -- RISKS

| Risk | Severity | Mitigation |
|---|---|---|
| **Base-rate collapse** -- 0.5% precision on realistic prevalence | Existential | R4/R6/R7. Entity-level risk, not event alerts. Nothing else matters until this is fixed. |
| **Incumbent bundling** -- agentic SOC free inside Falcon/Defender | High | Don't compete on triage. Compete on graph + air-gap + India compliance. |
| **No real telemetry** | High | Assessments *are* the telemetry acquisition strategy. |
| **Air-gap kills the flywheel** | Medium | Learn from graph *structure*, not raw telemetry. Federated detection content, signed bundles. |
| **2-4 unfunded people vs $57M competitors** | High | Never fight on integration surface. One wedge, one segment, revenue from week 6. |
| **Agentic reliability** | Medium | Critic agent, structured output, evidence IDs, deterministic policy engine, deterministic fallback. |
| **Honesty debt discovered publicly** | High *(and immediate)* | Phase 0.7 -- publish your own worst numbers first. This converts the largest liability into the strongest credibility asset. |

---

## Verification

Phase 0 (each independently checkable):
1. `docker build` then `curl /api/health` → response names the loaded detector and confirms
   the calibration basis matches it.
2. Kill the backend, use the live score widget → visible error, **no number rendered**.
3. `grep -rn "0.988\|0.386" src/ frontend/` → no hits outside a report.
4. Upload the bank CSV, click "Stream live" → streams *that* file, not `lanl_redteam_u66`.
5. `python scripts/audit_stale.py` → clean.
6. Every operational number in `PITCH_DECK.md` greps to a `reports/*.md` file.

Phase 1 (the ones that decide whether this is a product):
7. `POST /api/analyze` with 30 identical benign auth events → **0 alerts** (today: 30).
8. Two unrelated attack campaigns a month apart in one file → **2 incidents** (today: 1).
9. Realistic-prevalence log → **alert rate < 1%** and a stated alerts-per-day figure.
10. Ablate each feature individually → **no single ablation costs > 20% relative TPR@1%FPR**
    (today NTLM costs 74%).
11. `pytest` green, with new tests locking each of 7-10.

Full-stack: `docker compose up`, ingest a 90-day log export, confirm baselines persist across
restart, confirm the graph grows across ingests, confirm every action lands in the audit log
with a rollback record.
