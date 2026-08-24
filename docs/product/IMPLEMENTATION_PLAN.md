> **Status: written 2026-08-23. Phases 1 and 2 are largely DONE** on
> `harden/phase-1-integrity`; see that branch's log rather than this file for what
> actually shipped. Phase 3 onward (persistent entity baselines, ingest, the
> agent layer) is still the plan of record. Retained for the sequencing and the
> open-source adopt/avoid analysis.

# Implementation Plan -- Graph-Native Cyber Resilience Platform

> Companion to [PRODUCT_PRD.md](PRODUCT_PRD.md). The PRD says *what* and *why*; this says
> *how*, *in what order*, and *how you know it worked*. Written 2026-08-14.
>
> Constraints this plan is built against: **2-4 people, unfunded**, one codebase that must
> ship SaaS and air-gapped, hackathon credibility preserved throughout.

---

## 0. What the research changed

Six findings moved a decision. These are corrections to the PRD, not restatements of it.

| Finding | Impact on the plan |
|---|---|
| **Kùzu was archived in October 2025.** Community forks exist (one adds concurrent writes for multi-agent use), but the upstream project is dead. | **Recommendation withdrawn.** Do not bet an air-gapped product on an archived DB. Use **Postgres for everything** -- edge tables + recursive CTEs now, Apache AGE later if Cypher earns its keep. One dependency, identical in SaaS and on-prem. |
| **CORTEX (multi-agent alert triage) published hard numbers:** false-positive rate on non-actionable predictions fell **24.9% → 14.2%** vs a single-agent tool-using baseline -- at **23,600 tokens vs 4,152** (5.7×) and 3.1 vs 1.3 tool calls. | The multi-agent case is now empirical, not aspirational -- *and so is its cost*. Sets the target: **match the FP improvement at under 3× tokens** by keeping deterministic work deterministic. Also sets the honest caveat: latency comes from deliberation, not just API calls. |
| **Agent evaluation benchmarks now exist:** ExCyTIn-Bench (investigation-graph questions), **SIR-Bench** (794 cases; triage accuracy + novel-finding discovery + tool-usage appropriateness via adversarial LLM-judge; reference agent hits 97.1% TP detection, 73.4% FP rejection, 5.67 novel findings/case), SIABench, SecRespond. | The agent layer gets **measured, not demoed**. Phase 3 has real numbers to hit instead of vibes. This is also the single most defensible slide you can build. |
| **Sigma ecosystem is mature:** SigmaHQ has 3,000+ ATT&CK-mapped community rules; pySigma compiles to any backend; `rsigma` ships a parser, linter, correlation engine **and exports an ATT&CK Navigator coverage layer with gap reports** against Atomic Red Team and the SigmaHQ baseline. | **Do not hand-write a technique mapper.** P0-4 is solved by adopting Sigma and writing one backend (Sigma → SQL over your events table). Coverage becomes a *measured number with a gap report* instead of "no hallucinated IDs." |
| **ClickHouse is 3-5× smaller on disk and 10-100× faster on GROUP BY than Elasticsearch** for log workloads; security data lakes standardise on S3 + Parquet + partition-by-source-and-date. | Confirms the eventual event store -- but **not in Phase 1**. Postgres carries you to the first paying customers. Add ClickHouse when a measured query forces it, not before. |
| **Trident (YC) is doing agentic attack-path chaining** across AWS/Azure/GCP/K8s with exploit replay. Fabraix does AI red-teaming; BeeSafe does social-engineering defence. | A real YC competitor exists in attack paths -- **cloud-native and offensive**. Your differentiation sharpens to: **on-prem identity and authentication telemetry, defensive detection, air-gap capable, India regulatory fit.** Do not pitch "cloud attack paths"; that race is taken. |

Two things the research confirmed rather than changed: exact betweenness centrality is
intractable at scale and sampling-based approximation (Brandes-Pich pivots, ABRA with
Rademacher averages, progressive centroid updates for dynamic graphs) is the standard answer --
so **scope the subgraph and sample the pivots**. And temporal knowledge-graph systems
(Graphiti/Zep, MAGMA's layered graph memory) converge on **bi-temporal edges** -- validity
interval plus observation time -- which is exactly the edge model below.

---

## 1. Architecture decisions

Recorded ADR-style so the rejected option is visible. Every one is reversible except D2.

| # | Decision | Chosen | Rejected, and why |
|---|---|---|---|
| D1 | Event store | **Postgres, partitioned by time** | ClickHouse (right eventually, premature now -- one more thing to operate on-prem). Elasticsearch (cost, and you don't need full-text). Files (no concurrent write, no tenancy). |
| D2 | Graph store | **Postgres edge table, cumulative upsert** | Kùzu (archived). Neo4j (licence, ops weight, second system on-prem). Apache AGE (fine later; recursive CTEs cover Phase 1-2 and add zero deps). **This is the one hard-to-reverse call** -- the edge table shape must be right on day one. |
| D3 | Detection content | **Sigma + pySigma, one SQL backend** | Hand-written rule dicts (that is P0-4). A trained classifier (no labelled data). An LLM per event (see the token table in the PRD). |
| D4 | Anomaly model | **Keep the existing autoencoder**, add graph features | Rewrite (it works and the NumPy export is genuinely good). GNN (Phase 4 -- needs labelled graph data you don't have). |
| D5 | Alerting unit | **Entity-day risk score** | Per-event alerts (45% alert rate -- the thing that makes it unusable). |
| D6 | Agent orchestration | **Plain Python + pydantic-validated structured output** | LangGraph / CrewAI (a dependency and an abstraction for four agents; also harder to air-gap and to audit). |
| D7 | LLM boundary | **Config flag: `frontier \| self-hosted \| none`**, every agentic feature has a deterministic fallback | LLM-required paths (disqualifies air-gapped buyers, i.e. your lighthouse segment). |
| D8 | Action execution | **One `Action` interface, dry-run default, hash-chained audit log** | Direct API calls from the planner (unauditable, unreversible). |
| D9 | Deployment | **Single compose: app + Postgres.** Same image on-prem and SaaS | Kubernetes (nothing needs it yet). Serverless (stateful graph). |
| D10 | Frontend | **Keep React, add TanStack Query + one error boundary** | Rewrite (3,185 lines, the theming is genuinely good). Keep hand-rolled `useFetch` (no cache, no dedupe, no retry -- it is why three screens refetch a 350 KB payload). |

---

## 2. Data contracts

Everything downstream depends on these being right. Get them reviewed before writing code.

### 2.1 Events -- OCSF-aligned subset

Ingest targets the **actual Windows telemetry a customer can export**, which is the concrete
replacement for "a CSV of unknown shape":

| Event ID | Meaning | Why it matters |
|---|---|---|
| **4624** + `logon_type` | Successful logon | The core signal. Type **3** (network) and **10** (RDP) workstation→workstation is the lateral-movement primitive; type **9** (NewCredentials) is runas/overpass-the-hash. |
| 4625 | Failed logon | Brute force, password spray, credential validation. |
| 4648 | Explicit-credential logon | Runas, pass-the-hash precursor. |
| 4672 | Special privileges assigned | Admin logon -- pairs with 4624 to find admin-to-workstation. |
| 4768 / 4769 | Kerberos TGT / service ticket | Kerberoasting, golden/silver ticket, and the **Kerberos path an attacker uses to evade an NTLM-only detector** (directly fixes P0-7). |
| 4688 + 4104 | Process creation w/ cmdline, PowerShell script block | Execution techniques -- the events that break the 3-technique ceiling. |
| 4662 | Directory-service access | DCSync (with replication GUIDs). |
| 4728 / 4732 / 4756 | Group membership change | Privilege escalation, persistence. |

```sql
CREATE TABLE events (
  id            bigserial,
  tenant_id     uuid        NOT NULL,
  ts            timestamptz NOT NULL,
  class         text        NOT NULL,   -- authentication|process|network|directory|file
  actor_user    text,                   -- normalised user@domain
  src_host      text,
  dst_host      text,
  auth_type     text,                   -- Kerberos|NTLM|Negotiate|...
  logon_type    smallint,
  status        text,                   -- success|failure
  target_service text,
  process_name  text,
  cmdline       text,
  dst_ip        inet,
  bytes_out     bigint,
  source        text        NOT NULL,   -- windows_security|vpn|firewall|okta|...
  ingest_batch  uuid        NOT NULL,
  raw           jsonb,
  PRIMARY KEY (tenant_id, id)
) PARTITION BY RANGE (ts);

CREATE INDEX ON events (tenant_id, actor_user, ts DESC);
CREATE INDEX ON events (tenant_id, dst_host, ts DESC);
CREATE INDEX ON events (tenant_id, class, ts DESC);
```

Reuse [src/schema.py](src/schema.py) -- the alias coercion layer (`user`/`username`/`account`/
`principal`/`src_user`, `src`/`dst`/`source`/`destination`) is already good and is why uploads
survive real-world column names. Extend it; do not replace it.

### 2.2 Entity profiles -- the fix for P0-5

The whole defect is that features are computed from the uploaded file. This table is the
antidote: features are computed against **org history**, not against the slice you are looking at.

```sql
CREATE TABLE entity_profiles (
  tenant_id     uuid NOT NULL,
  kind          text NOT NULL,          -- user|host|service
  key           text NOT NULL,
  window_days   smallint NOT NULL,      -- 30
  n_events      bigint  NOT NULL,
  distinct_dst  int     NOT NULL,
  distinct_src  int     NOT NULL,
  fail_rate     real    NOT NULL,
  hour_hist     int[24] NOT NULL,
  auth_counts   jsonb   NOT NULL,       -- {"Kerberos": n, "NTLM": n}
  dst_topk      jsonb   NOT NULL,       -- {"HOST": count} top 200
  dst_sketch    bytea,                  -- count-min for the long tail
  maturity_days smallint NOT NULL,      -- days of history behind this profile
  updated_at    timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, kind, key, window_days)
);

-- org-wide host popularity: rarity must be global, never per-upload
CREATE TABLE host_stats (
  tenant_id uuid, host text, n_auths bigint, n_distinct_users int,
  updated_at timestamptz, PRIMARY KEY (tenant_id, host)
);
```

**Cold-start policy -- write this down and enforce it in code.** When
`maturity_days < 7`, the tenant is in **learning mode**: novelty features are suppressed,
detections still run, but **no risk alerts are emitted** and the UI says so explicitly. This is
what makes "30 identical benign events → 0 alerts" true rather than aspirational, and it is
honest with the customer about why week one is quiet.

### 2.3 Graph -- bi-temporal, cumulative, append-only

```sql
CREATE TABLE graph_edges (
  id           bigserial,
  tenant_id    uuid NOT NULL,
  src_kind     text NOT NULL, src_key text NOT NULL,
  dst_kind     text NOT NULL, dst_key text NOT NULL,
  rel          text NOT NULL,       -- authenticated_to|ran_on|member_of|has_cve|hosts_service
  first_seen   timestamptz NOT NULL,
  last_seen    timestamptz NOT NULL,
  obs_count    bigint NOT NULL DEFAULT 1,
  attrs        jsonb,               -- {auth_type, logon_type, techniques[]}
  UNIQUE (tenant_id, src_kind, src_key, dst_kind, dst_key, rel)
);
CREATE INDEX ON graph_edges (tenant_id, src_kind, src_key);
CREATE INDEX ON graph_edges (tenant_id, dst_kind, dst_key);

CREATE TABLE entities (
  tenant_id uuid, kind text, key text,
  first_seen timestamptz, last_seen timestamptz,
  criticality smallint DEFAULT 0,     -- 0 unknown, 1-5 declared
  tags text[],                        -- 'ot','medical','prod-db','crown-jewel'
  attrs jsonb,
  PRIMARY KEY (tenant_id, kind, key)
);
```

Ingest **upserts**: `obs_count = obs_count + 1`, `last_seen = greatest(...)`. That single choice
is what turns the graph from a per-request derivative into the system of record.

`criticality` is **declared by the customer**, never guessed. The current
"hosts the most accounts depend on" heuristic stays available as a *suggestion* the customer
confirms -- the explainer already admits a past crown jewel "was literally the middle element of
a list, presented as a finding," and this is the structural fix for that class of error.

### 2.4 Risk, incidents, actions, audit

```sql
CREATE TABLE entity_risk (            -- the fix for P0-6
  tenant_id uuid, kind text, key text, day date,
  score real NOT NULL,
  contributions jsonb NOT NULL,       -- [{signal, weight, evidence_ids[]}]
  PRIMARY KEY (tenant_id, kind, key, day)
);

CREATE TABLE incidents (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL,
  opened_at timestamptz, closed_at timestamptz,
  status text,                        -- open|triaged|contained|closed|false_positive
  severity text, score real,
  entity_keys jsonb, technique_ids text[],
  summary text, assigned_to text
);
CREATE TABLE incident_evidence (
  incident_id uuid, event_id bigint, edge_id bigint, note text
);

CREATE TABLE actions (
  id uuid PRIMARY KEY, tenant_id uuid, incident_id uuid,
  kind text,                          -- isolate_host|disable_account|block_ip|create_ticket
  target text, params jsonb,
  mode text,                          -- dry_run|auto|awaiting_approval|executed|denied
  proposed_by text, approved_by text,
  executed_at timestamptz, result jsonb,
  rollback jsonb NOT NULL,            -- how to undo. NOT NULL is deliberate.
  signature text
);

CREATE TABLE audit_log (              -- hash-chained: tamper-evident
  id bigserial PRIMARY KEY, tenant_id uuid, ts timestamptz,
  actor text, action text, subject text,
  before jsonb, after jsonb,
  prev_hash text, hash text
);
```

`rollback jsonb NOT NULL` means an action that cannot be described as reversible cannot be
inserted. `audit_log.prev_hash` makes the log tamper-evident, which is how you *earn* the
sentence "full auditability of every automated action" rather than asserting it.

---

## 3. Phase 0 -- Credibility hardening

**1 week · 1 person · do this before anything else, including any demo.**

Highest return per hour in the entire plan. Nothing here requires a design decision.

### 3.1 Stop shipping the wrong model

| # | Task | File | Detail |
|---|---|---|---|
| 0.1 | Ship the autoencoder | [Dockerfile:21](Dockerfile#L21) | Add `models/ae_lanl.npz` to the COPY line. Five KB, already tracked in git. |
| 0.2 | Health check that means something | [api/main.py:118](api/main.py#L118) | Return `{detector, calibration_basis, models_loaded, cache_built}`. **Refuse to start** if `score_ref.json.detector != loaded detector` -- that mismatch is what silently corrupted every severity number. |
| 0.3 | Startup self-check | new `api/startup.py` | Run `detector.demo()` and `predictor.demo()` at boot. Both already exist and assert. Fail loudly. |

### 3.2 Stop synthesising model output

| # | Task | File |
|---|---|---|
| 0.4 | Delete the fake scorer | [frontend/src/api.js:91-107](frontend/src/api.js#L91) -- replace with a thrown error surfaced as a visible degraded state. |
| 0.5 | Delete `FALLBACK_NEXT` | [frontend/src/api.js:112-118](frontend/src/api.js#L112) |
| 0.6 | Relabel the reasoning panel | [LiveScoreWidget.jsx:34-55](frontend/src/components/LiveScoreWidget.jsx#L34) -- header becomes "Rule-based reasoning (not model attribution)". |
| 0.7 | Fix the detector label | [LiveScoreWidget.jsx:157](frontend/src/components/LiveScoreWidget.jsx#L157) -- read it from `/api/health`, don't hardcode it. |

### 3.3 Stop displaying numbers with no source

| # | Task | File |
|---|---|---|
| 0.8 | Delete `SCORECARD` | [src/shared/views.py:35-40](src/shared/views.py#L35) -- read `reports/metrics.json` the way [scripts/build_cache.py:50](scripts/build_cache.py#L50) already does. |
| 0.9 | Delete the duplicate | [src/shared/views.py:319](src/shared/views.py#L319) `evidence` block -- same source. |
| 0.10 | Extend the stale-number audit | [scripts/audit_stale.py](scripts/audit_stale.py) -- add `0.988` (retired IF ROC) and `0.386` (orphan, reproduces from nothing). Wire it into CI so it can never drift again. |

### 3.4 Stop asserting things the data doesn't say

| # | Task | File |
|---|---|---|
| 0.11 | Un-hardwire the stream | [Incident.jsx:53](frontend/src/screens/Incident.jsx#L53) -- stream the scenario actually loaded. |
| 0.12 | Derive the narrative | [Incident.jsx:127-133](frontend/src/screens/Incident.jsx#L127) -- generate from the incident's techniques, or delete the card. |
| 0.13 | Remove the invented persona | [Layout.jsx:7,9](frontend/src/components/Layout.jsx#L7) -- read tenant and incident ID from the payload. |
| 0.14 | Honest MTTD chart | [MttdPanel.jsx:32](frontend/src/components/MttdPanel.jsx#L32) -- use a log scale, and label the 10-day figure a Mandiant **citation** at the same visual weight as the measurement. |
| 0.15 | Label the synthetic scenarios | [Analyze.jsx:70](frontend/src/screens/Analyze.jsx#L70) -- AIIMS and CBSE are fabricated; they currently sit unlabelled under "real data". |

### 3.5 Robustness

| # | Task | File |
|---|---|---|
| 0.16 | Size limit before parse | [api/main.py:349](api/main.py#L349) -- stream to a temp file with a byte cap; reject at the cap, not after pandas has the whole thing in memory. |
| 0.17 | Unblock the event loop | [api/main.py:358](api/main.py#L358) -- `run_in_threadpool(analyze_events, ...)`. |
| 0.18 | CORS allowlist | [api/main.py:80](api/main.py#L80) -- env-driven origins. |
| 0.19 | One error boundary | `frontend/src/components/ErrorBoundary.jsx`, wrap the router. |
| 0.20 | Guard the crash paths | `Graph.jsx:102` (`Math.min(...[])` → Infinity), `Metrics.jsx:42`, `IncidentReport.jsx:10`. |
| 0.21 | Clone-to-run | `scripts/bootstrap.py` -- fetch or rebuild artifacts; make [views.py:18](src/shared/views.py#L18) lazy so the API doesn't 500 on import without models. |

### 3.6 Delete (2,700+ lines and 4.3 MB of dead weight)

Every line deleted is a line that cannot drift, break, or embarrass you in a code review.

| Target | Size | Why |
|---|---|---|
| `src/demo_ps7_pipeline.py` | 286 lines | An older, independent rule engine with its own duplicate `MITRE_RULES` table. Nothing imports it. |
| `testsprite_tests/` | ~1,800 lines | Generated HTTP smoke tests, **zero result artifacts**, and at least one encodes a wrong expectation. It is the sole basis for the unverifiable "14/15" claim. |
| `data/demo/red_team_scenario.csv`, `spine_incident.json`, `spine_incident_full.json` | ~195 KB | Referenced by nothing. |
| Duplicate chart/architecture renders in `reports/` | ~4.3 MB of 6 MB | Four renders of one scaling chart, three of one architecture diagram. |
| `scripts/make_submission_doc.py` | 1,413 lines | More code than any engine, for a Word doc. Move out of the product repo. |

### 3.7 Rewrite the honesty slide as the strongest slide

This is the highest-leverage non-code task in Phase 0.

Lead with your own worst numbers, then the fix. Judges cannot be surprised by what you told
them first, and a field of wrapper projects cannot produce a single honest failure number.

| State plainly | Then state |
|---|---|
| PR-AUC **0.0082**; at the shipped operating point, **616 true positives against 112,212 false positives** | Entity-day risk aggregation replaces per-event alerting -- Phase 1, with an acceptance test |
| Remove one evadable protocol flag and TPR falls **87.7% → 22.8%** | Multi-signal detection with a CI ablation gate: no single feature may cost >20% relative |
| Our own AIIMS and CBSE demos flag **100% of events**, precision 0.28 | The baseline is computed per-upload; persistent profiles plus a 7-day learning mode fix it |
| Live ATT&CK vocabulary is **3 techniques** | Sigma adoption -- 3,000+ ATT&CK-mapped rules, with a published Navigator coverage layer and gap report |
| "1,243 alerts → 1 incident" is definitional -- `correlate()` returns one incident for any input | Real temporal + connectivity clustering, with a two-unrelated-campaigns test |
| MTTD "immediate" means the log starts at the pivot; "weeks→minutes" is a Mandiant citation minus a measured zero | Measured against a stated baseline, or not claimed |

**Exit gate -- all of these, verifiable in one sitting:**
`/api/health` names the loaded detector and its calibration basis · backend down ⇒ no number
appears anywhere · `grep -rn "0\.988\|0\.386" src/ frontend/` returns nothing outside a report ·
uploading a CSV and clicking "Stream live" streams *that* CSV · `audit_stale.py` clean in CI ·
every operational number in the deck greps to a `reports/*.md` file.

---

## 4. Phase 1 -- Make the core real

**8-10 weeks · 2 people.** This is the phase that decides whether a product exists. Nothing
here is customer-visible polish; all of it is the difference between a demo and a system.

### W1 · Persistence and tenancy foundation *(1.5 weeks)*

- `docker-compose.yml`: app + Postgres 16. Same file on-prem and in cloud.
- Alembic migrations for every table in §2. Migrations, not `create_all` -- you will be
  upgrading customer installs you cannot SSH into.
- `src/store/` -- repository modules: `events.py`, `entities.py`, `graph.py`, `profiles.py`,
  `risk.py`, `incidents.py`, `actions.py`, `audit.py`. Plain SQL via psycopg, no ORM for the
  hot paths.
- `tenant_id` threaded from request to query. **A test that fails if any query omits it** --
  cross-tenant leakage is the one bug that ends a security company.
- Hash-chained `audit.append()` with a chain-verification function.

### W2 · Ingest pipeline *(1.5 weeks)*

- `src/ingest/` -- `windows_security.py` (the event IDs in §2.1), `csv_generic.py` (keep the
  existing alias coercion), `syslog.py` stub.
- Idempotent batch ingest keyed on `ingest_batch` + content hash. Re-ingesting the same export
  must not double the graph.
- Backfill mode: ingest 90 days of history, then compute profiles. This is the assessment
  workflow, so it is a first-class path, not a script.
- **Golden-file tests** per source: raw event in, normalised row out, byte-exact.

### W3 · Entity profiles and the baseline *(2 weeks -- the most important two weeks in the plan)*

- `src/baseline/profile.py` -- incremental profile update on ingest. Top-k exact + count-min
  sketch for the long tail, so memory is bounded regardless of estate size.
- `src/baseline/features.py` -- the current 7 features, **recomputed against `entity_profiles`
  and `host_stats` instead of the input frame.** Add: hour-of-day novelty, auth-type novelty,
  privileged-logon-to-workstation, Kerberos service-ticket fan-out.
- Cold-start gate per §2.2. `maturity_days < 7` ⇒ learning mode, no alerts, UI says so.
- Recalibrate the autoencoder against baseline-derived features and store the anchors **in the
  database per tenant**, not in a committed JSON file.

> **Acceptance (blocking):** 30 identical routine auths from a user with 30 days of history →
> **0 alerts**. Today: 30. This single test is the gate for the whole phase.

### W4 · Graph as system of record *(1.5 weeks)*

- `src/graph/build.py` -- upsert edges on ingest, never rebuild.
- `src/graph/query.py` -- recursive-CTE implementations of: `neighbors(entity, hops)`,
  `paths_to_critical(entity, max_hops)`, `blast_radius(entity)`, `reachable_from(entity, since)`.
- `src/graph/analytics.py` -- **scoped** algorithms:
  - Scope rule: never run centrality on more than 5,000 nodes. Scope to the blast radius of
    confirmed pivots, or the critical-adjacent subgraph.
  - Choke points: **sampled betweenness** with `k = ceil(sqrt(n))` pivots (Brandes-Pich), not
    exact. Report the sample size in the output so the number is honest.
  - Cache results per `(tenant, subgraph_hash)`; invalidate on edge insert into that scope.
- Keep [src/shared/attack_graph.py](src/shared/attack_graph.py) as the in-memory analytics
  kernel -- the multi-pivot fix in it is correct and hard-won. Feed it scoped subgraphs.

### W5 · Detection content via Sigma *(2 weeks)*

- `src/detect/sigma_backend.py` -- a pySigma backend compiling Sigma → parameterised SQL over
  `events`. This is the single highest-leverage build in the plan: it buys 3,000+ ATT&CK-mapped
  rules.
- `detections/` -- curated rule set, versioned, reviewed in PRs. Start with the ~40 rules that
  map to the event IDs in §2.1: lateral movement, credential access, discovery, execution,
  privilege escalation, persistence, exfiltration.
- `scripts/coverage.py` -- emit an **ATT&CK Navigator layer plus a gap report**. Publish it.
  Organisations typically cover 20-40% of relevant techniques and 60%+ is considered strong --
  so a measured number is both credible and achievable.
- **Validation with Atomic Red Team:** run the atomic test for a technique, confirm the rule
  fires, record precision. That produces the per-technique precision number the PRD demands and
  the repo has never had.

### W6 · Entity risk aggregation *(1 week)*

- `src/risk/score.py`:
  ```
  entity_day_score = Σ_signals ( weight(signal) × severity(signal) × decay(age) )
                     capped per signal family, then squashed to 0-100
  ```
  Signals: Sigma rule hits (weighted by rule confidence), anomaly-score bands, graph signals
  (new path to a declared crown jewel, first-ever privileged logon, blast-radius growth).
- Contributions stored as `[{signal, weight, evidence_ids}]` -- **the risk score must be
  decomposable in the UI**, or analysts will not trust it and neither will an auditor.
- Threshold calibrated to a target **alerts per analyst per day** (start: 20), not to a score.

> **Acceptance (blocking):** on a realistic-prevalence log, alert rate **< 1% of events**, with
> a stated alerts-per-day figure at the shipped operating point.

### W7 · Real correlation *(1 week)*

- `src/correlate/cluster.py`, replacing [src/shared/correlate.py](src/shared/correlate.py):
  1. Take entity-days above the risk threshold.
  2. Union-find over `(entity, day)` nodes, joined when they share an event **or** are adjacent
     in the graph within `SESSION_GAP` (which finally gets used).
  3. Connected components under a temporal constraint = incidents.
  4. Merge incidents sharing > 50% of entities within 24 h.
- Incident severity from constituent risk, not `max()` of an anomaly score.

> **Acceptance (blocking):** two unrelated campaigns a month apart in one file → **2 incidents**.
> Today: 1, unconditionally.

### W8 · Ablation gate and the metrics story *(0.5 weeks)*

- `scripts/ablate.py` -- drop each feature, re-evaluate, fail CI if any single ablation costs
  more than **20% relative** TPR@1%FPR. This is the permanent fix for P0-7: the regression can
  never silently return.
- Re-run all evaluations against the new pipeline; regenerate `reports/`. Every number in the
  UI must trace to a regenerated report.

**Phase 1 exit gate:** the four blocking acceptance tests above, green in CI, plus baselines
that survive a container restart and a graph that demonstrably grows across two ingests of
different data.

---

## 5. Phase 2 -- Make it sellable

**8 weeks · 2-3 people.** Everything here exists to get a purchase order signed.

### Auth, tenancy, RBAC *(2 weeks)*
OIDC (customer IdP) plus local accounts for air-gapped installs. Roles: `analyst`, `lead`,
`admin`, `read_only`. API keys per integration, scoped and revocable. Route guards on the
frontend -- every path is currently deep-linkable with no session at all. Session and API-key
events into `audit_log`.

### CERT-In 6-hour report drafter *(1 week -- highest business return in the plan)*
`src/report/certin.py`. Populate the notification fields from the incident: time of detection,
affected systems, technique chain, evidence summary, containment actions taken, current status.
Deterministic template; the agent layer later drafts the narrative and a human always signs.
Track the 6-hour clock from detection in the UI. Mentioned **zero times** in the current repo,
and it is the difference between selling a nice-to-have and selling a statutory obligation.

### Assessment deliverable *(1.5 weeks)*
Productise [IncidentReport.jsx](frontend/src/components/IncidentReport.jsx) into the paid
artifact: executive summary, estate graph, ranked choke points with blast radius, path-to-crown-
jewel findings, ATT&CK coverage of the customer's own telemetry, prioritised remediation queue.
PDF + the live console. **This is what the beachhead customer actually buys**, so it gets design
attention, not a print stylesheet.

### Action framework *(2 weeks)*
```python
class Action(Protocol):
    kind: str
    def preview(self, ctx) -> ActionPreview      # what will change, blast radius
    def execute(self, ctx) -> ActionResult       # idempotent
    def rollback(self, result) -> ActionResult   # mandatory
```
Connectors: `ticket_create` (Jira/ServiceNow -- start here, zero blast radius),
`disable_account` (AD/Entra), `isolate_host` (CrowdStrike/Defender/SentinelOne),
`block_ip` (firewall). **Dry-run default, per-connector.** Every call recorded with its rollback.

### Policy engine *(1 week)*
```python
def evaluate(action, ctx) -> Literal["ALLOW","REQUIRE_APPROVAL","DENY"], reason
```
Deterministic inputs only: blast radius, entity criticality and tags, business hours, change
freeze, action kind, approval count. **Assets tagged `ot`, `medical` or `prod-db` are
`REQUIRE_APPROVAL` by default and cannot be configured to auto-execute** -- that default is a
selling point to exactly the buyers you want. Exhaustive unit tests; this code decides whether a
hospital ward loses a PC.

### Air-gap bundle *(0.5 weeks)*
`scripts/build_bundle.py` → signed tarball: ATT&CK snapshot, KEV/NVD snapshot, detection
content version, model weights, checksums. `POST /api/bundle/import` verifies the signature
before applying. The committed threat-radar snapshot already proves the pattern works.

**Phase 2 exit gate:** a first paid assessment delivered end to end -- customer log export in,
signed PDF and live console out, every action in the audit log, chain verified.

---

## 6. Phase 3 -- The agent layer

**10 weeks · 2-3 people.** This is the differentiation, and it is built last on purpose:
agents over a broken pipeline produce confident nonsense faster.

### 6.1 Tool surface -- fixed, ~8 tools, no free-form SQL

| Tool | Signature | Returns |
|---|---|---|
| `graph.neighbors` | `(entity, hops≤3, rel_filter, time_range)` | edges + `evidence_id` |
| `graph.paths_to_critical` | `(entity)` | paths + criticality + declared-by |
| `graph.blast_radius` | `(entity, since)` | node set + size + sample size if approximated |
| `events.query` | `(entity, time_range, class, limit≤500)` | rows + `evidence_id` |
| `baseline.profile` | `(entity)` | profile + `maturity_days` |
| `attack.lookup` | `(technique_id \| group)` | real ATT&CK data (corpus already parsed) |
| `intel.search` | `(technique \| cve \| actor)` | KEV/NVD/advisories |
| `incidents.similar` | `(incident_id)` | prior incidents + their resolutions |

Everything returns stable `evidence_id`s. **A claim without an evidence ID is rejected by the
schema, not by a reviewer.**

### 6.2 The four agents

| Agent | Output schema | Hard rule |
|---|---|---|
| **Investigator** | `Hypothesis{summary, timeline[], techniques[], confidence, evidence_ids[]}` | Every field traces to an evidence ID. Tool calls only. |
| **Attributor** | `Attribution{candidates[{actor, score, margin, evidence_ids[]}], abstained: bool, reason}` | **Must abstain when top-2 margin < 0.05.** Today five actors sit 0.001 apart and the report names one -- this rule makes that impossible. |
| **Critic** | `Verdict{refuted: bool, reasons[], missing_evidence[], alternative_hypothesis}` | Prompted to refute; **defaults to `refuted: true` under uncertainty.** Same tools as the Investigator. |
| **Planner** | `ActionPlan{actions[{kind, target, params, rationale, evidence_ids[]}]}` | Structured actions only. Output goes to the policy engine, never to a human as authority. |

Orchestration: plain Python. `Investigator → Critic → (loop ≤ 2 if refuted) → Attributor → Planner`.
Pydantic validation with retry on schema failure. **Deterministic fallback:** with
`llm_mode = none`, each agent has a template implementation -- investigation becomes the current
deterministic narrative, attribution becomes the existing retrieval ranking, planning becomes
the existing tactic→action mapping. That fallback is what keeps the air-gapped segment sellable.

### 6.3 Evaluation -- the slide nobody else will have

Run against published benchmarks plus a held-out set of your own labelled incidents:

| Benchmark | What it measures | Reference point |
|---|---|---|
| **SIR-Bench** (794 cases) | Triage accuracy, novel-finding discovery, tool-usage appropriateness, via adversarial LLM-judge | Reference agent: **97.1% TP detection, 73.4% FP rejection, 5.67 novel findings/case** |
| **ExCyTIn-Bench** | Investigation-graph question answering | -- |
| **CORTEX comparison** | Single-agent vs multi-agent FP rate and cost | Baseline **24.9% → 14.2% FP** at **4,152 → 23,600 tokens** (5.7×) |

**Your targets:** match or beat CORTEX's FP reduction at **under 3× tokens**, because Tiers 0-1
already did the work an LLM would otherwise pay for. Track and publish tokens per incident and
cost per incident -- cost is a first-class engineering concern in production agent systems, and
publishing it is credibility.

### 6.4 Also in Phase 3

**Continuous ingest** (2 weeks): syslog listener, S3/blob poller, Elastic and Splunk pull. Still
batch-oriented -- a scheduled 5-minute pull covers every buyer in the beachhead. Real streaming
is Phase 4.

**Vulnerability prioritisation as a graph query** (1.5 weeks): ingest KEV and NVD into
`entities(kind='cve')` and `graph_edges(rel='has_cve')`. Then
`SELECT cve WHERE EXISTS (path from affected_host to crown_jewel)` ranked by exploitability ×
path length × asset criticality. This closes PS7 bullet 4 and is a **query, not a subsystem** --
that is the graph decision paying for itself.

**MSSP tenancy** (1.5 weeks): tenant switcher, cross-tenant triage queue, per-tenant detection
overrides, aggregate reporting.

**Phase 3 exit gate:** published benchmark numbers, an abstaining attributor, a Critic that
measurably reduces false positives, and a deterministic fallback that passes the same
functional tests with `llm_mode = none`.

---

## 7. Phase 4 -- Platform

Ongoing, gated on revenue. Do not start any of it before Phase 3 ships.

- **Digital twin / attack simulation** on the graph -- PS7 bullet 5, and a real adjacent market
  (BAS is $1.29B in 2026 → $3.61B by 2031, 22.9% CAGR). Simulate "what if this host is
  compromised" and "what does this control actually buy." The graph makes this cheap.
- **OT/ICS**: Modbus, DNP3, PROFINET parsing; IT↔OT correlation across the graph. Purpose-built
  OT platforms beat SIEMs here because they understand the protocols natively -- so partner or
  ingest from Claroty/Nozomi/Dragos rather than reimplementing.
- **Graph learning**: a GNN or graph foundation model, once you have labelled graph data from
  assessments. Not before -- the current 7 flat features plus graph features get most of the lift.
- **ClickHouse migration** for the event store, when a measured query forces it.
- **Streaming**: Kafka/Redpanda and horizontal workers, when a customer's volume forces it.
- **Certification**: CERT-In empanelment, ISO 27001, SOC 2.

---

## 8. Team split

**Three people (recommended):**

| Role | Owns |
|---|---|
| **Platform** | Postgres, migrations, ingest, graph store and queries, tenancy, audit, deployment, air-gap bundle |
| **Detection & ML** | Baselines, features, Sigma backend and content, risk scoring, correlation, ablation gate, all evaluation, agent layer |
| **Product** | Console, assessment deliverable, CERT-In drafter, policy-engine UX, plus GTM: pilot conversations, pricing, security questionnaires |

**Two people:** Platform absorbs ingest and graph; Detection absorbs everything analytic;
frontend work is shared and the assessment PDF takes priority over console polish.

**Four people:** the fourth takes connectors and integrations -- the endless-surface work -- from
Phase 2 onward.

**Cadence:** weekly demo against an acceptance test, not against a screen. A phase does not
advance until its blocking tests are green in CI.

---

## 9. Risk register with kill criteria

Kill criteria matter more than mitigations -- they are what stops a small team sinking a year
into a dead branch.

| Risk | Mitigation | Kill criterion |
|---|---|---|
| **Entity risk aggregation doesn't fix the alert rate** | Tune weights and thresholds against a labelled corpus; target alerts-per-analyst, not a score | If alert rate stays above 5% of events after Phase 1 W6, **stop and reconsider the detection premise** before building anything on top |
| Postgres graph queries too slow | Scoped subgraphs, sampled centrality, aggressive caching | If a 3-hop blast-radius query exceeds 2 s at 100k edges, migrate to Apache AGE -- not Neo4j, not a fork of an archived DB |
| Sigma → SQL backend is harder than estimated | Start with a 40-rule subset; the pySigma backend surface is well documented | If the backend isn't compiling 40 rules in 3 weeks, hand-write those 40 as SQL and adopt Sigma later -- the rules matter, the compiler doesn't |
| No design partner | Assessments are cheap to deliver; offer the first free for a case study and a log export | If no signed assessment by end of Phase 2, **the beachhead is wrong** -- revisit segment before building Phase 3 |
| Agent layer doesn't beat deterministic | Benchmark before shipping; the fallback path is already required | If the Critic doesn't reduce FP by ≥5 points on your own labelled set, **ship deterministic only** and say so publicly. That is a stronger position than a worse agent |
| Air-gap kills the flywheel | Learn from graph structure and detection efficacy, not raw telemetry; federated content in signed bundles | -- |
| Cross-tenant data leak | `tenant_id` on every query with a test that fails on omission; namespace-per-tenant for regulated buyers | Any leak in testing halts feature work until the query layer is provably safe |
| Incumbent bundling | Compete on graph, air-gap and India compliance, never on alert triage | -- |

---

## 10. Verification -- end to end

### Continuous (CI, every commit)
`pytest` · `scripts/audit_stale.py` · `scripts/ablate.py` (fails if any single feature ablation
costs >20% relative TPR@1%FPR) · migrations apply forward and backward on a scratch DB ·
tenant-isolation test · `docker build` and health check.

### The five tests that define whether this worked

| # | Test | Today | Target |
|---|---|---|---|
| 1 | 30 identical benign auths from a mature-baseline user | **30 alerts** | **0 alerts** |
| 2 | Two unrelated campaigns one month apart, one file | **1 incident** | **2 incidents** |
| 3 | Alert rate on a realistic-prevalence log | ~45% | **< 1%**, with a stated alerts/day |
| 4 | Worst single-feature ablation, relative TPR@1%FPR cost | **74%** (NTLM) | **< 20%** |
| 5 | ATT&CK techniques reachable on live telemetry | **3** | **40+, each with measured precision** |

### Full-stack acceptance
`docker compose up` → ingest a 90-day Windows Security export → confirm learning mode for 7
days of history → confirm profiles survive a restart → ingest a second, different export →
confirm the graph **grew** rather than being rebuilt → trigger an incident → confirm the agent
layer cites evidence IDs → confirm the Attributor **abstains** at low margin → propose an action
against an `ot`-tagged asset → confirm the policy engine returns `REQUIRE_APPROVAL` → approve →
confirm execution, rollback record, and a verifiable audit-log hash chain → generate the CERT-In
6-hour draft → confirm every figure in it traces to an evidence ID.

### Air-gap acceptance
Same, with no outbound network: `llm_mode = none`, offline bundle sideloaded, signature verified,
and **every functional test above still passing**.

---

## 11. Timeline

| Phase | Duration | Cumulative | Milestone |
|---|---|---|---|
| **0** Credibility hardening | 1 week | wk 1 | Demo is unimpeachable. Nothing on screen lacks a source. |
| **1** Make the core real | 8-10 weeks | wk 11 | The five defining tests pass. A product exists. |
| **2** Make it sellable | 8 weeks | wk 19 | First paid assessment delivered. |
| **3** Agent layer | 10 weeks | wk 29 | Published benchmarks. First subscription. |
| **4** Platform | ongoing | -- | Twin, OT, graph learning, certification. |

**First revenue: ~week 19 (about 4.5 months). Differentiated product: ~week 29 (7 months).**

For 2-4 unfunded people that is aggressive but not fantasy, because Phase 1 rebuilds a core
that is only ~465 lines today, and Phase 2's flagship deliverable is a productised version of a
report that already exists.

**If a hackathon finale is still ahead: Phase 0 plus this document is the entry.** Do not start
Phase 1 for a demo. A working system with honestly stated limits, an articulated reason the LLM
is forbidden from 99.99% of the pipeline, and a statutory business hook beats more features --
and it is a week of work rather than a quarter.
