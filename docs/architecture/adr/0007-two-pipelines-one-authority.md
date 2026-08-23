# ADR 0007 — Two analysis lanes, one authority: the agent pipeline cross-checks

- **Status:** accepted
- **Date:** 2026-08-21

## Context

Merging `feature/10-agent-pipeline` left the repository with **two analyses of the
same event log**:

| | Workflow (`src/shared/workflow.py`) | Agent lane (`src/agents/`) |
|---|---|---|
| Shape | seven bounded nodes, one replan | ten agents over behavioural chunks |
| Severity from | peak calibrated anomaly score across correlated alerts | prioritiser risk band over ranked attack chains |
| Owns | claims, assessment, twin, vulnerabilities, RBAC, audit | chunking, per-chunk summaries, incident narrative |

On the AIIMS scenario they disagreed: `high` versus `medium`. Two pipelines
returning different verdicts on the same input is indefensible in a demo, because
"which one is right?" has no good answer, and the obvious fixes are both bad:

- **Delete one.** Throws away the agent lane's genuine contribution — behavioural
  chunking, per-window summaries and the narrative — none of which the workflow
  does.
- **Average them.** Invents a number neither analysis computed, which is exactly
  the "single blended score" ADR 0006 was written to stop.

## Decision

**The workflow is authoritative. The agent lane is a cross-check that becomes a
second independence group in the evidence-confidence model.**

`src/shared/crosscheck.py` compares the two and emits a verdict:

| Verdict | Condition | Corroboration |
|---|---|---|
| corroborates | identical severity, ≥1 shared technique | 0.45 |
| partially corroborates | adjacent severity or techniques only | 0.27 / 0.18 |
| contradicts | severity differs by ≥2 bands | **0.0** |
| inconclusive | no shared techniques | 0.0 |

That result becomes an `Evidence` item in the `agent-lane` independence group and
flows into `evidence_confidence`. On AIIMS it reads *partially corroborates* at
0.27, and evidence confidence moves 63.5 → 73.4.

This is what `claims.py` was built for. A disagreement between two differently
constructed analyses is not noise to be smoothed — it is precisely the signal the
noisy-OR model exists to carry.

## The honesty constraint that makes it work

**The two lanes are only partially independent.** They read the same log and share
`src.shared.attack_mapper`. They are a second *opinion*, not a second *sensor*,
and treating them as independent telemetry would be exactly the duplicate-evidence
inflation the research warns about.

So corroboration is capped at **0.45**, the cap is a named constant, the shared
components are listed in every result, and the UI states it. A degraded agent lane
halves its own contribution — a broken second opinion is worth less than a working
one.

## Consequences

- The agent lane is **visible**. Its endpoints existed but nothing in the SPA
  called them; the commit that added it claimed "UI integration" while changing
  only whitespace. `CrossCheck.jsx` now shows both lanes side by side with their
  severity bases, the shared and lane-only techniques, the verdict, and the
  narrative labelled non-authoritative.
- **A contradiction is a feature.** When the lanes disagree the UI says so and
  confidence drops, rather than one silently winning.
- The cross-check is **advisory and non-fatal**. A failure in the agent lane is
  caught, reported as `not available`, and the investigation completes unchanged —
  tested.
- Latency: the agent lane adds roughly 90 ms to an investigation. It can be
  disabled with `run_crosscheck=False`. **This figure is stale; see the
  2026-08-23 addendum for measured numbers.**
- The narrative is the agent lane's, and it is never authoritative regardless of
  whether a template or an LLM produced it.

## What would change our mind

- **Real independence.** If the agent lane consumed different telemetry —
  endpoint process data rather than the same authentication log — the cap should
  rise, because it would then genuinely be a second sensor.
- **Persistent disagreement on the hero scenario.** Adjacent severity is
  tolerable; if the two lanes routinely contradicted each other, that would mean
  one of them is wrong and the answer is to fix it, not to report the conflict.
- **The agent lane becoming the primary.** It would need to own claims,
  assessment, twin, RBAC and audit first. Today it owns none of them.

## Addendum, 2026-08-22: the rule fired, and the agent lane was the wrong one

On LANL the lanes came out two bands apart, `critical` against `medium`. By the
criterion above that is not a finding to display, so we went looking for the
fault. The agent lane had four, none of which the 353-test suite caught, because
every agent test fed the pipeline a hand-built stats dict rather than one the
chunker produced:

1. **Failures were never counted.** `chunker._compute_stats` tested
   `status == "failure"`; the canonical vocabulary from `src.shared.normalize` is
   `success` / `fail`. `failure_rate` was 0.0 for every chunk ever produced, in
   every scenario, since the lane was written. The T1110 brute-force rule was
   unreachable, and Detection scoring, Investigation triage and the Point-A
   summary text were all reading a constant.
2. **`protocol` was never aggregated**, so the `ntlm_lateral_movement` rule that
   already sat in `RULE_MAP` could never fire. On a dataset where 100% of
   red-team logins negotiate NTLM and the published ablation puts ROC at 0.992
   with the signal against 0.906 without it, the second lane was blind to the
   single strongest feature in the data.
3. **`prioritizer._actor_match` imported `load_attack` from
   `src.shared.parse_attack`**, which does not exist, inside a bare
   `except Exception: pass`. It returned 0.0 on every call, so `W_ACTOR`, 20% of
   the risk score, was dead weight and the bands were being applied to a score
   that could only ever reach 0.80.
4. **Chain `technique_ids` was not deduplicated.** U66's chain reported 49
   techniques that were 49 copies of one, so the predictor saw a chain of length
   one and the UI printed the same ID 49 times in a table cell.

Fixed at source. The lane now maps 269 of 287 flagged LANL chunks against 60,
finds three distinct techniques against one, and calls the campaign `high`
against the workflow's `critical` — adjacent, which is what this ADR says to
publish. `tests/test_agent_lane_signals.py` locks all four; each test fails
against the previous code.

Two honest consequences:

- **Severities moved up across the board**, because `W_ACTOR` is contributing
  for the first time. AIIMS went from agreeing at `high` to the agent lane
  reading `critical` against the workflow's `high`. Nothing was re-tuned to make
  the numbers agree; the thresholds are the ones the design always specified,
  now finally applied to the score the design intended.
- **Actor match is a weak feature and is now labelled as one.** 525 of 794
  ATT&CK techniques have at least one documented group, and the term fires on 34
  of 39 LANL chains, so it mostly shifts the distribution rather than separating
  it. The prioritiser now says so in its own notes, and `matched_actors` lists
  the groups so a reader can see that "APT28 uses pass-the-hash" is not an
  attribution of this incident to APT28.

## Addendum, 2026-08-23: merging the digital-twin branch

`feature/digital-twin-reasoning-simulation` brought a plain-English advisor, a
streaming agent pipeline, a containment-aware isolation search and a Digital
Twin screen. Merged, with four defects repaired first and the latency claim
above corrected.

### The lane ran twice per investigation

The branch added an agent-lane invocation inside `_n_signals`, and the
cross-check added by this ADR already ran its own. Same frame, same scenario,
measured at two `run_pipeline` calls per `investigate()`. The lane now runs once
in `_n_signals` and the cross-check reuses the stashed summary. It could never
have disagreed with itself usefully in any case: it was the same computation.

`_n_signals` also imported `_attach_agent_pipeline` from `api.main`, so
`src/shared` depended on the API layer. Only an inside-the-function import kept
that off the import graph. The helper moved to `src.shared.enrich`.

### Measured latency, replacing the 90 ms above

| Scenario | Events | Deterministic analysis | Agent lane adds |
|---|---|---|---|
| aiims_ransomware | 125 | ~30 ms | **419 ms** |
| lanl_campaign_all | 2,732 | 185 ms | **1,910 ms** |

The lane is now roughly ten times more expensive than this ADR claimed. Nothing
regressed: the fixes in `6f637bf` made it do the work it was always supposed to,
mapping 269 of 287 flagged chunks instead of 60 and building 307 graph nodes
instead of 222. A second opinion costing 1.9 s against a 185 ms authoritative
answer is a real trade, and the honest way to state it is that **the
deterministic result is available in under 200 ms and the cross-check is
advisory**. If interactive latency ever matters more than the second opinion,
`run_crosscheck=False` is the switch and confidence drops accordingly, which is
the behaviour this ADR already specifies.

The new isolation search was suspected first and cleared by measurement: 47 ms
across two calls on the 473-node LANL graph.

### What was repaired before merging

The branch's narrative work made the output far more readable and, in several
places, made it assert things the data does not support. The readability is
kept; the claims are not.

- **`chat_advisor.py` invented facts.** An unknown crown-jewel list defaulted to
  `["core database server", "domain controller"]` and an unknown blast radius to
  3, so a bundle with no graph produced a confident briefing naming two servers
  that do not exist. It also said "our digital twin simulated taking X offline"
  and "the simulation confirms this eliminates risk" on a keyword match against
  the user's question, with no simulation run. Rewritten: absent values are
  reported absent, no outcome is promised, and the reply is never authoritative
  by either path.
- **Retrieved advisories went into the LLM prompt unfenced**, against this
  project's standing rule that retrieved content is evidence and never
  instruction. Excerpts are now fenced, the system prompt states the fence is
  quoted material, and a document containing instruction-like text is flagged in
  the reply rather than acted on.
- **Citations were given invented sources.** A missing URL defaulted to
  `https://attack.mitre.org` and a missing publisher to `MITRE / CISA / CERT-In`.
  A guessed citation is worse than none because it survives being checked. It
  was also reading `text` and `source_id` from `evidence.search`, which returns
  `excerpt` and `section`, so every excerpt was empty.
- **The streaming UI announced a model that never runs.** Stage 3 was labelled
  "Agent 2: Autoencoder Anomaly Detection Agent" and claimed "reconstruction
  error profiles". The autoencoder scores a chunk only when the chunk carries
  the seven engineered LANL features, and chunk aggregates never do: the split
  on `lanl_campaign_all` is 442 heuristic, 0 autoencoder. The label is now
  derived from the method that actually ran.

Two narrative over-claims were also removed. `reasoner._chain_explanation`
printed "strongly correlates with known advanced adversary campaign signatures"
whenever `actor_match` was true, a flag that fires on 34 of 39 LANL chains and
means only that some documented group uses the technique; and it had dropped the
corroborating signals from the text, keeping the conclusion while deleting the
evidence. `predictor.generate_prediction_narrative` closed with "Proactive
isolation of active pivot hosts will interrupt this path before crown-jewel
assets are compromised", and described each technique with hand-written prose
chosen by keyword-matching its name. It now quotes the real ATT&CK description
and states the measured 38.1% top-3 accuracy inline.

The tests that shipped with the branch asserted the exact marketing headings, so
they passed for all of the above. `tests/test_twin_and_narratives.py` now checks
properties instead: no fact appears that was not supplied, no outcome is
promised, a poisoned citation cannot close its own fence, and the advisor is
never authoritative.

### Kept unchanged

`attack_graph._best_isolation` is a genuine improvement and replaces a real
defect. Isolation used to be the highest-betweenness node, which is central but
need not protect anything; the twin once recommended isolating a user account.
It now ranks candidates by crown jewels protected and blast-radius reduction,
and returns no recommendation when no single removal helps. `iter_pipeline` and
the streaming progress, the Digital Twin screen, the error boundary and the
attack-graph simulation are kept as written.
