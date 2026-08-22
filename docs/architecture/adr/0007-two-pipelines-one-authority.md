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
  disabled with `run_crosscheck=False`.
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
