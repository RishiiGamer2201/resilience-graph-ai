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
