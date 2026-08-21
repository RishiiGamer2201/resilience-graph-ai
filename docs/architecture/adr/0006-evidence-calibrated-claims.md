# ADR 0006 — ATT&CK conclusions are claims, not facts; four numbers, not one

- **Status:** accepted
- **Date:** 2026-08-19
- **Source:** `research/codex/it_ot_attack_detection_digital_twin_research.md` §6, §7, §15

## Context

Two problems, both of which the system had.

**We were asserting a technique from an anomaly score.** Earlier the same day, to
lift ATT&CK mapping coverage from 37.5% to 100%, every anomalous-but-successful
login was mapped to `T1078 Valid Accounts`. Coverage went up. Honesty went down.
The research names this exact risk:

> Anomaly establishes unusualness; T1078 additionally asserts adversarial use of
> a legitimate account. The system may create a candidate T1078 claim, but should
> expose the missing evidence and retain a benign alternative such as role
> change, travel, maintenance, or new device enrollment.

An authentication log cannot distinguish a compromised account from a nurse who
changed wards. Printing `T1078` next to that event tells an analyst it can.

**We were collapsing four questions into one number.** `attack_progression_confidence`
averaged tactic coverage, detector score, path depth **and** citation
corroboration. The first three are about how far along an intrusion looks; the
fourth is about how good our evidence is. Research §7:

> A single "87% attack score" hides too much. The UI should say, for example:
> "likelihood high, impact critical, confidence medium; strongest missing
> evidence is endpoint process telemetry on host X."

## Decision

**Every ATT&CK conclusion is a `Claim` with a status, its evidence, the evidence
it lacks, and the benign explanations it has not excluded. The four numbers are
reported separately.**

`src/shared/claims.py`:

- **Status vocabulary** — `observed`, `inferred`, `predicted`, `confirmed`,
  `disputed`, `retracted`. Only `observed` and `confirmed` are **actionable**.
- **Confidence is noisy-OR across independence groups.** Within a group the
  strongest evidence wins; across groups they compound:
  `C = 1 − Π(1 − strength × reliability)`. Ten copies of one detector's signal
  give exactly the confidence of one copy. This is the research's "repeating the
  same evidence through several agents must never increase confidence", enforced
  by construction rather than by reviewer vigilance.
- **The detector and the rule that reads its features share one group.** The rule
  fires *because* of the detector's output, so they cannot corroborate each other.
- **Contradiction discounts confidence** and flips the claim to `disputed`.
- **`Assessment`** carries anomaly, likelihood, impact and confidence, each with
  the distinct question it answers. An unmeasured dimension reads `not measured`.

The calibration lives in `attack_mapper.CLAIM_RULES`, one entry per rule, with
strength, missing evidence, benign alternatives and a note.

## Consequences

- `T1078` from an anomaly is now `inferred`, strength 0.30, confidence ~0.19,
  **not actionable** — and a maximum anomaly score cannot change that, because
  the ceiling is the rule's strength, not the detector's certainty.
- Directly observable rules outrank interpretations: a failed-login burst is
  `observed` at 0.70; an inferred lateral-movement technique is not.
- `attack_progression_confidence` is renamed `attack_progression_likelihood` and
  no longer contains `evidence_corroboration`. `evidence_confidence` is its own
  figure with its own formula.
- **Mapping coverage is no longer the headline retrieval-side metric it was.**
  100% coverage now means "every alert carries a candidate", not "every alert is
  explained". The scoreboard should report actionable claims alongside it.
- Two real bugs fell out of building this: `correlate.py` never carried
  `event_type` into a step, so every claim silently fell back to `normal_auth`
  and reported zero confidence; and citation corroboration at reliability 1.0
  pinned evidence confidence at exactly 100 whenever every technique had a
  citation. A citation proves a technique is *documented*, not that it *occurred*,
  so its reliability is capped at 0.5.

## What would change our mind

- Adjudicated outcomes. The research's §7 recommends maintaining a reliability
  posterior per detector (`precision ~ Beta(α + TP, β + FP)`) updated only from
  adjudicated evidence, incident closure or red-team replay. Our `strength` and
  `reliability` values are hand-set from what each observation can support; they
  are honest but they are not learned. With labelled outcomes they should be.
- Independent telemetry. Endpoint process data would put a second real
  independence group behind most claims, which is the whole point of the
  structure — today almost every claim has exactly one.
