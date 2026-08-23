# PS7 operational evaluation

Evaluated: 2026-08-24 01:20 IST  ·  3 run(s) per scenario

## Per scenario

| Scenario | Events | Alerts | Alert rate | Incidents | MTTD | Exposure | Likelihood | Evidence conf. | Actionable claims | Citations | Actions (gated) | Executed | Median latency |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| aiims_ransomware | 125 | 26 | 21% | 2 | 2 h | 50.0 | 60.0 | 91.8 | 1/3 | 6 | 5 (4) | 0 | 205 ms |
| cbse_exam_breach | 127 | 26 | 20% | 1 | 2 h | 0.0 | 55.0 | 91.8 | 1/3 | 6 | 5 (4) | 0 | 156 ms |
| lanl_campaign_all | 2732 | 1243 | 46% | 51 | immediate | 80.0 | 60.0 | 89.0 | 1/4 | 6 | 5 (4) | 0 | 1723 ms |
| lanl_redteam_u66 | 215 | 208 | 97% | 9 | immediate | 5.0 | 60.0 | 91.8 | 1/3 | 6 | 5 (4) | 0 | 210 ms |

## ATT&CK mapping

- alerts carrying a technique: **100.0%** (1503 of 1503)
  - **and it is 100% by construction.** 100% by construction: the only unmapped event type is returned only for events below the alert threshold, so no alert can be unmapped. Read the technique distribution below instead -- it is what actually says how specific the mapping is.

| Technique | Alerts | Share of alerts |
|---|---|---|
| `T1550.002` | 691 | 46.0% |
| `T1078` | 560 | 37.3% |
| `T1110` | 251 | 16.7% |
| `T1021` | 1 | 0.1% |
- emitted technique IDs valid against the canonical ATT&CK lookups: **100.0%** (invalid: none)
- event->technique precision: **Not measured** -- Not measured: no public dataset used here carries a per-event ATT&CK technique label, so event->technique precision cannot be computed. We report coverage and ID validity, which we can.

## SOAR coverage

- observed tactics with a playbook action: **100.0%** (Credential Access, Initial Access, Lateral Movement)
- observed techniques with real MITRE mitigations: **100.0%**
- actions executed against a real system: **0** (by design -- every action is simulated and human-gated)

## Latency

- p50 **208 ms**, p95 **1793 ms**, max 3775 ms over 12 runs (full 7-node investigation, warm process, laptop CPU, no GPU)

## MTTD / MTTR

- MTTD: seconds from the first event in the log to the first correlated alert. Per scenario: aiims_ransomware 6936s, cbse_exam_breach 7647s, lanl_campaign_all 0s, lanl_redteam_u66 0s
- MTTR: **Not measured.** Every response action in this product is SIMULATED and human-gated. With no execution there is no repair to time. Claiming an MTTR improvement would be fabricating the headline number PS7 asks for.

## Auditability and authorisation

- hash chain verifies: **True**; tampering detected: **True** (`record 1 (analysis.completed): content hash mismatch -- this record's contents were altered after it was written`)
- viewer denied `approve_critical`: **True**; crown-jewel action gated: **True**; low-impact pre-approved: **True**
