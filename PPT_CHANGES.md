# PPT Update Checklist — old numbers, names, models to fix

> What to change in the pitch deck (`ET Hack (1).pdf` / the Canva/PPTX source) so it
> matches the current code. Grouped by slide. Every "new" value is verified against
> `reports/metrics.json`, `reports/scaling_measurements.json`, and the live cache.

## The four global changes (they repeat across slides)

| Thing | Old (in deck) | New (correct) |
|---|---|---|
| Product name | Resilience Graph AI | **nextATT&CKs** |
| Detection model (shipped) | IsolationForest | **Autoencoder** (benign-trained; IsolationForest is now the *previous* model, kept only as comparison) |
| Prediction model (shipped) | Markov (1st-order) | **Interpolated Markov** |
| Anti-circularity margin | 5.2x kill-chain | **5.4x** kill-chain |

Do **not** change the URLs. `github.com/RishiiGamer2201/resilience-graph-ai` and
`resilience-graph-ai.onrender.com` are the real repo and site names and still work.
Only the *display name* changed, not the repo.

---

## Slide 1 — Title
No change. It already reads PS-7 / AI-Driven Cyber Resilience. (Optional: add the
product name **nextATT&CKs** somewhere on the title slide if you want it up front.)

## Slide 2 — Problem / Why current security fails
Title already says **nextATT&CKs** — good, no change.
No numbers to fix here (CERT-In 1.59M+, 70%+ end-of-life IT are external facts, still correct).

## Slide 3 — Motivation & Solution
- **Name:** "Resilience Graph AI approaches the problem differently" -> **"nextATT&CKs approaches the problem differently"**
- **Model:** pipeline box "Behavioural Anomaly Detection — **Isolation Forest** identifies suspicious events" -> **"Autoencoder identifies suspicious events"** (or "Autoencoder / Isolation Forest" if you want to show both).

## Slide 4 — Features
- **Model:** "Live event scoring — Score a single auth event on stage with the real **IsolationForest**" -> **"...with the real Autoencoder"**.
- **Prediction (optional wording):** "Next technique prediction — Ranked next moves with a real transition probability (e.g. 52.5%)" — the 52.5% example is still fine (it is a real transition in the table). No change needed unless you want to say "interpolated Markov".
- Numbers here (104 accounts) are unchanged.

## Slide 5 — Architecture Overview
- **Engine One "Behavioral Detection Engine — Uses Isolation Forest and Autoencoder models":**
  the shipped detector is now the **Autoencoder**. Either reword to
  **"Autoencoder (shipped) with Isolation Forest as the baseline comparison"**, or at
  minimum make the Autoencoder the primary. Keeping "Isolation Forest and Autoencoder"
  is not wrong (both were built), but a judge should see the Autoencoder is what ships.
- No numeric values on this slide.

## Slide 6 & 7 — Technical Architecture (these two are the same diagram)
**Replace the whole image** with the regenerated one:
`reports/technical_architecture_final.png` (already updated in the repo). If you are
editing the boxes by hand instead, the exact changes are:

- **Detection engine box:**
  - "IsolationForest, benign trained" -> **"Autoencoder, benign trained"**
  - "LANL ROC AUC 0.988" -> **"LANL ROC AUC 0.992"**
  - "CICIDS PR AUC 0.57" -> **"TPR 87.7 pct at 1 pct FPR"** (this operating-point number is the real win; ROC alone barely moved)
- **Prediction and attribution box:**
  - "Markov next technique" -> **"Interpolated Markov next technique"**
  - "5.2x kill chain baseline" -> **"5.4x kill chain baseline"**
- **Persisted runtime artifacts box:**
  - "iforest and Markov models" -> **"autoencoder and Markov models"**
- Everything else on the diagram (planes, endpoints, spine stages, deployment line)
  is still correct.

## Slide 8 — Technical Architecture (alternate stylised diagram)
- **Detection Engine — "Isolation Forest & Autoencoder"** -> make the **Autoencoder**
  the shipped one (e.g. "Autoencoder (Isolation Forest baseline)").
- **Prediction & Attribution — "Predict next technique & likely threat group"**: fine,
  but if a model is named, it should be **Interpolated Markov**.
- No numeric values on this slide.

## Slide 9 — Impact & Honesty
- **Table header:** "With **Resilience Graph AI**" -> **"With nextATT&CKs"**
- **Analyst load row:** "**1,192** alerts to triage" -> **"1,243 alerts to triage"**
- **Containment row:** "Which of **479** hosts?" -> **"Which of 473 hosts?"** (the
  "Isolate 1 -> cut **463**" stays the same, that number did not change)
- **Honesty rule #3:** "Anti-circularity, out loud — Markov **5.2x** the kill-chain
  baseline" -> **"Interpolated Markov 5.4x the kill-chain baseline"**
- Links: unchanged (real URLs).
- Everything else (10-day dwell, who-benefits, real-vs-simulated) is still correct.

## Slide 10 — Feasibility & Scalability
- **Replace the chart image** with the regenerated one:
  `reports/scaling_chart_detailed.png` (already updated in the repo). If editing by hand:

  **Scaling table (bottom-left of the chart):**

  | EVENTS | old TIME / ALERTS / THROUGHPUT | new TIME / ALERTS / THROUGHPUT |
  |---|---|---|
  | 2,732 | 0.140s / 1,192 / 19,514/s | **0.131s / 1,243 / 20,855/s** |
  | 10,000 | 0.535s / 4,202 / 18,692/s | **0.508s / 4,808 / 19,685/s** |
  | 20,000 | 1.021s / 8,090 / 19,589/s | **0.956s / 9,458 / 20,921/s** |
  | 50,000 | 2.493s / 20,185 / 20,056/s | **2.186s / 22,661 / 22,873/s** |

  **"WHAT THE DATA SHOWS" panel:**
  - "2.493s — 50K-event full-pipeline latency" -> **"2.186s"**
  - "20,056/s — sustained event throughput at the cap" -> **"22,873/s"**
  - "20,185 — alerts produced from the 50K workload" -> **"22,661"**
  - "49.9 ms — processing time per 1,000 events at 50K" -> **"43.7 ms"**

  **Chart annotations:**
  - "REAL CAMPAIGN — 2,732 events - 0.140s" -> **"2,732 events - 0.131s"**
  - "DOCUMENTED CAP — 50,000 events - 2.493s" -> **"50,000 events - 2.186s"**

  **The "Property / Evidence" table on this slide:**
  - "Model light serving — Embeddings precomputed; runtime unpickles sklearn + Markov only"
    -> the detector no longer unpickles sklearn at runtime; it runs the Autoencoder in
    NumPy. Reword to **"Embeddings precomputed; runtime runs the Autoencoder in NumPy plus the Markov table — no torch"**.
  - "Runs anywhere — One Docker container, no GPU runtime, slim deps (no torch)" stays
    correct (the autoencoder ships as NumPy weights, so still no torch at runtime).
  - "29 automated tests" is still correct.
  - "Metric integrity — Eval scripts write reports/metrics.json; the UI **it** - drift
    impossible" has a typo ("the UI it") -> **"the UI reads it - drift impossible"**.

## Slide 11 — Thank you
No change.

---

## Quick summary of every number that changed

| Metric | Old | New | Where in deck |
|---|---|---|---|
| Product name | Resilience Graph AI | nextATT&CKs | slides 3, 9 (2 already done) |
| LANL detector | IsolationForest | Autoencoder | slides 3, 4, 5, 6/7, 8 |
| LANL ROC-AUC | 0.988 | 0.992 | slides 6/7 |
| LANL TPR @ 1% FPR (new, add it) | (not shown) | 87.7% (616/702) | slides 6/7 |
| Predictor | Markov | Interpolated Markov | slides 6/7, 8, 9 |
| Anti-circularity | 5.2x | 5.4x | slides 6/7, 9 |
| Alerts | 1,192 | 1,243 | slides 9, 10 |
| Hosts | 479 | 473 | slide 9 |
| Isolate-1 cut | 463 | 463 (unchanged) | slide 9 |
| 50K latency | 2.493s | 2.186s | slide 10 |
| 50K alerts | 20,185 | 22,661 | slide 10 |
| 50K throughput | 20,056/s | 22,873/s | slide 10 |
| ms per 1,000 events | 49.9 ms | 43.7 ms | slide 10 |
| 2,732 latency | 0.140s | 0.131s | slide 10 |

Numbers that did **not** change (leave them): 2,732 events, 104 accounts, 4 pivots,
isolate-1-cuts-463, CERT-In 1.59M+, 70%+ end-of-life IT, ~10-day dwell, 519M lines
streamed, 12-field schema, 29 tests, CICIDS autoencoder PR-AUC 0.57.

Two easiest wins: **swap slide 6/7 and slide 10 images** for the regenerated
`reports/technical_architecture_final.png` and `reports/scaling_chart_detailed.png` —
that fixes most of the numbers in one step.
