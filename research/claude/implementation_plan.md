# Resilience Graph AI — End-to-End Implementation Plan

**PS7 · Critical National Infrastructure · Date:** 2026-07-10
**Tracks:** [final_pipeline.md](final_pipeline.md) · **Owners:** M1 vision/graph · M2 anomaly · M3 NLP/KG · M4 data/MLOps/UI
**How to use:** check boxes as done. Each task has an **Acceptance** (definition of done) and a **Deliverable** (the file/artifact). Don't mark done until Acceptance is verifiably true.

**Legend:** 🔴 critical-path (blocks others) · 🟡 core · 🟢 polish/stretch

---

## Milestone 0 — Repo & environment setup *(Day 0 · owner M4)* — ✅ COMPLETE

- [x] 🔴 Create Python env + `requirements.txt` (`pandas pyarrow numpy scikit-learn torch sentence-transformers networkx streamlit stix2 mitreattack-python matplotlib`) — **venv on Python 3.10.11**, all deps installed
- [x] 🔴 Add repo structure: `src/{engine1,engine2,shared,app}/`, `configs/`, `models/`, `reports/`
- [x] 🔴 `src/schema.py` — freeze the common event schema (single source of truth) — **smoke test passed**
- [x] 🟡 `.gitignore` for `data/raw/`, `models/*.pkl`, `__pycache__` (don't commit 11GB) — also excludes `.venv/`, models, processed
- [x] 🟡 One-line "who owns what / branch naming" note in `README.md` to avoid Codex/Claude/human edit collisions
- [x] 🔴 **Acceptance:** imports clean — torch 2.13.0+cpu · sklearn 1.7.2 · sentence-transformers 5.6.0 · networkx 3.4.2 · streamlit 1.59.1
- **Deliverable:** `requirements.txt`, `src/schema.py`, folder skeleton. ✅ committed (`e8d2137`)
- **Note:** Python pinned to **3.10.11** (was 3.13) per team decision for library compatibility.

---

## Milestone 1 — PHASE 0: Data Foundation 🔴 *(Days 1–2 · owner M4, +M2)*
*Everyone is blocked until this is done. Do it first, together if needed.*

- [x] 🔴 **0.1 CICIDS preprocess** — unzip `MachineLearningCSV.zip`; strip column-name whitespace; drop/clip `Inf`/`NaN` in flow-rate cols; dedupe; **drop leakage cols (esp. `Destination Port`/IPs)**; concat 9 daily CSVs; keep `Label` ✅
  - **Handle the 3 known CICIDS pitfalls (from team research):** (A) extreme imbalance >80% benign → never report accuracy, use PR-AUC/F1/recall [Engine 1 unsupervised sidesteps it; SMOTE only for a supervised baseline]; (B) NaN/Inf in `Flow Bytes/s` & `Flow Packets/s` → clip/drop + log row count; (C) leakage/duplicates → drop identifier cols, dedupe, split by day.
  - **Acceptance:** ✅ loads as one dataframe, no `Inf`/`NaN`, label distribution printed, identifier cols dropped, split by day.
  - **RESULT:** 2,830,743 raw → **2,297,036** rows · 77 features · **85.4% benign / 14.6% attack** · 4,376 Inf cells fixed · 530,840 dupes dropped · 15 attack types · 1,960,544 benign-only rows for unsupervised training. See `reports/cicids_prep.md`.
  - **Deliverable:** `data/processed/cicids2017/flows.parquet` (gitignored) + `src/engine1/prep_cicids.py` ✅
- [ ] 🔴 **0.2 LANL red-team window** — **stream** `auth.txt.gz` (never fully unzip); keep events on days 1–29 within ±N sec of the 749 red-team events + a matched normal-auth sample; join red-team labels
  - **Acceptance:** parquet has both classes; red-team rows labeled 1; row count sane (<few M rows); memory stays bounded (streamed).
  - **Deliverable:** `data/processed/lanl/auth_redteam_window.parquet` + `src/engine1/prep_lanl.py`
- [x] 🔴 **0.3 ATT&CK lookups** — parse Enterprise + ICS STIX into dicts: `technique→tactics`, `group→techniques`, `technique→mitigations`, `technique→description`, `campaign→techniques` ✅
  - **Acceptance:** ✅ self-test passes — APT29: 66 techniques; T1078 = "Valid Accounts" w/ 8 mitigations; pickle reloads.
  - **RESULT:** 794 techniques · 172 groups · 57 campaigns · 96 mitigations (682 techniques mapped to mitigations). See `reports/attack_lookups.md`.
  - **Deliverable:** `data/processed/mitre_attack/attack_lookups.pkl` (gitignored) + `src/shared/parse_attack.py` ✅
- [ ] 🔴 **0.4 Schema freeze** — implement + document the 12-field common event schema; normalizers for CICIDS & LANL emit it
  - **Acceptance:** both datasets round-trip through `normalize()` into identical columns.
  - **Deliverable:** `src/schema.py` (finalized), `src/shared/normalize.py`

---

## Milestone 2 — ENGINE 1: Real Detection 🟡 *(Days 2–5 · owner M2, +M1)*
*This is the number that earns Technical Excellence (20%). Build before the fancy stuff.*

- [ ] 🔴 **E1.2a Baselines first** — implement (a) random scorer, (b) rule threshold (failed-login count / bytes threshold)
  - **Acceptance:** baseline precision/recall/F1 printed on CICIDS. *(You cannot claim lift without these.)*
  - **Deliverable:** `reports/baseline_metrics.md`
- [ ] 🟡 **E1.2b IsolationForest** — train on normal traffic only; score; tune contamination
  - **Acceptance:** ROC-AUC + PR curve on CICIDS labels; **beats both baselines** (report the lift number).
  - **Deliverable:** `models/iforest_cicids.pkl`, `reports/evaluation_report.md`
- [ ] 🟢 **E1.2c Autoencoder** — comparison model (only if time)
  - **Acceptance:** side-by-side vs IsolationForest in eval report.
- [ ] 🔴 **E1.3 LANL lateral movement** — features (new-host auth, failed→success burst, rare-dest, auth fan-out); score window; evaluate vs red-team ground truth
  - **Acceptance:** **TPR @ fixed FPR** reported on the 749 red-team events; confusion matrix; cite ~85%@<1% as literature context (not our claim).
  - **Deliverable:** `reports/lanl_redteam_detection.md`, scored events parquet
- [ ] 🟢 **E1.x UNSW-NB15** — second benchmark to show generalization (stretch)

---

## Milestone 3 — ENGINE 2: Prediction & Attribution 🟡 *(Days 3–7 · owner M3)*
*The Innovation (25%) centerpiece. E2.4 is the highest-risk single task — budget for it.*

- [ ] 🔴 **E2.2 Sequence dataset (~196 + 3–5)** — auto-build: every group + campaign with ≥6 techniques, ordered by kill-chain tactic order; schema `{source, actor, ordered_technique_ids, is_manual}`
  - **Acceptance:** ≥190 auto sequences generated; sequence-level train/val/test split; counts printed.
  - **Deliverable:** `data/processed/engine2/sequences.json` + `src/engine2/build_sequences.py`
- [ ] 🟡 **E2.2b Manual CERT-In sequences** — hand-curate 3–5 from CERT-In advisories (optionally TRAM-assisted then corrected); flag `is_manual=true`
  - **Acceptance:** 3–5 sequences added, source-referenced; the honest split is documented.
- [ ] 🟡 **E2.3 Technique embeddings** — descriptions → all-MiniLM-L6-v2
  - **Acceptance:** cosine sanity check: same-tactic techniques cluster tighter than random pairs.
  - **Deliverable:** `data/processed/engine2/technique_embeddings.pkl`
- [ ] 🔴 **E2.4a Baselines FIRST** — (1) most-frequent-next-technique, (2) kill-chain-order heuristic, (3) first-order Markov transition model
  - **Acceptance:** top-1/top-3/top-5 reported for all 3 baselines. *(⚠️ These guard the circularity trap — do before the neural net.)*
  - **Deliverable:** `reports/prediction_baselines.md`
- [ ] 🔴 **E2.4b Neural predictor** — LSTM or small Transformer over embedding sequences → next technique
  - **Acceptance:** top-1 AND top-3/top-5 reported; **lift over all 3 baselines shown** (if no lift over Markov → present Markov instead); manual-vs-heuristic broken out.
  - **Deliverable:** `models/next_technique.pt`, `reports/prediction_eval.md`
  - **Fallback ready:** raw-technique-ID model, or tactic-level (14-class) as headline metric.
- [ ] 🟡 **E2.5 Actor attribution** — group technique-usage profiles; similarity vs observed sequence; templated justification string
  - **Acceptance:** given a partial sequence, returns ranked actors + "matches 4/6 of APT41" style justification.
  - **Deliverable:** `src/engine2/attribution.py`

---

## Milestone 4 — SHARED SPINE 🟡 *(Days 5–8 · owner M1 graph, M4 rest)*

- [ ] 🟡 **S2 Attack-chain correlation** — group alerts by user/source-host/time-window/shared-dest/rising-severity → one incident timeline
  - **Acceptance:** N raw alerts collapse into 1 incident object with ordered events + severity.
  - **Deliverable:** `src/shared/correlate.py`
- [ ] 🟡 **S3 ATT&CK mapper** — rule-based `event_type→technique` for demo confidence; RAG over ATT&CK descriptions for explanation, LLM constrained to valid technique IDs
  - **Acceptance:** each chain step tagged `tactic/technique/T-ID/confidence/explanation`; no hallucinated IDs.
  - **Deliverable:** `src/shared/attack_mapper.py`
- [ ] 🔴 **S4 Attack-path graph** — nodes (users/hosts/servers/DBs/critical assets/ext IPs), edges (logged-into/connected/accessed-db/sent-to); built on real LANL host graph
  - **Acceptance:** shortest-path-to-critical-asset + betweenness (choke points) + blast-radius computed and rendered.
  - **Deliverable:** `src/shared/attack_graph.py`, graph viz
- [ ] 🟡 **S5 Simulated SOAR** — `technique/tactic→action` from ATT&CK mitigations + realistic actions; confidence gating (low→monitor, med→ticket, high→contain, critical-asset→human approval)
  - **Acceptance:** each incident yields gated actions; critical-asset action blocked pending approval in UI.
  - **Deliverable:** `src/shared/soar.py`, `configs/playbook_map.json`

---

## Milestone 5 — DEMO APP & INTEGRATION 🔴 *(Days 7–10 · owner M4)*
*2nd-biggest risk after E2.4. A broken live demo tanks UX (15%) + the whole impression.*

- [ ] 🔴 **S6a Streamlit replay** — step through LANL-derived event stream timestamped; per event show: anomaly flag → mapped technique → predicted next 2–3 → attributed actor → gated action
  - **Acceptance:** full replay runs end-to-end on one scenario without manual intervention.
  - **Deliverable:** `src/app/dashboard.py`
- [ ] 🔴 **S6b Pre-cache + recorded fallback** — pre-compute all outputs; "recorded" mode that needs no live inference
  - **Acceptance:** demo runs with network/inference disabled. *(Non-negotiable for the live pitch.)*
- [ ] 🟡 **S6c Incident report generator** — auto-produce audit-ready report (ID, severity, summary, ATT&CK chain, path, predictions, actor, gated response)
  - **Deliverable:** `reports/incident_INC-001.md` (generated)
- [ ] 🟡 **S6d MTTD delta panel** — show weeks→minutes detection-time story visually
- [ ] 🟡 **2–3 India scenarios** — ransomware pattern echoing AIIMS/CBSE; concrete > generic
  - **Acceptance:** each scenario replays cleanly + has a one-line stakes framing.
- [ ] 🟢 **3-agent narrative wrapper** — name components Anomaly/Prediction/Response agents (polish only, not a rebuild)

---

## Milestone 6 — PITCH & SUBMISSION 🔴 *(Days 10–12 · all)*

- [ ] 🔴 Deck with the 4 **honesty rules** stated explicitly (sequence split · real-data metrics · baseline lift · SOAR simulated)
- [ ] 🔴 Record a backup demo video (in case live fails)
- [ ] 🟡 30-second hook rehearsed (the demo sentence from the pipeline)
- [ ] 🟡 Anticipate the sharp judge Q&A: circularity, synthetic-data honesty, scale-to-production path
- [ ] 🟡 Architecture diagram (from final_pipeline.md) polished for slide
- [ ] 🟢 One-page concept note handout

---

## Critical path (the chain that determines finish time)
`M0 env → 0.1/0.2/0.3 data → E1.2 anomaly+baseline → E2.2 sequences → E2.4 predictor → S4 graph → S6 dashboard+fallback → deck/video`

## Risk register
| Risk | Mitigation | Owner |
|---|---|---|
| E2.4 predictor shows no lift over Markov | Present Markov honestly; fall back to tactic-level | M3 |
| Circularity spotted by judge | Baselines built first; disclosed in deck | M3 |
| Live demo fails | Pre-cached + recorded fallback (S6b) | M4 |
| LANL too big to process | Streamed windowed extract only (0.2) | M2 |
| Multi-agent file collisions (Codex/Claude/human) | Branch/ownership note (M0) | M4 |
| Scope creep (5 threads) | 🟢 tasks are cut first if behind | all |

## Definition of "demo-ready" (minimum to present)
✅ Real anomaly metric on CICSIDS **or** LANL with baseline lift · ✅ ~196-sequence predictor with baseline comparison · ✅ attack-path graph to a critical asset · ✅ gated SOAR · ✅ Streamlit replay with recorded fallback · ✅ one India scenario.

---
*Check boxes as completed. If behind schedule, cut 🟢 first, then defer 🟡 stretch items; never cut 🔴.*
