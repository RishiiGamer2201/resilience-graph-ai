# Resilience Graph AI — FINAL Pipeline (v1.0, all improvements merged)

**Status:** build-ready · **Date:** 2026-07-10
**Merges:** team doc Tab 2 "pipeline" + "Improvements" pass + decision-memo corrections (two engines, real data, honest baselines).
**One-line pitch:** *We detect low-and-slow attacks in real logs, connect weak signals into an explainable MITRE ATT&CK chain, predict the attacker's next moves, name the likely actor, and recommend gated containment — before the breach completes.*

---

## Architecture at a glance

```
                         ┌─────────────────────────────────────────────┐
                         │        PHASE 0 — DATA FOUNDATION            │
                         │  CICIDS csv · LANL extract · ATT&CK lookups │
                         └───────────────┬─────────────────────────────┘
              ┌──────────────────────────┴──────────────────────────┐
              ▼                                                     ▼
┌───────────────────────────────┐              ┌───────────────────────────────────┐
│ ENGINE 1 — REAL DETECTION     │              │ ENGINE 2 — PREDICTION+ATTRIBUTION │
│ (Technical Excellence, 20%)   │              │ (Innovation, 25%)                 │
│ E1.1 CICIDS preprocess        │              │ E2.1 ATT&CK lookup tables         │
│ E1.2 anomaly model + baseline │              │ E2.2 sequence dataset (~196+5)    │
│ E1.3 LANL lateral movement    │              │ E2.3 technique embeddings         │
│      vs red-team ground truth │              │ E2.4 next-technique model         │
└──────────────┬────────────────┘              │      + Markov/heuristic baselines │
               │ anomaly scores                │ E2.5 actor attribution + template │
               ▼                               └────────────────┬──────────────────┘
┌──────────────────────────────────────────────────────────────┴──────────────────┐
│                            SHARED SPINE                                          │
│ S1 normalized event schema → S2 attack-chain correlation → S3 ATT&CK mapper      │
│ → S4 attack-path graph → S5 simulated SOAR (confidence-gated)                    │
└──────────────────────────────────┬───────────────────────────────────────────────┘
                                   ▼
                    ┌──────────────────────────────┐
                    │ S6 STREAMLIT SOC DASHBOARD   │
                    │ replay mode · attack graph   │
                    │ predictions · SOAR approvals │
                    │ incident report · MTTD delta │
                    └──────────────────────────────┘
```

**The demo sentence that joins everything:** real anomaly fires (E1) → chain forms (S2) → each step maps to ATT&CK (S3) → *"attacker's likely next 2–3 moves are X, Y, Z — profile matches APT41 4/6"* (E2) → path to critical asset lights up (S4) → containment recommended, awaiting analyst approval (S5).

---

## PHASE 0 — Data foundation *(everyone blocked until done — do first)*

| Step | What | Output |
|---|---|---|
| 0.1 | Unzip CICIDS `MachineLearningCSV.zip` → clean (strip col whitespace, drop/clip `Inf`/`NaN`, dedupe) | `processed/cicids2017/*.parquet` |
| 0.2 | LANL windowed extract: **stream** `auth.txt.gz` (never fully unzip — ~70GB), keep days 1–29 ± context around the 749 red-team events + matched normal-auth sample | `processed/lanl/auth_redteam_window.parquet` |
| 0.3 | Parse ATT&CK STIX (Enterprise + ICS) into lookups: `technique→tactics`, `group→techniques`, `technique→mitigations`, `technique→description`, `campaign→techniques` | `processed/mitre_attack/attack_lookups.pkl` |
| 0.4 | Freeze the common event schema (below) — all datasets normalize into it | `src/schema.py` |

**Common event schema (S1):**
`timestamp · user · source_host · destination_host · event_type · status · protocol · port · bytes_out · command · asset_criticality · label`

---

## ENGINE 1 — Real detection *(Technical Excellence 20% · owner M2, +M1 on graph)*

### E1.1 CICIDS preprocess
Clean 9 daily CSVs → unified labeled table. Feature set = flow stats; keep `Label`. Train/test split by day (avoid leakage).

**⚠️ CICIDS-2017 known pitfalls — handle explicitly (judges reward this):**
- **A. Extreme class imbalance** (>80% BENIGN). *Accuracy is a trap* — a "always benign" guess scores ~80% and catches zero attacks. **We sidestep it by design:** Engine 1 is unsupervised anomaly detection trained on **benign-only**, so imbalance doesn't bias training and **SMOTE is N/A**. Report **PR-AUC / F1 / recall**, never accuracy. *(Only if we add a supervised classifier baseline do class-weighting/SMOTE apply.)*
- **B. NaN / Infinity** in `Flow Bytes/s`, `Flow Packets/s` (CICFlowMeter quirk) → clip/drop; log how many rows affected.
- **C. Leakage / duplicates** → drop identifier columns (esp. `Destination Port`) so the model can't memorize them; dedupe repeated flows; be aware of CICIDS-2017's known label errors (Engelen et al. 2021, "Improved CICIDS2017"). Split by day, not random row shuffle.

### E1.2 Anomaly model + baselines *(the verifiable claim)*
- **Model:** IsolationForest (primary) + Autoencoder (comparison), trained on **normal traffic only**.
- **CICIDS eval:** **PR-AUC (primary, robust to imbalance)** + precision / recall / F1; ROC-AUC secondary. *Never headline accuracy.*
- **⚠️ MUST report lift vs baselines:** (a) random, (b) rule threshold (e.g. failed-login count). *Lift over baseline = the actual Technical-Excellence point; a lone accuracy number is not.*
- **Output:** per-event anomaly score + `evaluation_report.md`.

### E1.3 LANL lateral-movement detection *(the moat — real ground truth)*
- Score auth events in the windowed extract; evaluate detection of red-team events vs `redteam.txt` ground truth.
- **Headline metric:** TPR @ fixed FPR. Literature bar for context (cite, don't claim): ~85% TPR @ <1% FPR for graph-based detectors (USENIX RAID'20, GL-GV, LMDetect).
- Features: new-host auth, failed→success bursts, rare-destination, auth fan-out per user/time.
- **Output:** scored LANL events + red-team detection metrics.

---

## ENGINE 2 — Prediction & attribution *(Innovation 25% · owner M3)*

### E2.1 ATT&CK lookup tables *(light — reuse Phase 0.3)*
Validate with manual queries (APT29 techniques, mitigations for T1078). No training.

### E2.2 Sequence dataset *(~196 auto + 3–5 manual — NOT 15–25)*
- **Auto (bulk, scriptable):** every group + campaign with ≥6 techniques → **145 groups + 51 campaigns = ~196 sequences**, ordered by ATT&CK tactic kill-chain order.
- **Manual (differentiator):** hand-curate **3–5 CERT-In advisory** sequences (read → map). Optionally run **MITRE TRAM** to auto-suggest tags then correct (shows automated extraction w/o building an NLP model).
- **Schema:** `{source, actor_or_advisory, ordered_technique_ids, is_manual}`.
- **Split at sequence level** (not across steps).
- **Output:** `sequences.json` (flagged heuristic vs manual — disclose the split in the pitch).

### E2.3 Technique embeddings *(very light, no training)*
Technique descriptions → **all-MiniLM-L6-v2** → `technique_embeddings.pkl`. Sanity check: same-tactic techniques cluster (cosine).

### E2.4 Next-technique predictor *(centerpiece — do properly)*
- Embedding sequences → **LSTM / small Transformer**, predict next technique. Report **top-1 AND top-3/top-5**.
- **⚠️ CIRCULARITY FIX (survives judge Q&A):**
  - Sequences ordered by kill-chain heuristic → model can trivially re-learn ordering. So **predict the specific technique** (525-vocab) that tactic-order *can't* determine.
  - **Always show lift over 2 baselines:** (1) most-frequent-next-technique, (2) the kill-chain-order heuristic itself.
  - If a **first-order Markov** model matches the neural net → present Markov. Honest > fancy.
  - Disclose: **21% of techniques span >1 tactic** → ordering ambiguous for 1-in-5 steps.
- **Fallback:** raw-technique-ID model, or **tactic-level prediction (14 classes)** as headline + technique-level secondary.
- **Output:** model + `prediction_eval.md` (metrics, baseline lift, manual-vs-heuristic broken out).

### E2.5 Actor attribution *(medium, no classifier)*
Group technique-usage profiles → score observed sequence vs each (overlap/embedding sim) → ranked actors. **Templated justification:** *"predicted next T1078 (Valid Accounts) — matches 4/6 of APT41's techniques."*

---

## SHARED SPINE *(owner M1 graph, M4 rest)*

- **S1 Normalize** → common schema (Phase 0.4).
- **S2 Attack-chain correlation** — group alerts by user / source host / time window / shared dest / rising severity → **one incident timeline** (kills alert fatigue).
- **S3 ATT&CK mapper** — rule-based technique lookup for high-confidence demo; **RAG over ATT&CK descriptions** for explanation only, LLM constrained to valid technique IDs.
- **S4 Attack-path graph** — nodes (users/hosts/servers/DBs/critical assets/external IPs), edges (logged-into/connected/accessed-db/sent-to). Algorithms: shortest path to critical asset · betweenness (choke points) · reachability · blast radius. Built on **real LANL host graph**. *Strongest visual.*
- **S5 Simulated SOAR** — `technique/tactic→action` from ATT&CK mitigations + realistic actions. **Gating:** low→monitor · med→ticket+enrich · high→recommend containment · **critical asset→human approval**.
- **S6 Streamlit dashboard** — **replay mode** stepping through the LANL-derived stream; per event: anomaly flag → mapped technique → predicted next 2–3 → attributed actor → gated action. **Pre-cache all outputs; keep a recorded fallback.** Prep **2–3 India scenarios** (ransomware echoing AIIMS/CBSE). Show **MTTD delta** (weeks→minutes). *(Optional: wrap as 3 named agents for narrative — not a rebuild.)*

---

## Grounding numbers *(measured from our files, 2026-07-10)*
| Fact | Value | Source |
|---|---|---|
| Auto-buildable sequences | ~196 (145 groups + 51 campaigns ≥6 tech) | `enterprise-attack.json` |
| Prediction vocabulary | 525 distinct techniques | " |
| Techniques spanning >1 tactic | 21% (145/697) | " |
| LANL red-team events | 749 · 104 users · days 1–29 of 58 | `redteam.txt.gz` |
| Datasets on disk | CICIDS, LANL (all 5), UNSW, ATT&CK ent+ICS | `data/raw/` verified |

## Owner split
| Owner | Modules |
|---|---|
| **M2** time-series/anomaly | E1.1–E1.3 (real detection — the verifiable moat) |
| **M1** vision/graph | S4 attack-path graph + graph features; assist M2 on LANL |
| **M3** NLP/LLM/KG | E2.1–E2.5 (all of Engine 2), S3 mapper |
| **M4** data/MLOps/UI | Phase 0, S5 SOAR, S6 dashboard + incident report + pre-cached fallback |

## Honesty rules *(put in the deck)*
1. Sequences: state heuristic-ordered vs manually-curated counts.
2. Anomaly metrics: all on real data (CICIDS/LANL) — no synthetic-only claims.
3. Prediction: always show baseline lift, never a lone accuracy number.
4. SOAR: clearly simulated + human-gated.

## Build order *(de-risked)*
1. **Phase 0** — data foundation (unblocks everyone). ← *do first*
2. **E1.1 + E1.2** — real anomaly baseline + metrics (turns "real data" into a number).
3. **E2.1 + E2.2** — lookups + ~196 sequences (fast, scriptable).
4. **E2.4** — predictor + baselines (centerpiece; guard circularity).
5. **E1.3** — LANL lateral-movement vs red-team.
6. **S2–S4** — correlation + mapping + graph.
7. **E2.3, E2.5** — embeddings + attribution.
8. **S5, S6** — SOAR + dashboard; pre-cache; rehearse fallback.
9. Polish + India scenarios + deck.

---
*Canonical build spec. Reconcile Tab-2 and `src/demo_ps7_pipeline.py` (currently a scripted mock) to this document. Numbers measured from `data/raw/` on 2026-07-10.*
