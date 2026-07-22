# nextATT&CKs: Problem, Approach, and Every Feature

> **Living document, update every working session.** Last updated: 2026-07-22.
>
> A judge-facing brief: what PS-7 asks for, the specific problem we solve, how we
> solve it, and every feature with the failure it attacks. Companion to
> [PITCH_DECK.md](PITCH_DECK.md) and [EXPLAINER.md](EXPLAINER.md). Every number is
> real and traceable to `reports/metrics.json`, `reports/scaling_measurements.json`,
> or a labelled external citation.

---

## Part 1: The problem

### 1a. What PS-7 actually asks for

PS-7 is **"AI-Driven Cyber Resilience for Critical National Infrastructure."** The
operative word is *resilience*, not *detection*. Resilience means four capabilities
in sequence: **anticipate** an attack, **detect** it while it is still unfolding,
**understand** its spread, and **respond** fast enough to contain it. A tool that
only raises alarms is not resilience; resilience is the whole loop from a weak early
signal to a contained incident.

The context PS-7 sets is specifically Indian CNI:

| Fact | Number | Source |
|---|---|---|
| Incidents handled by CERT-In in 2023 | 1.59 million and above | CERT-In |
| Indian government entities on end-of-life IT | Over 70 percent | PS-7 brief |
| Global median attacker dwell time | About 10 days | Mandiant M-Trends 2024 |
| Real Indian precedents | AIIMS Delhi ransomware (2022), CBSE breaches (2024, 2026) | Public reporting |

The common thread in those precedents is the important part: they were **not** exotic
zero-days. They were quiet intrusions using **valid stolen credentials** and **lateral
movement**, where the attacker logs in legitimately, machine by machine, until they reach
something valuable.

### 1b. The specific problem we solve

Modern attackers on CNI deliberately look normal. They steal one password and
authenticate their way across the network. **Every single login they make is
individually valid and individually boring.** That produces three failures, which all
share one root cause.

| Failure | Why it happens |
|---|---|
| Low-and-slow evades signatures | Valid credentials match no known-bad rule. Antivirus, firewalls and threshold rules all look for something unauthorised, and nothing here is. |
| Alert fatigue | Every event is scored alone, so one intrusion becomes thousands of disconnected alerts. On our real campaign that is 1,243 alerts for 1 attack. Analysts triage rows, miss the pattern, burn out. |
| No blast-radius view | Even when one alert is investigated, nobody can see the path from a compromised workstation to the patient database, or answer the only question that matters mid-incident: which single machine do we unplug first? |

**The root cause and our thesis:** the data needed to catch these attacks already
exists, in the authentication logs organisations already collect and pay to store. The
missing piece is not more sensors, it is **the layer that connects those
individually-boring events into one story, in time.** That layer is what we built. It
is why the system needs **no new sensors, no endpoint agents, and no infrastructure
change**, a decisive advantage for the 70 percent of entities that cannot fund a
24 by 7 SOC.

---

## Part 2: How we solve it

### The core idea: behavioural intelligence, not signature intelligence

We never tell the model what an attack looks like (impossible, since attackers invent
new things). Instead we teach it what **normal** authentication behaviour looks like
for each account, and measure deviation. This is the only approach that catches an
attack nobody has catalogued yet. A nurse logs into the same three machines daily; an
attacker using her account touches twenty she has never touched, and that behavioural
gap is what we detect.

### The pipeline: seven stages, one live function call

Everything runs **live, per request**, inside one function `analyze_events()`. Submit
a log, a shipped scenario or your own CSV, and all seven stages execute on it.

```mermaid
flowchart LR
  A["Raw auth log<br/>scenario or CSV"] --> N["1 Normalize<br/>schema + aliases"]
  N --> S["2 Score<br/>0 to 100 anomaly"]
  S --> C["3 Correlate<br/>alerts to ONE incident"]
  C --> M["4 ATT&CK map<br/>verified technique IDs"]
  M --> G["5 Attack graph<br/>paths + blast radius"]
  G --> R["6 Gated SOAR<br/>human-approved actions"]
  M --> P["7 Predict + attribute<br/>next move, likely actor"]
  G --> OUT["One bundle to every screen"]
  R --> OUT
  P --> OUT
```

- **Stages 1 and 2 are Engine 1 (detection):** turn each raw login into 7 behavioural
  features, then score every event 0 to 100 with a benign-trained autoencoder.
- **Stages 3 to 6 are the shared spine (understanding and response):** group alerts
  into ONE incident, map each behaviour to a real MITRE ATT&CK technique, build the
  attack-path graph, and recommend human-gated containment.
- **Stage 7 is Engine 2 (looking forward and outward):** predict the next technique and
  rank the likely threat actor.

This maps directly onto PS-7's resilience loop: **anticipate** (Threat Radar and
prediction), **detect** (Engine 1), **understand** (correlation and graph),
**respond** (gated SOAR).

**Proven on real data (LANL red-team campaign):**

| Output | Value |
|---|---|
| Events analysed, alerts, incidents | 2,732, then 1,243, then 1 |
| Compromised accounts | 104 |
| Attack graph | 473 hosts, 484 movements, 4 attacker pivots |
| Concentration | C17693 alone carries 670 of 702 red-team events |
| Crown jewels reachable, total exposure | 16 reachable, 469 hosts |
| Isolate one host (C17693) | cuts 463 hosts of blast radius |
| Detection | ROC-AUC 0.992 against 702 real labelled attack events, zero attack labels in training. At the 1 percent false-positive operating point it catches 616 of 702 |

---

## Part 3: Every feature, and how it attacks the problem

### 1. Analyze any log (scenario pick or CSV upload), live per request
**What it is:** Choose a shipped scenario or upload your own authentication CSV; the
entire application re-renders on that data. Robust to real logs: it resolves column
aliases (`username` or `account`, `src` or `source`, `dst`) and accepts timestamps as
epoch integers or ISO-8601 strings.
**How it solves the problem:** This is the proof that the product is a real analysis
engine, not a demo reel. A judge can drop in their own log and watch all seven stages
run. It directly answers the deployability requirement, an operator points it at logs
they already have, with no integration project needed.

### 2. Campaign view, all 104 accounts as one incident
**What it is:** Instead of collapsing to a single victim, it shows the entire campaign:
all 104 compromised accounts in one correlated incident.
**How it solves the problem:** This is the direct antidote to alert fatigue. A real
intrusion touches many accounts; a per-victim view fragments the story. The campaign
view is what turns 1,243 scattered alerts into the one thing an analyst can act on.

### 3. Per-account drill-down
**What it is:** Open any single account and get its own scoped incident, graph and
report, recomputed live for that account.
**How it solves the problem:** Resilience needs both altitudes. The campaign view
answers "are we under attack"; the drill-down answers "what exactly did this account
do." It lets a responder investigate one suspicious identity without losing the
campaign context.

### 4. Attack-path graph
**What it is:** Every alert becomes an edge in a directed host-to-host movement graph.
Click any machine to see every authentication involving it. It computes blast radius
across all attacker pivots, not just one.
**How it solves the problem:** This is the fix for the missing blast-radius view, the
feature that answers "which machine do we unplug first." It surfaces the killer
operational fact: isolate C17693, sever 463 hosts. It also fixed a real bug where
assuming a single entry point under-reported exposure and wrongly cleared four crown
jewels; reachability is now unioned over every pivot.

### 5. Live event scoring
**What it is:** Score a single authentication event on demand, on stage, using the real
trained autoencoder, returning a 0 to 100 anomaly score with fixed calibration
anchors, so a score of 50 is exactly the 1 percent false-positive operating point.
**How it solves the problem:** It makes the detection engine tangible and auditable in
real time. A skeptic can hand it one event and watch the model react, proving the
scores are computed, not canned.

### 6. Next-technique prediction
**What it is:** A first-order Markov model ranks the attacker's likely next MITRE
technique with a genuine transition probability (for example `T1566.001 to T1566.002 at
52.5 percent`), learned from 205 real attack sequences.
**How it solves the problem:** This is the anticipate half of resilience, getting ahead
of the attacker instead of only reacting. It is deliberately honest: it beats a
purpose-built kill-chain baseline 5.4 times (proving it learns real transitions, not
just an ordering), and we shipped Markov over an LSTM that lost at this data scale.

### 7. Actor attribution
**What it is:** Ranks which of 172 known MITRE threat groups the observed behaviour
resembles, via transparent weighted retrieval, coverage (0.55) plus Jaccard (0.20) plus
semantic similarity (0.25), with a printed justification for every result.
**How it solves the problem:** It replaces hours of manual threat-intelligence reading
with a ranked, auditable answer. Crucially it is transparent retrieval, not a black-box
classifier, so an analyst can audit the reasoning, which is what makes it trustworthy in
a security decision.

### 8. Threat Radar
**What it is:** Pulls free, legitimate external CTI feeds, maps each item to real ATT&CK
identifiers, ranks India-relevant items first (CERT-In, NCIIPC, UPI, Aadhaar,
India-targeting actors), and cross-references them against your current incident.
**How it solves the problem:** This is the outward-facing anticipate capability, and it
fits the Indian focus precisely. It connects "what is happening in the wild" to "where
you are exposed." It is also a demonstration of honesty: no social-media scraping
(rejected for terms-of-service and mis-attribution risk), and "no matches" is shown
plainly rather than faked.

### 9. Audit-ready report
**What it is:** A printable and downloadable incident report suitable for compliance
records.
**How it solves the problem:** Resilience includes the aftermath; regulators and CERT-In
require documentation. This turns a live investigation into a defensible artifact, which
matters for exactly the regulated CNI operators (hospitals, exam boards, grid) the PS
targets.

### 10. Gated SOAR, simulated by design
**What it is:** Generates recommended containment seeded from real MITRE mitigations for
the observed techniques, gated by severity: anything touching a critical asset requires
human approval.
**How it solves the problem:** This is the respond stage. The human gate is the point,
resilience for CNI cannot mean an AI unplugging a hospital's servers autonomously. Every
action is labelled simulated because there is no live network to act on, and we state
that up front rather than implying autonomous execution.

### 11. India scenarios shipped (AIIMS and CBSE)
**What it is:** Two scenarios, hospital ransomware (AIIMS-style) and exam-board breach
(CBSE-style), as synthetic logs styled after the real reported incidents, labelled
synthetic in the interface.
**How it solves the problem:** They make the problem statement's own precedents runnable
end to end, letting a judge see the pipeline against the exact threat classes PS-7 names.

### 12. LIVE and SAMPLE provenance badge
**What it is:** A top-bar badge, always visible, reading LIVE ANALYSIS or SAMPLE DATA.
**How it solves the problem:** It is the honesty backbone of the whole product, a viewer
can always tell whether what they see was computed just now from their data or is the
shipped sample (which is itself a real analysis of a shipped log, via the same
pipeline). It is a correctness feature, not decoration, and it underpins the "nothing
fabricated on screen" rule.

### 13. Live Incident replay and streaming
**What it is:** Event-by-event replay of an incident, served over Server-Sent Events
(`/analyze/stream`), alongside live scoring and the report.
**How it solves the problem:** It reconstructs the attacker's timeline as a narrative a
human can follow, which is the concrete form of turning alerts into a story.

---

## Part 4: Technologies used

Everything below is actually in the repository. The deployed image deliberately
carries a **smaller** dependency set than the development environment, because the
heavy machine-learning libraries are needed only at build time.

### 4.1 Languages and runtimes

| Layer | Technology | Version | Why this one |
|---|---|---|---|
| Backend and ML | Python | 3.10 (pinned, `python:3.10-slim` base image) | Library compatibility across scikit-learn, torch and the ATT&CK STIX tooling |
| Frontend | JavaScript with JSX | ES2022 | No TypeScript build step to maintain under hackathon time pressure |
| Container | Docker, two-stage build | - | A Node stage builds the frontend, a slim Python stage serves everything |

### 4.2 Machine learning and data science

| Library | Used for | Runtime or build-time |
|---|---|---|
| scikit-learn (1.7.2 pinned) | IsolationForest (the previous detector, kept as the published comparison), StandardScaler, and every evaluation metric: PR-AUC, ROC-AUC, precision, recall, F1 | Runtime |
| NumPy | All numeric work, scoring, bootstrap significance testing | Runtime |
| pandas | Log loading, the 12-field schema, feature engineering, CSV and parquet handling | Runtime |
| PyArrow | Parquet input and output for processed datasets | Build-time |
| PyTorch | Training the shipped autoencoder, plus the LSTM and biLSTM comparison models and the model bake-off | Build-time only, exported to NumPy for the runtime |
| sentence-transformers (all-MiniLM-L6-v2) | 384-dimension embeddings of ATT&CK technique descriptions, used for semantic similarity in attribution | Build-time only, shipped as a precomputed pickle |
| networkx | The attack-path graph: reachability, blast radius, betweenness centrality, shortest path | Runtime |
| joblib | Serialising the trained detector and scaler | Runtime |
| Matplotlib | Precision-recall curves and the measured scaling chart | Build-time |

The version pin on scikit-learn is deliberate: it must match the version that
pickled `models/iforest_lanl.joblib`, or loading the shipped model fails.

### 4.3 Models we built

| Model | Type | Where it is used | Status |
|---|---|---|---|
| Autoencoder | Encoder-decoder neural network, 7-16-4-16-7, benign-trained, reconstruction error is the anomaly score | Engine 1, scores every authentication event 0 to 100 | **Shipped.** Trained with PyTorch offline, exported to NumPy weights so the runtime needs no deep-learning framework |
| IsolationForest | Unsupervised ensemble, 200 trees, 4,096 max samples, trained on 800,000 benign-only rows | Engine 1, previous detector | Replaced. Kept as the published comparison |
| Autoencoder (CIC-IDS2017) | Same recipe on network flows | Engine 1 second benchmark | Evaluated, documented |
| Interpolated Markov | Blends order-2, order-1 and unigram transitions, weights tuned on validation | Engine 2, next-technique prediction with a real probability | **Shipped** |
| First-order Markov chain | Technique-to-technique transition table with frequency backoff | Engine 2, previous predictor | Replaced, 36.5 percent against 38.1 percent |
| Second-order Markov | Conditions on the last two techniques, backs off to first order | Engine 2 candidate | Evaluated, lost |
| LSTM | Recurrent network over frozen MiniLM embeddings | Engine 2 candidate | Evaluated, lost, published as a negative result |
| Bidirectional LSTM | BiLSTM with masked mean-pooling over the observed prefix | Engine 2 candidate | Evaluated, lost |
| Attribution scorer | Transparent weighted retrieval, 0.55 coverage plus 0.20 Jaccard plus 0.25 semantic similarity | Engine 2, ranks 172 MITRE groups | Shipped, deliberately not a trained classifier |

### 4.4 Backend and API

| Technology | Used for |
|---|---|
| FastAPI | The whole programming interface: live analysis, model calls, cached reads, and serving the built frontend |
| Uvicorn | ASGI server, port 8000 |
| python-multipart | Multipart CSV upload on `/api/analyze/upload` |
| Server-Sent Events (native) | `/api/analyze/stream`, event-by-event incident replay |
| httpx | Endpoint testing |
| Python standard library `urllib` and `xml.etree` | All Threat Radar network and feed parsing, chosen specifically so the deployed image gains zero new dependencies |

### 4.5 Frontend

| Package | Used for |
|---|---|
| React 19 | The single page application, eight screens |
| Vite 8 | Build tool and development server with an API proxy |
| react-router-dom 7 | Client-side routing |
| recharts | Charts and score visualisations |
| react-force-graph-2d | The interactive attack-path graph |
| lucide-react | Icon set |
| oxlint | Linting |
| React Context (`AnalysisProvider`, `useScreenData`) | State flow, so a live analysis bundle overrides the cached sample across every screen |

### 4.6 Security data and standards

| Source | What we take from it |
|---|---|
| MITRE ATT&CK, Enterprise plus ICS plus Mobile, via STIX bundles | 918 techniques, 175 groups, official mitigations and descriptions |
| mitreattack-python and stix2 | Parsing those STIX bundles into our lookup table |
| LANL Cyber Security Events | 11.2 million authentication events with 702 labelled red-team events |
| CIC-IDS2017 | 2.3 million labelled network flows |
| UNSW-NB15 | Second benchmark, official train and test split |
| CISA KEV, CISA advisories, security RSS feeds | Threat Radar external intelligence, all free and no key required |
| CERT-In advisories | Four analyst-verified Indian attack sequences for the non-circular test |

### 4.7 Infrastructure, testing and tooling

| Technology | Used for |
|---|---|
| Docker, two-stage build | One deployable container holding the interface and the frontend |
| Render | Hosting, free tier, one URL, deployed from `render.yaml` |
| Git and GitHub | Version control, with runtime artifacts committed so the app runs from a fresh clone |
| pytest | 29 automated tests covering the pipeline, graph, scoping and intelligence mapping |
| TestSprite | Browser end-to-end testing across 15 user flows |
| Headless Chrome | Rendering diagrams and the submission PDF |
| python-docx | Generating the submission document |

### 4.8 What we deliberately did not use

| Not used | Why |
|---|---|
| PyTorch at runtime | Both neural components are exported to plain arrays: sentence embeddings ship as a pickle, and the detector's weights ship as a NumPy `.npz` that we run with matrix multiplies. The deployed image needs no deep-learning framework and no GPU, even though the shipped detector is a neural network |
| A GPU in production | Nothing in the request path requires one. The full pipeline runs on a laptop CPU |
| A graph database | networkx in memory is comfortable to about 50,000 events per analysis, which we measured. A graph database is the documented next step, not a present need |
| A large language model | Technique text is read verbatim from official MITRE files, so a fabricated technique identifier is structurally impossible |
| Third-party HTTP and feed libraries | The standard library covers it and keeps the deployed image dependency-free for this feature |
| Social media APIs and scrapers | Rejected on terms-of-service grounds and because person-level attribution from public posts risks naming the wrong people |

---

## The through-line for a judge

Every feature is one link in PS-7's resilience loop, and each attacks one of the three
failures.

| PS-7 resilience stage | Features | Failure it fixes |
|---|---|---|
| Anticipate | Threat Radar, Next-technique prediction | Gets ahead of low-and-slow attacks |
| Detect | Analyze any log, Live event scoring (Engine 1) | Catches valid-credential attacks signatures miss |
| Understand | Campaign view, Per-account drill-down, Attack-path graph, Live Incident, Actor attribution | Ends alert fatigue and the missing blast-radius view |
| Respond | Gated SOAR, Audit-ready report | Turns understanding into contained, documented action |
| Trust throughout | LIVE and SAMPLE badge, honesty rules | Makes it credible to a regulated operator |

**One-line summary:** the logs already know an attack is happening. nextATT&CKs
is the layer that listens, connects the weak signals into one story, and turns weeks of
undetected dwell into a contained incident in minutes, using only the data an operator
already has.
