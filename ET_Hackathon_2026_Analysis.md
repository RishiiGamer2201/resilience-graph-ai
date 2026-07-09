# ET AI Hackathon 2026 — Problem Statement Analysis & Strategy

**Purpose:** A complete, team-facing breakdown of all 8 problem statements (PS), scored against the official judging criteria *and* against what our 4-person all-AI/ML/DL/DS team can realistically execute and win with in a multi-week window.

For **each PS** you'll find: context → challenge → build options → **solution type (HW/SW)** → **tech stack / hardware components** → **datasets (if training needed)** → **architecture diagram** → team-fit & win-score.

> **Decision required:** Each team picks **one** PS. This doc is the shared input for that decision.

---

## 1. How the contest is actually scored

Every PS uses the **identical** rubric:

| Criterion | Weight | What it rewards |
|---|---|---|
| **Innovation** | 25% | A novel angle, not "another RAG chatbot." |
| **Business Impact** | 25% | Tangible, large-scale, board/policy-grade value. |
| **Technical Excellence** | 20% | A demo that genuinely *works* on real data, measurable vs a baseline. |
| **Scalability** | 15% | Credible path prototype → national/multi-site deployment. |
| **User Experience** | 15% | A polished, instantly-understandable "wow" demo. |

**Innovation + Business Impact = 50%.** That's the lever. A flawless but unoriginal/low-stakes build caps mid-table.

### Strategic reality of this hackathon
- Most teams ship **agentic-RAG / LLM-wrapper** demos (lowest barrier). Judges see many near-identical ones.
- Winning is **relative**. Two separators: (1) a **technical moat the field can't replicate** — real model work on real data; (2) a **demo that makes a judge feel the stakes in 30 seconds**.
- So pick a PS where **hard, verifiable ML is the core**, the **stakes are national-scale**, and we can still ship a clean UI.
- **Avoid crowded approaches** ("AQI dashboard", "RAG over docs") — strong teams pick them, so the bar to *win* is higher.

---

## 2. Our team (4 × AI / ML / DL / DS)

All four are AI/ML/DL/DS practitioners. There is **no dedicated hardware, GIS, or frontend engineer**. We split by ML sub-specialty, not by job title:

| Role | Owns |
|---|---|
| **M1 — Vision / Imagery models** | Object detection, segmentation, image classification (satellite, CCTV, documents, currency). |
| **M2 — Time-series / Forecasting / Anomaly** | LSTM/Transformer forecasting, anomaly detection, simulation/scenario modelling, degradation models. |
| **M3 — NLP / LLM / RAG / Agents / KG** | LangChain/LangGraph agents, RAG, knowledge graphs, document/text intelligence. |
| **M4 — Data Engineering + MLOps + Demo** | Data acquisition/ETL, APIs, deployment, **dashboard/UI**, demo video, deck. |

**Implications of an all-ML team (important):**
- ✅ **Strength:** any PS whose *win* comes from **models** (detection, forecasting, anomaly, classification, GNN, RAG) suits us — that's most of them.
- ⚠️ **Gap 1 — UX (15%):** no frontend specialist. **Mitigate** with **Streamlit / Gradio / Plotly Dash / Kepler.gl** (all Python — we already know them). Don't attempt bespoke React unless M4 is comfortable.
- ⚠️ **Gap 2 — Hardware:** we cannot build/integrate real sensors, cameras, or edge devices. **Any PS that envisions hardware must be done software-only** for the prototype (simulate sensor streams / use public datasets). This is fine for a hackathon but we must *frame it honestly* and not pretend we have live hardware.
- ⚠️ **Gap 3 — Domain depth:** cybersecurity (PS7) and proprietary industrial corpora (PS4/PS8) need domain knowledge/data we don't have.

### Shared toolchain (reused across PSes)
`Python` · `PyTorch` · `Ultralytics YOLO` (detection/OBB) · `scikit-learn`/`XGBoost` · `LangChain`/`LangGraph` or `CrewAI` (agents) · `Claude API` (LLM) · `FAISS`/`Chroma`/`Qdrant` (vector DB) · `Neo4j`/`NetworkX`/`PyTorch-Geometric` (graphs/KG) · `GeoPandas`/`rasterio`/`xarray`/`Folium`/`Kepler.gl` (geospatial) · `FastAPI` (backend) · `Streamlit`/`Gradio`/`Plotly Dash` (UI) · `Docker`.

> **Legend — Solution Type:** `SW-only` = pure software. `HW+SW (prod)` = full product envisions hardware, but the **hackathon prototype is software-only** (simulated/public data). `HW-only` = inherently hardware (none of these are).

---

## 3. The eight problem statements

Scoring key (1–5) per criterion. **Weighted Win-Score** uses official weights (Innov 0.25, Biz 0.25, Tech 0.20, Scale 0.15, UX 0.15). Max 5.00.

---

### PS1 — AI-Powered Industrial Safety Intelligence for Zero-Harm Operations
**Theme:** Industrial Intelligence / Worker Safety / Geospatial Safety Analytics

**Context.** 6,500+ fatal Indian workplace accidents in FY2023. Vizag Steel gas explosion (Jan 2025, 8 dead) had working sensors but *no layer connecting warnings to decisions in time*. FICCI 2024: 60%+ of large facilities rely on **manual handoffs** between safety tools. Gap = fusion + action, not technology.

**Challenge.** Fuse IoT/SCADA + permit-to-work + CCTV + shift records into a predictive layer that detects **compound risk** (e.g., maintenance + gas accumulation) no single sensor flags, and triggers preemptive intervention.

**Build options.** Compound Risk Detection Engine · Geospatial Safety Heatmap · Incident Pattern Intelligence (RAG over OISD/Factory Act) · Digital Permit Intelligence Agent · Emergency Response Orchestrator · Quality & Compliance Audit Agent.

**Solution type:** `HW+SW (prod)` — real product needs sensors/cameras; **prototype = SW-only** (simulate sensor + SCADA streams).

**If hardware (production vision):** industrial gas detectors (catalytic-bead / IR / electrochemical), IP CCTV cameras, edge inference (NVIDIA Jetson), worker-location tags (UWB/BLE/RFID), SCADA integration via OPC-UA / Modbus.

**Tech stack (prototype):** multi-agent (LangGraph/CrewAI) · time-series store (`InfluxDB`/`TimescaleDB`) · CCTV CV (`YOLO` PPE/zone-breach) · anomaly (`scikit-learn`/autoencoder) · KG (`Neo4j`: equipment–permit–risk) · RAG (`Chroma` + Claude over OISD/incident docs) · UI (`Streamlit` + `Folium`/`Kepler.gl` heatmap).

**Datasets (training needed):**
- PPE / safety CV: **SH17**, **Pictor-PPE**, **CHV (colour helmet-vest)**, Roboflow construction-safety sets.
- Fire/smoke: **D-Fire**.
- Gas/SCADA: *no good public source* → **simulate** physically-grounded streams.
- Text corpus: **OSHA incident reports**, **DGFASLI** data, **OISD** standards (PDFs) for RAG.

**Architecture**
```
LAYER 1 — SOURCES:   gas/IoT sensors* · SCADA* · permit-to-work logs · CCTV feeds · shift records
        │
        ▼
LAYER 2 — AI MODELS: CCTV computer vision (PPE / zone-breach) · time-series anomaly · RAG (OISD/incident corpus)
        │
        ▼
LAYER 3 — FUSION:    Compound-Risk Engine (multi-agent correlation) + KG (equipment–permit–risk) + lead-time predictor
        │
        ▼
LAYER 4 — OUTPUT:    geospatial safety heatmap · pre-emptive alerts · auto incident report · compliance flags
(* simulated/synthetic in hackathon prototype)
```

**Team fit & win.** CV + RAG + KG suit us; **but the defining feature (IoT/SCADA compound risk) is data-starved → must simulate, which can read as synthetic.** Strong emotional impact.
**Scores:** Innov 4 · Biz 5 · Tech 3 · Scale 4 · UX 4 → **Win-Score 4.05** · Data: Low · Competition: Med · Risk: High

---

### PS2 — AI-Driven Energy Supply Chain Resilience for Import-Dependent Economies ⭐
**Theme:** Supply Chain Intelligence / Energy Security / Geopolitical Risk

**Context.** India imports ~88% of crude; 40–45% transits the **Strait of Hormuz**. 2025 US–Iran standoff → Brent +8% in a session; early-2026 Iran sanctions + Red Sea Houthi attacks keep it live. SPR covers **~9.5 days**. McKinsey: no-automation economies took **47 days longer** to stabilize.

**Challenge.** Continuously monitor geopolitical + logistics risk, model disruption scenarios + downstream economic impact, and generate **executable procurement-rerouting** recommendations.

**Build options.** Geopolitical Risk Intelligence Agent · Disruption Scenario Modeller · Adaptive Procurement Orchestrator · Strategic Reserve Optimisation Agent · Supply Chain Digital Twin.

**Solution type:** `SW-only` — entirely software/data (satellite + AIS + news). **No hardware.**

**Tech stack:** satellite ingest (`Sentinel Hub` / `Google Earth Engine` / `sentinelsat`) · vessel detection (`Ultralytics YOLO-OBB`) + type classifier · AIS (`AISStream` / `Global Fishing Watch` API) · dark-vessel/anomaly logic · KG (`Neo4j`: supplier→route→risk→refinery) · scenario sim (`Python` / `SimPy` / system-dynamics) · news/sanctions RAG (`LangChain` + `Chroma` + Claude) · agents (`LangGraph`) · maps (`Kepler.gl`/`deck.gl` + `Streamlit`).

**Datasets (training needed):**
- Vessel detection (optical/SAR): **Airbus Ship Detection (Kaggle)**, **HRSC2016**, **ShipRSImageNet**, **DOTA** (ship class), **xView**; SAR: **FUSAR-Ship**, **SAR-Ship-Dataset**. (Fine-tune on **Sentinel-2** tiles.)
- AIS: **Global Fishing Watch** (open), **Marine Cadastre AIS** (open historical), **AISStream.io** (free realtime).
- Crude/refinery/prices: **EIA open data**, **PPAC (India)**, **OPEC MOMR**, Brent series.
- Geopolitical signal: **GDELT**, news APIs.

**Architecture**
```
LAYER 1 — SOURCES:   Sentinel-2 imagery · AIS vessel feeds · sanctions registries · commodity prices · news/GDELT
        │
        ▼
LAYER 2 — AI MODELS: vessel detection (OBB) + type classifier · dark-vessel/anomaly detector · LLM news/sanctions extraction
        │
        ▼
LAYER 3 — INTELLIGENCE: KG (supplier→route→risk→refinery) · disruption-scenario simulator · procurement-rerouting agent
        │
        ▼
LAYER 4 — OUTPUT:    live corridor risk map · scenario cascade (refinery/price/GDP) · ranked rerouting recommendations
```

**Team fit & win.** ✅✅ **Best fit + best moat:** the win comes from a real **detection model** on satellite + AIS — verifiable, rare, hard to fake. SW-only (no hardware gap). Cinematic demo. **Lowest competition** of the top tier. One risk: keep economic-cascade assumptions explicit.
**Scores:** Innov 5 · Biz 5 · Tech 4.5 · Scale 4 · UX 5 → **Win-Score 4.75** 🥇 · Data: Good · Competition: **Low** · Risk: Med

---

### PS3 — AI for Industrial EV Supply Chain & Asset Intelligence: Accelerating Net Zero
**Theme:** Sustainability / EV Manufacturing / Asset Performance Management / Supply Chain

**Context.** 2M+ EVs in FY2025 but <7% of sales, <2.5% industrial/commercial. Barriers now operational: fleet operators lack asset-intelligence for battery lifecycle/charging/maintenance; makers face battery-material + cell-to-pack quality + multi-tier supplier risk. Target 30% commercial-EV by 2030.

**Challenge.** (1) Run EV fleets with industrial rigour (procurement, predictive APM, maintenance); (2) help makers manage quality-critical supply chains.

**Build options.** EV APM Agent (battery SoH/RUL) · Fleet Electrification Readiness · EV Supply Chain Risk & Traceability · Manufacturing Quality Intelligence (QMS) · Net Zero Carbon Tracker · Maintenance Ops Optimiser.

**Solution type:** `HW+SW (prod)` — needs BMS/telematics; **prototype = SW-only** (public battery datasets).

**If hardware (production):** BMS, CAN-bus loggers, telematics units, charger energy meters, edge gateways.

**Tech stack:** degradation forecasting (`PyTorch` LSTM/Transformer/GRU) · `scikit-learn` SoH regression · supply-chain graph (`Neo4j`) · route/charging optimization (`OR-Tools`/`OSMnx`) · carbon model (Python) · UI (`Streamlit`).

**Datasets (training needed):**
- Battery: **NASA PCoE Battery**, **Oxford Battery Degradation**, **Severson/Stanford-Toyota (124-cell)**, **CALCE (Maryland)**.
- Fleet ops: **NREL Fleet DNA** (limited); charging/QMS → **synthetic**.

**Architecture**
```
LAYER 1 — SOURCES:   BMS/telematics* · charging logs* · battery cycle datasets · supplier/material data · fleet routes
        │
        ▼
LAYER 2 — AI MODELS: battery SoH/RUL forecaster (LSTM/Transformer) · quality-drift detector · route/charging optimizer
        │
        ▼
LAYER 3 — INTELLIGENCE: APM engine · multi-tier supply-chain risk graph · electrification-readiness scorer · carbon model
        │
        ▼
LAYER 4 — OUTPUT:    fleet health dashboard · procurement/transition recommendations · Scope-1/2 carbon tracker
(* simulated in prototype; battery models trained on public datasets)
```

**Team fit & win.** Battery modelling is ML-friendly but **well-trodden academically → limited Innovation**; fleet/QMS data mostly proprietary. Risk of looking like a battery-RUL notebook + dashboard.
**Scores:** Innov 3 · Biz 4 · Tech 3 · Scale 4 · UX 3 → **Win-Score 3.40** · Data: Med · Competition: Med · Risk: Med

---

### PS4 — AI Intelligence Platform for Data Centre EPC Project Delivery
**Theme:** Industrial Intelligence / Infrastructure Construction / Quality Management

**Context.** India DC capacity ~900 MW (2024) → 2,700+ MW (2027), $15B+ capex. A hyperscale build = 15k–40k line items, 200 contractors, thousands of commissioning tests. Turner & Townsend 2024: 67% of APAC DC EPC projects overran >10%, rooted in **information fragmentation**.

**Challenge.** Unify project docs/specs/schedules/procurement/quality into a living intelligence layer for proactive schedule management, automated compliance/quality checks, commissioning support.

**Build options.** Spec & Quality Compliance Agent · Predictive Schedule Risk Engine · Supply Chain Visibility Agent · Commissioning QA Copilot · Project Knowledge & RFI Intelligence (RAG).

**Solution type:** `SW-only`.

**Tech stack:** OCR (`PaddleOCR`/`Tesseract`) · doc parsing (`unstructured.io`, `LayoutLMv3`/`Donut`) · drawing CV (`YOLO`) · RAG (`LlamaIndex` + vector DB + Claude) · schedule risk (Python Monte-Carlo / CPM) · project KG (`Neo4j`) · UI (`Streamlit`).

**Datasets (training needed):**
- Standards text: **TIA-942 / BICSI / Uptime** (public summaries).
- Layout/drawing CV: **PubLayNet**, **FUNSD**, **CubiCasa5K** (floor plans) as proxies.
- EPC project docs/schedules: **proprietary → mostly synthetic** for the demo.

**Architecture**
```
LAYER 1 — SOURCES:   specs/standards (TIA-942/BICSI) · submittals/drawings · schedules · procurement status · RFIs
        │
        ▼
LAYER 2 — AI MODELS: OCR + document parsing · drawing/submittal CV · schedule-risk predictor · embeddings/RAG
        │
        ▼
LAYER 3 — INTELLIGENCE: spec-compliance agent · project KG · commissioning copilot · RFI retrieval
        │
        ▼
LAYER 4 — OUTPUT:    non-conformance flags · schedule-risk alerts · cited Q&A · commissioning test packages
```

**Team fit & win.** Core is **RAG over technical docs = the most crowded hackathon approach**, and authentic EPC corpora are **proprietary**. Niche domain → lower felt impact.
**Scores:** Innov 3 · Biz 4 · Tech 3 · Scale 3 · UX 3 → **Win-Score 3.25** · Data: Low · Competition: High · Risk: Med

---

### PS5 — AI-Powered Urban Air Quality Intelligence for Smart City Intervention ⭐
**Theme:** Smart Cities / Environmental Intelligence / Geospatial Analytics / Public Health

**Context.** National crisis (Delhi AQI ~218; Mumbai/Kolkata/Bengaluru/Chennai deteriorating). Lancet: **1.67M premature deaths/yr**. 900+ CAAQMS stations, but 2024 CAG audit: only **31%** of cities had actionable multi-agency response linked to readings. Data exists; the act-on-it layer doesn't.

**Challenge.** Fuse stations + satellite + mobility + meteorology + land-use → **proactive intervention**: source attribution, hyperlocal forecasting, enforcement prioritization.

**Build options.** Geospatial Source Attribution Engine · Hyperlocal AQI Forecasting (24–72h, 1km) · Enforcement Intelligence Agent · Multi-City Dashboard · Citizen Health Advisory (multi-language).

**Solution type:** `SW-only` (all data from existing APIs/satellites). *Optional* low-cost sensor add-on, **not required**.

**Tech stack:** remote sensing (`Google Earth Engine` / `Copernicus`: Sentinel-5P TROPOMI; `FIRMS` fire) · `xarray`/`rasterio` · forecasting (`PyTorch` LSTM / Temporal Fusion Transformer / spatiotemporal GNN, `XGBoost` baseline) · dispersion (`HYSPLIT` / Gaussian plume) · multilingual advisory (Claude) · maps/UI (`Kepler.gl` + `Streamlit`).

**Datasets (training needed):**
- Stations: **CPCB CAAQMS**, **OpenAQ** (India).
- Satellite: **Sentinel-5P TROPOMI** (NO₂/SO₂/CO/aerosol), **MODIS MAIAC AOD (MCD19A2)**, **VIIRS/MODIS active fire (FIRMS)**.
- Meteorology: **ERA5**. Land use: **ESA WorldCover**, **Bhuvan LULC**.
- Emission inventory (for attribution ground truth): **SAFAR**, **TERI**, **EDGAR**.

**Architecture**
```
LAYER 1 — SOURCES:   CAAQMS stations · Sentinel-5P (NO2/aerosol) · MODIS/VIIRS (fire/AOD) · ERA5 weather · land use · traffic
        │
        ▼
LAYER 2 — AI MODELS: source-attribution model · hyperlocal AQI forecaster (LSTM/TFT/GNN) · dispersion model · multilingual LLM
        │
        ▼
LAYER 3 — INTELLIGENCE: ward-level source apportionment · enforcement-prioritization agent · population-vulnerability mapping
        │
        ▼
LAYER 4 — OUTPUT:    1km AQI forecast map · ranked enforcement actions · citizen advisories (regional languages)
```

**Team fit & win.** ✅✅ Purest fit + **best free data of any PS**; the win is **forecasting + attribution models** (our strength). ⚠️ **Crowded topic** — to win, beat a **persistence baseline** on forecast and show **measurable** source attribution, not "another dashboard."
**Scores:** Innov 4 · Biz 5 · Tech 4 · Scale 4 · UX 4.5 → **Win-Score 4.33** 🥉 · Data: **Excellent** · Competition: **High** · Risk: Med

---

### PS6 — AI for Digital Public Safety: Defeating Counterfeiting, Fraud & Digital Arrest Scams ⭐
**Theme:** Smart Cities / Public Safety / Digital Trust / Geospatial Law Enforcement

**Context.** 1.14M cybercrime complaints in 2023 (+60% YoY). "Digital arrest" scams defrauded citizens of **₹1,776 crore in 9 months of 2024**. Industrialised cross-border ops (spoofed numbers, AI voices, fake portals). Plus record **FICN** (fake ₹500 notes). LE lacks pre-victimisation intelligence + point-of-contact detection.

**Challenge.** Equip LE/banks/citizens with proactive tools to detect/disrupt fraud networks, counterfeit circulation, and organised scams — reactive investigation → predictive neutralisation.

**Build options.** Digital Arrest Scam Detection & Alerting · Counterfeit Currency CV · Fraud Network Graph Intelligence · Geospatial Crime Pattern Intelligence · Citizen Fraud Shield (WhatsApp/IVR/app).

**Solution type:** `SW-only` (mobile/web CV, NLP, speech, graph). *Production* counterfeit may use UV/POS hardware; **prototype uses phone camera → SW-only**.

**Tech stack:** counterfeit CV (`PyTorch`/`YOLO`/CNN) · scam NLP (`transformers` + Claude) · speech anti-spoof (`Whisper` + ASVspoof models) · deepfake CV · fraud GNN (`PyTorch-Geometric`/`NetworkX`) · channels (`WhatsApp Business API` / `Twilio` IVR) · UI (`Streamlit`/`Gradio`).

**Datasets (training needed):**
- Counterfeit currency: **Kaggle Indian-currency / fake-note sets**, Roboflow currency *(scarce/sensitive)*.
- Scam text: **synthetic** + phishing/spam corpora.
- Voice spoof: **ASVspoof 2019/2021**. Deepfake: **FaceForensics++**, **DFDC**, **Celeb-DF**.
- Fraud graph: **IEEE-CIS Fraud**, **Elliptic (crypto)**, **PaySim**, **ULB Credit-Card Fraud**.

**Architecture**
```
LAYER 1 — SOURCES:   call/scam transcripts · voice audio · currency images · txn/device/account graphs · complaint geo-data
        │
        ▼
LAYER 2 — AI MODELS: scam-NLP classifier · voice-spoof/deepfake detector · counterfeit-note CV · fraud GNN
        │
        ▼
LAYER 3 — INTELLIGENCE: real-time scam-session risk scorer · fraud-network mapper · geospatial crime clustering
        │
        ▼
LAYER 4 — OUTPUT:    Citizen Fraud-Shield verdicts (WhatsApp/IVR) · counterfeit scan result · LE intelligence package + hotspot map
```

**Team fit & win.** ✅ Very ML-rich (CV + NLP + speech + GNN = 4 model families we own) and **demo-spectacular + on-trend**. ⚠️ **Scope risk** (3 loosely-coupled problems) → go deep on **one** (Digital-Arrest-Scam detection + Citizen Fraud Shield). ⚠️ Channel integration (WhatsApp/IVR) is the non-ML part for M4.
**Scores:** Innov 4 · Biz 5 · Tech 4 · Scale 4 · UX 5 → **Win-Score 4.40** 🥈 · Data: Med · Competition: Med-High · Risk: Med (scope)

---

### PS7 — AI-Driven Cyber Resilience for Critical National Infrastructure
**Theme:** Cybersecurity / Industrial Intelligence / National Security

**Context.** CERT-In handled 1.59M+ incidents in 2023. AIIMS Delhi ransomware (2022); CBSE breaches (2024 + early-2026). 70%+ of govt entities run end-of-life IT. Real problem = **detection speed**; APTs run low-and-slow to evade signatures.

**Challenge.** Autonomously detect behavioural anomalies, correlate weak IT/OT signals, map attack progression to known frameworks, orchestrate containment — weeks → hours.

**Build options.** Behavioural Anomaly Detection (UEBA) · APT Attribution & Prediction (MITRE ATT&CK) · Autonomous IR Orchestrator (SOAR) · Vulnerability Prioritisation · Cyber Resilience Digital Twin.

**Solution type:** `SW-only`.

**Tech stack:** anomaly detection (`PyTorch` autoencoders / `IsolationForest` / UEBA) · attack-path GNN (`PyTorch-Geometric`) · RAG over CVE/CERT-In/ATT&CK (`LangChain` + vector DB + Claude) · KG (`Neo4j`: ATT&CK TTPs) · log processing (`pandas`/ELK) · SOAR (simulated playbooks) · UI (`Streamlit`).

**Datasets (training needed):**
- Network/IDS: **CICIDS-2017**, **CSE-CIC-IDS2018**, **UNSW-NB15**, **NSL-KDD**.
- Host/lateral movement: **LANL cyber (auth + redteam)**.
- Threat KB: **MITRE ATT&CK (STIX)**, **NVD CVE feed**.

**Architecture**
```
LAYER 1 — SOURCES:   network flows/logs (CICIDS/UNSW) · endpoint telemetry · CVE feeds · CERT-In advisories · MITRE ATT&CK
        │
        ▼
LAYER 2 — AI MODELS: UEBA anomaly detector (autoencoder/IsolationForest) · attack-path GNN · threat-intel RAG
        │
        ▼
LAYER 3 — INTELLIGENCE: ATT&CK technique mapping (KG) · APT next-move prediction · vuln prioritization · SOAR playbooks
        │
        ▼
LAYER 4 — OUTPUT:    behavioural alerts (low FP) · attack-path graph · ranked remediation queue · auto-containment actions
```

**Team fit & win.** Anomaly/GNN are ML-friendly and benchmark data exists, **but cybersecurity domain depth (ATT&CK, SOC ops, OT) is a real ramp** in limited time; SOC dashboards read "dry" to non-expert judges.
**Scores:** Innov 4 · Biz 4.5 · Tech 3.5 · Scale 4 · UX 3 → **Win-Score 3.88** · Data: Good · Competition: Med · Risk: High (domain)

---

### PS8 — AI for Industrial Knowledge Intelligence: Unified Asset & Operations Brain
**Theme:** Industrial Intelligence / Document Management / Knowledge Engineering / Quality

**Context.** McKinsey 2024: asset-intensive staff spend **35%** of hours searching/recreating docs. Plants run 7–12 disconnected doc systems; fragmentation drives 18–22% of unplanned downtime. **Knowledge cliff** — ~25% of senior engineers retire within a decade.

**Challenge.** Ingest heterogeneous docs (drawings, maintenance, SOPs, inspections, project files), make collective intelligence queryable + actionable + continuously updated at point of need.

**Build options.** Universal Doc Ingestion + KG Agent · Expert Knowledge Copilot (RAG) · Maintenance Intelligence & RCA · Quality & Regulatory Compliance · Lessons-Learned Failure Intelligence.

**Solution type:** `SW-only`.

**Tech stack:** OCR (`PaddleOCR`) · layout parsing (`LayoutLMv3`/`Donut`, `unstructured.io`) · P&ID symbol CV (`YOLO`) · NER/relation extraction (`spaCy`/transformers) · KG + ontology (`Neo4j`, DEXPI) · RAG (`LlamaIndex` + `Qdrant` + Claude) · UI (`Streamlit`, mobile-friendly).

**Datasets (training needed):**
- P&ID/drawings: **Digitize-PID**, **Dataset-P&ID** (synthetic P&IDs), **DEXPI** reference.
- Docs/OCR/layout: **FUNSD**, **DocVQA**, **PubLayNet**, **RVL-CDIP**.
- Real industrial manuals: **proprietary → public OEM PDFs + synthetic**.

**Architecture**
```
LAYER 1 — SOURCES:   PDFs/manuals · P&IDs/drawings · scanned forms · spreadsheets · work orders · regulatory texts
        │
        ▼
LAYER 2 — AI MODELS: OCR + layout parsing · P&ID symbol CV · entity/relation extraction (NER) · embeddings
        │
        ▼
LAYER 3 — INTELLIGENCE: unified Knowledge Graph + ontology · RAG copilot (cited) · RCA/maintenance reasoner · compliance mapper
        │
        ▼
LAYER 4 — OUTPUT:    conversational answers w/ citations · RCA + maintenance recommendations · compliance-gap reports
```

**Team fit & win.** P&ID CV is a genuine ML differentiator, **but core is KG+RAG over docs = #1 hackathon cliché**, eval wants **real industrial docs** (proprietary), and enterprise-search demos have a low "wow" ceiling.
**Scores:** Innov 3 · Biz 4 · Tech 3 · Scale 4 · UX 3 → **Win-Score 3.40** · Data: Low · Competition: High · Risk: Med

---

## 4. Master comparison matrix

| # | Problem Statement | Type | Innov | Biz | Tech | Scale | UX | **Win-Score** | Team Fit | Data | Competition | Risk |
|---|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| **2** | **Energy Supply Chain Resilience** | SW | 5 | 5 | 4.5 | 4 | 5 | **4.75** 🥇 | ★★★★★ | Good | **Low** | Med |
| **6** | **Digital Public Safety (fraud/scams)** | SW | 4 | 5 | 4 | 4 | 5 | **4.40** 🥈 | ★★★★ | Med | Med-High | Med |
| **5** | **Urban Air Quality Intelligence** | SW | 4 | 5 | 4 | 4 | 4.5 | **4.33** 🥉 | ★★★★★ | **Excellent** | High | Med |
| 1 | Industrial Safety (Zero-Harm) | HW+SW | 4 | 5 | 3 | 4 | 4 | 4.05 | ★★★ | Low | Med | High |
| 7 | Cyber Resilience (CNI) | SW | 4 | 4.5 | 3.5 | 4 | 3 | 3.88 | ★★★ | Good | Med | High |
| 3 | Industrial EV / Asset Intelligence | HW+SW | 3 | 4 | 3 | 4 | 3 | 3.40 | ★★★ | Med | Med | Med |
| 8 | Industrial Knowledge Intelligence | SW | 3 | 4 | 3 | 4 | 3 | 3.40 | ★★★ | Low | High | Med |
| 4 | Data Centre EPC Delivery | SW | 3 | 4 | 3 | 3 | 3 | 3.25 | ★★ | Low | High | Med |

> **Type:** SW = software-only prototype · HW+SW = production needs hardware, prototype simulated.
> **Win-Score** = official weighted criteria. The right-hand columns are execution realities for an all-ML team that modulate which high-score PS we can actually *win*.

---

## 5. Recommendation

### 🥇 Primary: PS2 — Energy Supply Chain Resilience
Tops the weighted score **and** execution realities:
- **Highest Innovation + Business Impact** (the 50% that decides winners); national-energy-security framing.
- **SW-only** → no hardware gap; **the win comes from a real detection model on satellite + AIS** — verifiable, rare, hard to fake (Technical Excellence + Innovation).
- **Cinematic demo:** "Hormuz closure" → live tanker map → cascade to fuel prices → auto-rerouting.
- **Lowest competition** of the top tier (the geospatial core is hard, so few attempt it well).
- **Data achievable** in a multi-week window.

**Scope discipline — build 3 deeply, not all 5:** (1) Maritime Risk Intelligence *(the moat)*, (2) Disruption Scenario Modeller *(explicit assumptions)*, (3) Adaptive Procurement Orchestrator; plus a news/sanctions RAG agent feeding 1 → 2.

### 🥈 / 🥉 Alternates
- **PS6 (Digital Public Safety)** — pick if we want the most **demo-spectacular, on-trend** build. ML-rich (CV+NLP+speech+GNN). **Go deep on one thread** (Digital-Arrest-Scam + Citizen Fraud Shield).
- **PS5 (Air Quality)** — **lowest-risk fit, best free data.** Pick for maximum certainty the demo works. **Caveat:** crowded — must win on measurable attribution + beating a persistence baseline.

### Decision guidance
| If the team prioritises… | Choose |
|---|---|
| Highest ceiling + unique moat + low competition (best shot to win) | **PS2** |
| Most demo-spectacular, citizen-facing, on-trend | **PS6** |
| Lowest execution risk, best data, pure model-driven comfort | **PS5** |

---

## 6. Next steps (once PS is locked)
1. **Lock the PS** as a team.
2. One-page concept note + detailed architecture diagram for the chosen PS.
3. **Data-acquisition checklist** — confirm every dataset is obtainable before building.
4. Week-by-week plan with the 4-person split (M1 vision · M2 forecasting/anomaly · M3 NLP/LLM/KG · M4 data/MLOps/UI).
5. Define the **baseline we'll beat** for the eval-focus metric (this earns Technical Excellence).
6. Lock the **demo storyboard early** — UX + narrative are 30% of the score and decide ties. (Build it in Streamlit/Gradio given our team.)

---

*Team decision aid for ET AI Hackathon 2026. Scores are judgement-based estimates against the official rubric; revise as data access is confirmed.*
