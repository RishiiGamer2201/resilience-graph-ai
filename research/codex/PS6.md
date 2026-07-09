# PS6 Deep Research: AI for Digital Public Safety

Last updated: 2026-07-06

Problem statement: AI for Digital Public Safety: Defeating Counterfeiting, Fraud and Digital Arrest Scams

This note is written for a software-only hackathon build. It rules out dedicated hardware such as UV currency scanners, bank-grade note counting machines, telecom core integrations, or law-enforcement production systems. The prototype can still simulate those environments through uploaded images, text/audio samples, synthetic case data, graph datasets, and a dashboard.

## 1. One-line understanding

PS6 asks us to build an AI intelligence layer that helps citizens, banks, telecom providers, and law enforcement detect and disrupt fraud before the victim loses money or before a fraud network scales.

In simpler words: instead of waiting for someone to file a complaint after losing money, the system should identify the scam pattern during the suspicious call/message/payment flow, warn the victim, connect related incidents, and generate an investigation-ready intelligence package.

## 2. Why this problem matters

India's financial and communication stack has become extremely digital. UPI, mobile banking, Aadhaar-linked services, WhatsApp, video calls, and online KYC have made daily life easier, but they have also created a large attack surface for social-engineering fraud.

The official hackathon problem statement highlights:

- 1.14 million cybercrime complaints in India in 2023.
- A sharp rise in "digital arrest" scams.
- Reported losses of more than Rs 1,776 crore from digital arrest scams in the first nine months of 2024.
- Fake Indian Currency Notes, especially Rs 500 notes, remaining a persistent banking and law-enforcement concern.

The deeper issue is not only "detect one bad message." Organized scam operations use multiple layers:

- Fake identities and forged government documents.
- Spoofed phone numbers and WhatsApp video calls.
- Psychological coercion over hours or days.
- Mule bank accounts to receive money.
- SIM cards and devices rotated across campaigns.
- Cross-state or cross-border infrastructure.
- Victim targeting patterns by age, city, profession, or recent online activity.

That makes PS6 a multi-source intelligence problem: text, speech, image, transaction graph, geospatial pattern, and human-risk communication.

## 3. Basic concepts

### 3.1 Digital arrest scam

A digital arrest scam is a social-engineering fraud in which the attacker pretends to be from a government, police, customs, CBI, ED, TRAI, RBI, bank, or courier authority. The attacker falsely claims that the victim is under investigation and must remain on call or video call. The attacker then pressures the victim to transfer money to "safe accounts," disclose OTPs, install remote access apps, or share personal documents.

Common script pattern:

1. Hook: "Your SIM/Aadhaar/bank account/courier parcel is linked to a crime."
2. Authority escalation: call is "transferred" to fake police/CBI/ED officer.
3. Isolation: victim is told not to speak to family, lawyer, or local police.
4. Fear: threats of arrest, jail, asset seizure, public shame.
5. Fake legality: forged FIR, warrant, ID card, court order, or video call with someone in uniform.
6. Financial extraction: transfer to "verification" or "safe custody" account.
7. Laundering: funds move through mule accounts and wallets.

AI opportunity:

- Classify scam scripts in real time.
- Detect coercive language and impersonation markers.
- Identify forged document templates.
- Flag risky accounts/numbers/devices.
- Generate victim-specific guidance in plain language.

### 3.2 Counterfeit currency detection

Counterfeit currency detection means identifying whether a banknote is genuine or fake using visible and/or machine-readable features. In a hardware-free hackathon prototype, we should use phone-camera images only.

Important visible features on Indian notes include:

- Watermark region.
- Security thread.
- Microtext.
- Latent image.
- See-through register.
- Denomination numeral style.
- Serial number alignment.
- Color consistency.
- Printing sharpness and texture cues.

AI opportunity:

- Image classification: genuine vs suspicious.
- Object detection: locate security thread, watermark zone, serial number, denomination.
- Feature quality scoring: blurred, low light, crop issue, rotation issue.
- Explainable output: "serial number alignment suspicious," "security thread region not detected."

Hackathon caution:

Counterfeit detection from normal phone images is imperfect because real validation often depends on tactile, optical, UV, magnetic, or machine-readable features. We should frame the prototype as a field triage assistant, not a final legal authenticity tool.

### 3.3 Fraud network graph

A fraud network graph represents entities and relationships:

- Victims
- Phone numbers
- Bank accounts
- UPI IDs
- Devices
- IPs
- SIM cards
- Locations
- Transactions
- Complaints
- Scam scripts

Nodes are entities. Edges are relationships such as "called," "transferred money to," "used same device," "shared bank account," "filed complaint from same city," or "used similar script."

AI opportunity:

- Cluster related cases.
- Detect mule accounts.
- Find central operators.
- Rank risky nodes.
- Predict which account/number may be part of the same campaign.

Useful graph algorithms:

- Connected components for linking obvious related cases.
- PageRank/eigenvector centrality for important mule accounts.
- Louvain/community detection for fraud rings.
- Node2Vec/GraphSAGE/GAT for learned node risk.
- Temporal graph analysis for campaign evolution.

### 3.4 Voice spoof and deepfake detection

Fraudsters increasingly use synthetic voices, voice conversion, replayed audio, and video-call impersonation. A software prototype can accept an uploaded audio sample and estimate whether it is likely bonafide or spoofed.

AI opportunity:

- Audio deepfake classifier.
- Replay-attack detector.
- Speaker inconsistency detection.
- Transcript plus audio fusion: "fake police script + synthetic voice = high risk."

Hackathon caution:

Voice-spoof detection is hard across languages, accents, compression, WhatsApp call quality, and background noise. Treat this as a risk signal, not the sole verdict.

## 4. Software-only product direction

Recommended focused build:

FraudShield AI: Digital Arrest Scam Detection and Fraud Network Intelligence

Do not try to build every official sub-problem equally. The strongest software-only approach is:

1. Digital Arrest Scam Detection
2. Citizen Fraud Shield
3. Fraud Network Graph Intelligence
4. Law Enforcement Intelligence Brief

Counterfeit currency and voice spoof detection can be optional stretch modules.

## 5. User personas

### 5.1 Citizen

Needs:

- "Is this call/message real or a scam?"
- "What should I do right now?"
- "How do I report this?"
- "How do I avoid losing money?"

Design requirement:

The citizen interface must be simple, low-stress, and non-technical. The output should not overwhelm the user with model details.

### 5.2 Bank fraud analyst

Needs:

- Which accounts are receiving suspicious transfers?
- Which accounts are likely mule accounts?
- Which transactions need hold/freeze review?
- Which complaints map to the same campaign?

Design requirement:

The analyst interface should show transaction graph, risk score, explainability, and evidence trail.

### 5.3 Law enforcement analyst

Needs:

- Link cases across districts/states.
- Identify top suspect nodes.
- Generate case brief.
- Produce auditable evidence mapping.

Design requirement:

The law-enforcement view must preserve auditability: every claim should trace back to input evidence.

### 5.4 Telecom/platform trust team

Needs:

- Which numbers are repeatedly reported?
- Which call patterns look coordinated?
- Which accounts are newly activated and high risk?
- Which messages match scam templates?

Design requirement:

Prototype can simulate telecom metadata; avoid claiming real telecom integration.

## 6. Recommended MVP

### Module A: Scam transcript/message classifier

Inputs:

- Pasted WhatsApp/SMS text.
- Uploaded call transcript.
- User-filled call details.
- Optional audio converted to transcript by Whisper or another ASR.

Outputs:

- Risk score: 0-100.
- Scam category: digital arrest, KYC fraud, courier fraud, investment fraud, OTP fraud, job fraud, loan fraud.
- Red flags detected:
  - fake law-enforcement threat
  - demand for secrecy
  - demand for immediate transfer
  - video-call custody language
  - fake warrant/FIR mention
  - remote access request
  - OTP request
- Immediate action:
  - disconnect call
  - do not transfer money
  - call 1930 / report via cybercrime.gov.in
  - contact local police/bank

Model options:

- Baseline: rule-based red-flag detector using phrase lists.
- ML baseline: TF-IDF + Logistic Regression / Linear SVM.
- Stronger model: multilingual transformer fine-tuned on scam/non-scam text.
- LLM layer: explanation, summarization, victim guidance, report drafting.

Best hackathon approach:

Use a hybrid system:

- Rules for high-precision red flags.
- ML classifier for generalization.
- LLM for natural-language explanation and report generation.

### Module B: Citizen Fraud Shield

Interface:

- Chat-style or form-style UI.
- Citizen pastes suspicious text or describes the call.
- The system asks 3-5 clarifying questions:
  - Did they ask you to stay on video call?
  - Did they ask you not to tell family/police?
  - Did they ask for money transfer?
  - Did they show a warrant/FIR/ID card?
  - Did they ask for OTP or screen sharing?

Output:

- "High risk digital arrest scam"
- Explanation in simple language.
- Safety checklist.
- Report-ready summary.
- Regional language advisory as stretch.

UX principle:

The tool must give a firm warning when risk is high. Avoid vague outputs like "possibly suspicious" when the script contains classic coercion markers.

### Module C: Fraud network graph

Inputs:

- Synthetic complaint dataset.
- Transaction table.
- Phone number/account/device mappings.
- Scam text similarity clusters.

Example schema:

complaints.csv:

- complaint_id
- date
- city
- victim_age_band
- channel
- reported_loss
- transcript_id
- suspect_phone
- suspect_account
- suspect_upi

transactions.csv:

- txn_id
- timestamp
- source_account
- destination_account
- amount
- bank
- city
- status

entities.csv:

- entity_id
- entity_type
- risk_label
- first_seen
- last_seen

Graph output:

- Network visualization.
- Top mule accounts.
- Connected complaints.
- Campaign clusters.
- Timeline of fund movement.

Algorithms:

- Connected components to link cases.
- Community detection to identify campaigns.
- Centrality to prioritize investigation.
- Supervised model or graph features to score mule accounts.

### Module D: Law enforcement intelligence brief

Automatically generate:

- Case summary.
- Victim impact.
- Scam script pattern.
- Linked phone numbers/accounts/devices.
- Fund flow path.
- Top suspects/entities.
- Evidence table.
- Confidence score.
- Recommended actions:
  - freeze account review
  - telecom number takedown review
  - cross-district linkage
  - citizen advisory

Critical design point:

Every generated statement must cite the underlying evidence row or input. Judges will reward auditability because the official PS explicitly mentions legal admissibility.

## 7. Optional modules

### 7.1 Counterfeit note image triage

Inputs:

- Uploaded image of note front/back.

Pipeline:

1. Image quality check: blur, lighting, crop, rotation.
2. Note alignment and denomination detection.
3. Security feature localization.
4. Genuine/fake classification.
5. Explainable warning.

Model:

- Start with MobileNet/EfficientNet image classifier.
- Add YOLO for security feature region detection if dataset allows.

Risks:

- Public Indian counterfeit datasets are limited and may be low quality.
- Real note authentication requires physical/UV/magnetic features.
- Avoid claiming bank-grade final authenticity.

Best framing:

"Mobile-first field triage tool for suspicious-note escalation."

### 7.2 Voice spoof/deepfake risk

Inputs:

- Uploaded suspicious audio.

Pipeline:

1. Voice activity detection.
2. Spectrogram feature extraction.
3. Spoof classifier trained on ASVspoof.
4. Transcript extraction.
5. Fusion with scam-script classifier.

Datasets:

- ASVspoof 2019/2021.

Risks:

- Indian languages and call-compressed audio may be underrepresented.
- Better to present as an auxiliary signal.

## 8. Architecture

```text
Citizen / Analyst Inputs
  - message text
  - call transcript
  - optional audio
  - optional note image
  - complaint records
  - transaction/account graph
        |
        v
Ingestion and Preprocessing
  - language detection
  - OCR/ASR if needed
  - entity extraction
  - PII masking
  - transaction normalization
        |
        v
AI Models
  - scam text classifier
  - red-flag rule engine
  - fraud graph risk scorer
  - optional voice spoof detector
  - optional counterfeit note classifier
        |
        v
Fusion and Decision Layer
  - risk score
  - evidence aggregation
  - campaign clustering
  - confidence calibration
        |
        v
Outputs
  - citizen warning
  - analyst dashboard
  - fraud network graph
  - law-enforcement intelligence brief
  - reporting guidance
```

## 9. Data strategy

### 9.1 Text scam data

Real digital-arrest scam transcripts are sensitive and rarely open. Use a layered strategy:

1. Manually create 50-100 high-quality synthetic digital arrest scripts based on known scam patterns.
2. Add public phishing/SMS spam datasets for non-digital-arrest fraud classes.
3. Generate controlled paraphrases in English, Hinglish, Hindi, and one regional language if needed.
4. Include benign official communication examples to reduce false positives.
5. Label red flags at phrase/span level.

Suggested labels:

- digital_arrest
- fake_law_enforcement
- courier_customs_fraud
- kyc_bank_fraud
- otp_fraud
- investment_fraud
- benign

Span-level tags:

- authority_impersonation
- fear_threat
- secrecy_instruction
- money_transfer_request
- fake_document_reference
- remote_access_request
- otp_request
- urgency

### 9.2 Fraud graph data

Possible data sources:

- IEEE-CIS Fraud Detection benchmark for transaction fraud.
- ULB Credit Card Fraud Detection dataset.
- PaySim synthetic mobile-money transaction dataset.
- Custom synthetic graph tuned to Indian scam workflow.

Recommended:

Use synthetic graph data for the demo because it lets you tell a clear digital-arrest story. Use public fraud benchmarks to validate the model separately if time allows.

### 9.3 Audio data

Use:

- ASVspoof 2019/2021 for spoof vs bonafide audio detection.

Adaptation:

- Add noise/compression augmentation to mimic phone/WhatsApp audio.
- If using Indian-language samples, clearly label them as demo samples unless you have permissions.

### 9.4 Counterfeit note data

Possible sources:

- Public Kaggle/Roboflow Indian currency image datasets.
- Team-collected genuine note photos.
- Synthetic fake-note perturbations for demo only.

Caution:

Do not create realistic counterfeit-generation instructions. The model should classify or triage images, not assist forgery.

## 10. Evaluation plan

Judges will care about whether the system works, not only whether the UI looks nice.

### 10.1 Scam classifier metrics

Primary:

- Precision for high-risk scam class.
- Recall for digital arrest scam.
- F1 score.
- False positive rate on benign official messages.

Why:

Citizen-facing systems must avoid both missing real scams and falsely panicking people. For "high-risk scam," precision should be high; for "possible scam," recall can be higher.

### 10.2 Red-flag extraction metrics

Measure:

- Exact or partial match of red-flag spans.
- Per-category precision/recall.

Example:

If transcript says "Do not tell anyone or you will be arrested," the system should tag secrecy_instruction and fear_threat.

### 10.3 Fraud graph metrics

Measure:

- Fraud cluster detection purity.
- Mule account ranking precision@K.
- Time-to-identify linked cases.
- Graph explainability: can the system explain why two cases are linked?

### 10.4 Voice spoof metrics

Measure:

- Equal Error Rate (EER).
- AUC.
- Accuracy on clean vs noisy audio.

### 10.5 End-to-end demo metrics

Create before/after story:

- Manual review time: 20 minutes per complaint.
- AI triage time: less than 30 seconds.
- Linked case discovery: from isolated complaints to one campaign cluster.
- Citizen action: warning before transfer.

## 11. Technical stack

Recommended:

- Python
- pandas, numpy
- scikit-learn for baselines
- PyTorch or TensorFlow for deep models
- Hugging Face Transformers for text classifier
- Whisper or other ASR for audio transcription
- NetworkX for graph analytics
- PyVis, Plotly, or Cytoscape for graph visualization
- Streamlit for UI
- FastAPI if separating backend
- SQLite/Postgres for prototype storage
- Chroma/FAISS if using RAG over advisories

LLM use:

- Summarize complaints.
- Generate citizen advisory.
- Generate law-enforcement brief.
- Extract structured fields from unstructured transcripts.

Do not rely only on LLM classification. Judges may see it as a wrapper. Pair it with measurable classifiers and graph algorithms.

## 12. Model design

### 12.1 Baseline scam classifier

Simple baseline:

- Clean text.
- Convert to TF-IDF features.
- Train Logistic Regression or Linear SVM.
- Output class probabilities.

Pros:

- Fast.
- Explainable.
- Easy to evaluate.

Cons:

- Weak on paraphrases and multilingual text.

### 12.2 Transformer classifier

Options:

- IndicBERT / MuRIL / XLM-RoBERTa for Indian multilingual inputs.
- DistilBERT for English-only prototype.

Training:

- Fine-tune on labeled scam/benign examples.
- Add class weighting for imbalance.
- Use train/validation split.

Output:

- Scam category.
- Risk probability.

### 12.3 Red-flag rule engine

Maintain curated red-flag phrase patterns:

- "digital arrest"
- "do not disconnect"
- "do not tell anyone"
- "CBI officer"
- "money laundering case"
- "safe account"
- "verification transfer"
- "your Aadhaar is linked"
- "customs parcel"
- "arrest warrant"
- "screen share"
- "AnyDesk"
- "OTP"

Use fuzzy matching and language variants.

### 12.4 Risk fusion

Example formula:

```text
risk_score =
  0.35 * scam_classifier_probability
+ 0.25 * red_flag_score
+ 0.20 * graph_entity_risk
+ 0.10 * voice_spoof_score
+ 0.10 * user_context_score
```

Then calibrate into:

- 0-30: low
- 31-60: suspicious
- 61-80: high risk
- 81-100: emergency scam warning

### 12.5 Fraud graph risk

Node features:

- number of complaints
- total received amount
- number of victim cities
- account age
- transaction burstiness
- in-degree/out-degree
- shared device count
- number of linked scam scripts

Model options:

- Rule-based mule score.
- Random Forest/XGBoost over node features.
- GraphSAGE/GAT if time permits.

Hackathon-safe choice:

Use NetworkX plus XGBoost/RandomForest. Add GNN only if the team is comfortable.

## 13. Demo storyboard

### Scene 1: Citizen receives threat

Show a fake scam transcript:

"This is from Mumbai Cyber Crime Branch. Your Aadhaar has been linked to money laundering. You are under digital arrest. Stay on this video call. Do not tell anyone. Transfer your funds to the RBI verification account."

System output:

- High risk digital arrest scam.
- Red flags highlighted.
- Immediate safety advice.

### Scene 2: Citizen files/report gets created

System creates:

- Plain-language report.
- Complaint summary.
- Evidence table.

### Scene 3: Analyst sees linked cases

Dashboard shows:

- Same account linked to 14 complaints.
- Same script template used across 5 cities.
- Funds moved to 3 downstream mule accounts.

### Scene 4: Intelligence brief

System generates:

- "Campaign A: fake cyber police digital arrest"
- Top linked numbers/accounts.
- Recommended freezing/takedown review.
- Confidence and evidence references.

### Scene 5: Impact

Show metrics:

- Scam detection F1.
- Mule account precision@10.
- Response time reduced from hours to seconds.

## 14. Innovation angles

The winning version should not be just a chatbot. Strong innovation claims:

1. Multimodal risk fusion: text + graph + optional voice/image.
2. Span-level scam script explainability.
3. Campaign-level clustering, not isolated complaint classification.
4. Citizen-to-law-enforcement pipeline: warning to evidence brief.
5. Audit-ready intelligence package with evidence traceability.
6. Indian context: digital arrest scripts, Hinglish support, 1930/cybercrime reporting guidance.

## 15. Business and social impact

Stakeholders:

- Citizens avoid losses.
- Banks get earlier mule-account signals.
- Telecom providers get risky-number indicators.
- Police get linked-case intelligence.
- Policy teams get hotspot and pattern analysis.

Impact metrics:

- Reduced time from victim contact to warning.
- Reduced time from complaint to linked case discovery.
- Increased freezing/takedown prioritization quality.
- Reduced repeated victimization by the same infrastructure.

## 16. Risks and mitigations

### Risk: Scope explosion

Mitigation:

Focus on digital arrest scams first. Fraud graph second. Voice/counterfeit as stretch.

### Risk: Synthetic data looks fake

Mitigation:

Create realistic scripts from documented scam patterns, label red flags, and clearly state what is synthetic. Use public fraud graph datasets for model validation.

### Risk: LLM hallucination in legal brief

Mitigation:

Use structured evidence tables. Force the brief generator to cite evidence IDs. Never allow unsupported claims.

### Risk: False positives harm users

Mitigation:

Use risk tiers. Provide "verify independently" guidance. Avoid accusing real people/accounts in demo data.

### Risk: Privacy and PII

Mitigation:

Mask phone/account numbers. Use synthetic data. Show privacy-aware ingestion.

### Risk: Counterfeit module overclaims

Mitigation:

Call it "suspicious-note triage" and state that final authentication requires authorized methods.

## 17. Suggested team split

M1 - NLP/Text ML:

- Scam classifier.
- Red-flag extraction.
- Multilingual handling.

M2 - Graph/Fraud ML:

- Fraud graph schema.
- Mule account scoring.
- Cluster detection.

M3 - LLM/Agents:

- Citizen advisory.
- Structured extraction.
- Intelligence brief with citations.

M4 - Data/UI/MLOps:

- Synthetic case generator.
- Streamlit dashboard.
- Integration and demo.

Optional:

- One person can add voice spoof detection using ASVspoof if core modules are complete.

## 18. Build plan

### Day 1-2

- Finalize scope.
- Create synthetic digital arrest dataset.
- Create graph schema.
- Build first Streamlit skeleton.

### Day 3-5

- Build TF-IDF baseline classifier.
- Build red-flag rule engine.
- Build complaint form and citizen output.

### Day 6-8

- Build fraud graph generator.
- Add NetworkX clustering and centrality.
- Add graph visualization.

### Day 9-11

- Add LLM-based report generator.
- Add evidence traceability.
- Add evaluation metrics.

### Day 12-14

- Polish UI.
- Create demo script.
- Create deck and video.
- Test end-to-end scenario.

## 19. What to show judges

Show:

- Scam input.
- Highlighted red flags.
- Risk score and explanation.
- Linked fraud network.
- Evidence-backed intelligence brief.
- Evaluation metrics.

Say:

"We are not just classifying messages. We are connecting citizen-facing prevention with law-enforcement intelligence."

Avoid saying:

- "This will automatically arrest criminals."
- "This proves a note/account/person is fake."
- "This replaces police/bank investigation."

## 20. Recommended final project title

FraudShield AI: Real-Time Digital Arrest Scam Detection and Fraud Network Intelligence

Alternative titles:

- ScamRakshak AI
- CyberShield 1930
- Digital Arrest Defense Grid
- FraudNet India

## 21. Final recommendation

PS6 is a strong hackathon choice if the team keeps scope disciplined. The best build is not a scattered platform with five half-working models. The best build is a deep, polished digital-arrest scam workflow:

1. Detect scam script.
2. Warn citizen.
3. Link cases through graph intelligence.
4. Generate evidence-backed law-enforcement brief.

This gives strong Innovation, Business Impact, Technical Excellence, and UX.

## 22. References

Note: The detailed paper explanations are also available as a separate companion file:
`research/codex/PS6_papers.md`. If your editor or preview only shows this document up to section 22, open that file directly.

Official/local:

- ET AI Hackathon 2026 Problem Statements PDF in this repo: `6a38ce305640d_ET_AI_Hackathon_2026_Problem_Statements.pdf`
- Local analysis file: `ET_Hackathon_2026_Analysis.md`

Public safety and cybercrime context:

- National Cyber Crime Reporting Portal: https://cybercrime.gov.in/
- Indian Cyber Crime Coordination Centre overview: https://www.mha.gov.in/division_of_mha/cyber-and-information-security-cis-division/Details-about-Indian-Cybercrime-Coordination-Centre-I4C-Scheme
- Recent digital arrest scam reporting and examples:
  - Economic Times, CBI arrests in Rs 2.07 crore digital arrest case: https://m.economictimes.com/news/india/cbi-nabs-three-people-in-2-07-cr-digital-arrest-scam/articleshow/132169073.cms
  - Times of India, senior citizen loses Rs 74 lakh: https://timesofindia.indiatimes.com/city/pune/kothrud-senior-citizen-loses-rs74-lakh-in-digital-arrest-scam/articleshow/132170368.cms
  - Times of India, multi-state digital arrest fraud arrests: https://timesofindia.indiatimes.com/city/ahmedabad/four-who-cheated-senior-citizen-from-gujarat-of-rs-2-27-through-digital-arrest-fraud-arrested-from-bihar-west-bengal-haryana/articleshow/129785375.cms

Currency/counterfeit context:

- Reserve Bank of India annual reports: https://www.rbi.org.in/Scripts/AnnualReportMainDisplay.aspx
- Recent Rs 500 counterfeit reporting: https://m.economictimes.com/news/economy/finance/fake-rs-500-notes-surge-20-as-counterfeits-rise-across-banking-system/articleshow/131386765.cms

Datasets and technical references:

- ASVspoof 2019 challenge: https://www.asvspoof.org/index2019.html
- IEEE-CIS Fraud Detection: https://www.kaggle.com/c/ieee-fraud-detection
- ULB Credit Card Fraud Detection: https://www.kaggle.com/datasets/mlg-ulb/creditcardfraud
- PaySim synthetic mobile-money fraud dataset: https://www.kaggle.com/datasets/ealaxi/paysim1

Related technical/project references:

- ASVspoof main site: https://www.asvspoof.org/
- ASVspoof 2021: https://www.asvspoof.org/index2021.html
- ASVspoof 2024: https://www.asvspoof.org/index2024.html
- Hugging Face Transformers documentation: https://huggingface.co/docs/transformers/
- NetworkX documentation: https://networkx.org/documentation/stable/
- Streamlit documentation: https://docs.streamlit.io/
- Plotly Python graphing library: https://plotly.com/python/
- scikit-learn documentation: https://scikit-learn.org/stable/

## 23. Papers

This section explains the academic/research papers most relevant to a strong PS6 build. These are not all mandatory to implement, but they give language, methods, metrics, and defensible technical grounding for the deck.

### 23.1 Automated Classification of Cybercrime Complaints using Transformer-based Language Models for Hinglish Texts

Link: https://arxiv.org/abs/2412.16614

What the paper is about:

This paper studies automated classification of cybercrime complaints, especially in Hinglish and code-mixed Indian text. It uses transformer models such as HingBERT and HingRoBERTa and discusses privacy-aware preprocessing, class imbalance, and data augmentation.

Why it matters for PS6:

Digital arrest scam reports in India will often be written in English, Hindi, Hinglish, or mixed regional language. A simple English-only classifier may miss real complaints. This paper directly supports the idea that cybercrime complaint triage needs multilingual and code-mixed NLP.

How to use it in our project:

- Use it as justification for choosing Indic/multilingual transformer models.
- Use its framing for complaint classification rather than generic spam detection.
- Mention class imbalance and privacy-aware preprocessing in the methodology.
- Use its reported metrics as a rough benchmark direction, not as a direct comparison unless using the same dataset.

Practical takeaway:

For MVP, start with TF-IDF/logistic regression and a red-flag rule engine. For a stronger version, fine-tune XLM-R, MuRIL, IndicBERT, HingBERT, or similar models on scam/benign complaint text.

### 23.2 ASVspoof 2019: A Large-scale Public Database of Synthesized, Converted and Replayed Speech

Link: https://arxiv.org/abs/1911.01601

What the paper is about:

This paper describes the ASVspoof 2019 dataset and challenge for detecting spoofed speech. It covers logical access attacks such as synthetic and voice-converted speech, and physical access attacks such as replayed speech.

Why it matters for PS6:

The official PS6 statement mentions AI voices and impersonation. Digital arrest scammers may use replayed or synthetic voices to increase credibility. ASVspoof gives a standard research foundation for voice-spoof detection.

How to use it in our project:

- Use ASVspoof as the dataset for an optional voice-risk module.
- Treat voice-spoof score as one risk signal, not the final verdict.
- Use audio model output in risk fusion alongside transcript scam score and graph risk.

Practical takeaway:

Voice detection should be optional/stretch. The core PS6 win should remain digital arrest scam text + graph intelligence. If implemented, use ASVspoof to train or demo a bonafide/spoof classifier.

### 23.3 ASVspoof 2019: Future Horizons in Spoofed and Fake Audio Detection

Link: https://arxiv.org/abs/1904.05441

What the paper is about:

This paper introduces the ASVspoof 2019 challenge direction and discusses fake audio detection under logical access and physical access scenarios. It also highlights evaluation metrics such as tandem detection cost function and equal error rate.

Why it matters for PS6:

It helps explain why voice-spoof detection is difficult and why standard evaluation matters. It is useful if the team includes a voice module and wants to avoid vague claims.

How to use it in our project:

- Use Equal Error Rate (EER) or AUC for the audio module.
- Explain that replay, synthesis, and voice conversion are different attack types.
- Mention that noisy phone-call conditions can reduce reliability.

Practical takeaway:

If showing audio spoof detection, state the limitation clearly: "This is an auxiliary risk signal, especially useful when combined with scam-script indicators."

### 23.4 ASVspoof 2019: Spoofing Countermeasures for the Detection of Synthesized, Converted and Replayed Speech

Link: https://arxiv.org/abs/2102.05889

What the paper is about:

This paper reviews ASVspoof 2019 challenge results and discusses the performance of submitted spoofing countermeasure systems. It explains what worked, where systems struggled, and why fusion approaches can help.

Why it matters for PS6:

The paper supports the idea that no single signal is enough. Different spoofing conditions can degrade performance, so a multimodal fraud detector should combine transcript analysis, graph signals, and optional audio signals.

How to use it in our project:

- Use it to justify multimodal fusion.
- Mention that audio-only detection is fragile under real-world noise.
- Keep the main verdict evidence-based and not dependent on voice alone.

Practical takeaway:

Do not overclaim "we detect all AI voices." Say "we estimate voice-spoof risk and combine it with scam behavior indicators."

### 23.5 The DKU Replay Detection System for the ASVspoof 2019 Challenge

Link: https://arxiv.org/abs/1907.02663

What the paper is about:

This paper presents a replay attack detection system for ASVspoof 2019. It discusses feature representations, deep learning classifiers, data augmentation, and score fusion.

Why it matters for PS6:

Replay attacks are realistic in scam scenarios: a fraudster may replay official-sounding audio, recorded threats, or synthetic clips. The paper gives technical ideas for detecting replayed speech.

How to use it in our project:

- Use spectrogram-style features or pretrained audio embeddings.
- Apply data augmentation for phone noise/compression.
- Use score fusion if multiple audio features are implemented.

Practical takeaway:

Useful for a stretch audio module. Not necessary for the core PS6 MVP.

### 23.6 Interpretable vs Learned Encoders for High-Cardinality Fraud Detection

Link: https://arxiv.org/abs/2607.00477

What the paper is about:

This recent paper evaluates encoding methods for fraud detection using high-cardinality categorical variables on the IEEE-CIS fraud benchmark. It compares approaches such as target encoding, entity embeddings, CatBoost, and TabNet-style models.

Why it matters for PS6:

Fraud data often contains high-cardinality fields: account IDs, device IDs, phone numbers, UPI IDs, merchant IDs, IPs, and locations. Encoding these fields well matters for transaction and mule-account risk scoring.

How to use it in our project:

- Use it to justify CatBoost/LightGBM or target/entity encoding for tabular fraud features.
- Explain that IDs and categorical fields carry fraud signals.
- Include interpretability in the fraud analyst view.

Practical takeaway:

For a hackathon, use CatBoost/LightGBM or engineered graph features before attempting a complex GNN.

### 23.7 SCAFDS: Edge-Feature Graph Attention for Interbank Fraud Detection with Attribution-Grounded SAR Generation

Link: https://arxiv.org/abs/2605.18913

What the paper is about:

This paper proposes a graph attention approach for interbank fraud detection and includes attribution-grounded suspicious activity report generation. It emphasizes graph structure, edge features, and report traceability.

Why it matters for PS6:

This aligns strongly with the PS6 law-enforcement intelligence brief. The official problem asks for auditability and legal admissibility. A graph-plus-report approach gives the right direction: detect suspicious networks and explain them with evidence.

How to use it in our project:

- Use graph edges with features such as amount, frequency, time gap, and shared complaint count.
- Generate reports with evidence references.
- Include an "evidence table" under every generated intelligence brief.

Practical takeaway:

Even if we do not build a graph neural network, we should borrow the core product idea: graph-based fraud risk plus attribution-grounded report generation.

### 23.8 Serial Scammers and Attack of the Clones: How Scammers Coordinate Multiple Rug Pulls on Decentralized Exchanges

Link: https://arxiv.org/abs/2412.10993

What the paper is about:

This paper studies scammer coordination in decentralized exchanges. It identifies repeated patterns, scam clusters, shared infrastructure, and money-flow behaviors.

Why it matters for PS6:

Although it is crypto-specific, the core lesson applies to digital arrest scams: organized fraud repeats scripts, infrastructure, accounts, and fund-flow patterns across many victims.

How to use it in our project:

- Use cluster-level thinking, not only single-transaction classification.
- Detect repeated scam templates and linked mule accounts.
- Show campaign-level intelligence in the dashboard.

Practical takeaway:

Judges will like the shift from "single scam detector" to "organized campaign intelligence."
