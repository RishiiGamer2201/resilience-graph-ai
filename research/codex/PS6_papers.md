# PS6 Papers: Detailed Research Notes

Last updated: 2026-07-06

Companion file for `research/codex/PS6.md`.

This file contains only the paper-focused research for PS6: AI for Digital Public Safety. It is separated out so the team can quickly find the academic grounding without scrolling through the full PS6 research document.

## 1. Automated Classification of Cybercrime Complaints using Transformer-based Language Models for Hinglish Texts

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

## 2. ASVspoof 2019: A Large-scale Public Database of Synthesized, Converted and Replayed Speech

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

Voice detection should be optional/stretch. The core PS6 win should remain digital arrest scam text plus graph intelligence. If implemented, use ASVspoof to train or demo a bonafide/spoof classifier.

## 3. ASVspoof 2019: Future Horizons in Spoofed and Fake Audio Detection

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

## 4. ASVspoof 2019: Spoofing Countermeasures for the Detection of Synthesized, Converted and Replayed Speech

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

## 5. The DKU Replay Detection System for the ASVspoof 2019 Challenge

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

## 6. Interpretable vs Learned Encoders for High-Cardinality Fraud Detection

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

## 7. SCAFDS: Edge-Feature Graph Attention for Interbank Fraud Detection with Attribution-Grounded SAR Generation

Link: https://arxiv.org/abs/2605.18913

What the paper is about:

This paper proposes a graph attention approach for interbank fraud detection and includes attribution-grounded suspicious activity report generation. It emphasizes graph structure, edge features, and report traceability.

Why it matters for PS6:

This aligns strongly with the PS6 law-enforcement intelligence brief. The official problem asks for auditability and legal admissibility. A graph-plus-report approach gives the right direction: detect suspicious networks and explain them with evidence.

How to use it in our project:

- Use graph edges with features such as amount, frequency, time gap, and shared complaint count.
- Generate reports with evidence references.
- Include an evidence table under every generated intelligence brief.

Practical takeaway:

Even if we do not build a graph neural network, we should borrow the core product idea: graph-based fraud risk plus attribution-grounded report generation.

## 8. Serial Scammers and Attack of the Clones: How Scammers Coordinate Multiple Rug Pulls on Decentralized Exchanges

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
