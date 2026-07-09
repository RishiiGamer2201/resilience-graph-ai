# PS7 Deep Research: AI-Driven Cyber Resilience for Critical National Infrastructure

Last updated: 2026-07-06

Problem statement: AI-Driven Cyber Resilience for Critical National Infrastructure

This note is written for a software-only hackathon build. It rules out real production access to government networks, live SOC integrations, endpoint agents, firewalls, EDR deployment, and destructive response actions. The prototype should use public cybersecurity datasets, simulated enterprise/critical-infrastructure topology, MITRE ATT&CK mapping, and simulated response playbooks.

## 1. One-line understanding

PS7 asks us to build an AI system that detects abnormal cyber behavior early, connects weak signals across IT/OT logs, maps the attack to known adversary tactics, and recommends or simulates containment before the attack becomes a full breach.

In simple words: do not wait until ransomware detonates. Detect the attacker while they are moving quietly through the network.

## 2. Why this problem matters

Critical national infrastructure includes sectors such as:

- Power grids
- Railways and transport
- Telecom
- Banking and payments
- Healthcare
- Education systems
- Government data centers
- Water systems
- Oil, gas, and industrial plants

These systems are attractive targets because outages can cause public disruption, financial damage, national-security risk, and loss of trust.

The official hackathon problem statement highlights:

- CERT-In handled more than 1.59 million cybersecurity incidents in 2023.
- High-profile Indian public-sector incidents include AIIMS Delhi ransomware and education-system breaches.
- Many government entities operate with legacy or end-of-life systems.
- The deep problem is detection speed: attackers often stay inside systems for long periods before discovery.

The PS7 goal is to compress:

```text
initial compromise -> detection -> investigation -> containment
```

from weeks/months to hours/minutes.

## 3. Basic concepts

### 3.1 Cyber resilience

Cybersecurity often means preventing attacks. Cyber resilience is broader. It means the organization can:

1. Prepare for attacks.
2. Detect attacks quickly.
3. Contain damage.
4. Recover operations.
5. Learn from incidents.

For a critical national infrastructure system, perfect prevention is unrealistic. The winning idea is resilience: assume attackers may enter, but detect and contain them before catastrophic impact.

### 3.2 SOC

SOC means Security Operations Center. A SOC monitors alerts, logs, endpoint activity, network traffic, and threat intelligence.

SOC workflow:

1. Collect telemetry.
2. Generate alerts.
3. Triage alerts.
4. Investigate suspicious activity.
5. Map to attack pattern.
6. Contain or remediate.
7. Document the incident.

PS7 is essentially asking for an AI-augmented SOC for critical infrastructure.

### 3.3 SIEM

SIEM means Security Information and Event Management. It collects and correlates logs from many systems:

- Firewalls
- Servers
- Active Directory
- VPN
- DNS
- Proxy
- Applications
- Cloud services
- Endpoints

Examples: Splunk, Elastic, QRadar, Sentinel.

In the hackathon, we can simulate a SIEM by reading CSV/log files and showing correlated events in a dashboard.

### 3.4 SOAR

SOAR means Security Orchestration, Automation and Response. It runs playbooks after alerts:

- Disable user
- Block IP
- Isolate endpoint
- Revoke token
- Create ticket
- Notify analyst
- Snapshot VM
- Trigger backup validation

In the hackathon, response actions should be simulated and gated by confidence level. Do not claim real-world autonomous containment unless integrated with production controls.

### 3.5 IT vs OT

IT systems:

- Email
- Servers
- User devices
- Web apps
- Databases
- Identity systems

OT systems:

- Industrial controllers
- SCADA
- PLCs
- Sensors
- Physical process control

PS7 mentions heterogeneous IT and OT. For software-only scope, build around IT logs plus an optional simulated OT asset graph.

### 3.6 APT

APT means Advanced Persistent Threat. These are usually skilled, patient attackers who:

- Gain initial access.
- Establish persistence.
- Escalate privileges.
- Move laterally.
- Collect data.
- Exfiltrate data or disrupt operations.

APT detection is hard because early actions can look normal in isolation. The AI value is correlating weak signals.

## 4. MITRE ATT&CK basics

MITRE ATT&CK is a globally used knowledge base of adversary tactics and techniques based on real-world observations. MITRE describes it as a foundation for threat models and methodologies in government, industry, and the cybersecurity community.

Important idea:

- Tactic = why the attacker is doing something.
- Technique = how the attacker does it.

Example:

- Tactic: Credential Access
- Technique: Brute Force

Enterprise ATT&CK tactics include:

- Reconnaissance
- Resource Development
- Initial Access
- Execution
- Persistence
- Privilege Escalation
- Defense Evasion
- Credential Access
- Discovery
- Lateral Movement
- Collection
- Command and Control
- Exfiltration
- Impact

For PS7, ATT&CK gives the "language" to explain alerts. Judges will understand the system better if it says:

"This pattern maps to Valid Accounts + Remote Services + Lateral Movement"

instead of:

"Anomaly score is 0.91."

## 5. Recommended software-only product direction

Recommended focused build:

ResilienceGraph AI: Behavioral Anomaly Detection, ATT&CK Mapping, and Response Simulation for Critical Infrastructure

Core modules:

1. Behavioral anomaly detector.
2. Attack-stage correlation engine.
3. MITRE ATT&CK mapper.
4. Attack path graph.
5. Simulated SOAR response.
6. Analyst dashboard and incident report.

Avoid trying to build a full cyber product. Build one strong story:

"A low-and-slow attacker compromises a user, moves laterally, touches a critical server, and our system detects the behavior before impact."

## 6. User personas

### 6.1 SOC analyst

Needs:

- Which alerts matter?
- Why is this behavior suspicious?
- What technique does it map to?
- What should I investigate next?
- What response is safe?

### 6.2 Incident commander

Needs:

- What is the blast radius?
- Which assets are critical?
- What is the likely attack stage?
- What containment action is recommended?
- What is the business impact?

### 6.3 CISO / public-sector security leader

Needs:

- Risk posture.
- Mean time to detect and respond.
- Legacy asset exposure.
- Prioritized remediation.
- Audit trail.

### 6.4 OT/plant security engineer

Needs:

- Which IT compromise can affect OT?
- Which network paths reach critical control assets?
- Which response actions are safe and unsafe?

## 7. Recommended MVP

### Module A: Log ingestion and normalization

Inputs:

- Network flow logs.
- Authentication logs.
- Process logs.
- DNS logs.
- Optional vulnerability/asset inventory.

Output normalized event schema:

- timestamp
- user
- source_host
- destination_host
- event_type
- protocol
- port
- process
- status
- bytes
- label, if available

This normalization is important because cyber datasets often have different columns.

### Module B: Behavioral anomaly detection

Goal:

Build a baseline of normal behavior and detect deviations.

Examples:

- User logs in at unusual time.
- User authenticates to many new hosts.
- Host contacts rare destination.
- Abnormal data volume.
- Unusual process starts.
- Failed logins spike.
- Lateral movement pattern.

Model options:

- Isolation Forest.
- One-Class SVM.
- Local Outlier Factor.
- Autoencoder.
- LSTM/Transformer sequence model.
- Graph anomaly detection.

Hackathon recommendation:

Start with Isolation Forest and feature engineering. Add an autoencoder or sequence model only if the baseline works.

Why:

Cyber datasets are noisy. A simple, explainable anomaly model plus good features often demos better than a deep model that is hard to interpret.

### Module C: Attack-stage correlation

A single anomaly is not enough. The system should correlate events into a timeline.

Example chain:

1. Multiple failed logins.
2. Successful login from unusual source.
3. Discovery commands.
4. Authentication to many internal hosts.
5. Connection to file server.
6. Large outbound transfer.

This becomes an incident chain.

Implementation:

- Sort events by time.
- Group by user/host/session.
- Identify windows of related anomalies.
- Assign tactic labels.
- Calculate incident severity.

### Module D: MITRE ATT&CK mapper

Inputs:

- Event features.
- Detection rules.
- Model explanations.

Outputs:

- ATT&CK tactic.
- ATT&CK technique.
- Confidence score.
- Explanation.

Examples:

- Many failed logins -> Credential Access / Brute Force.
- Login to many hosts with same account -> Lateral Movement / Remote Services or Valid Accounts.
- Suspicious PowerShell -> Execution / Command and Scripting Interpreter.
- Large outbound transfer -> Exfiltration / Exfiltration Over Web Service.

Implementation options:

- Rule-based mapping for high-confidence demo.
- RAG over ATT&CK pages for explanation.
- LLM to draft explanation, constrained to known technique IDs.

Do not let the LLM invent technique names. Maintain a whitelist of tactics/techniques.

### Module E: Attack path graph

Graph nodes:

- Users
- Hosts
- Servers
- Applications
- Critical assets
- Vulnerabilities
- Network segments

Graph edges:

- user logged into host
- host connected to host
- host can reach server
- host has vulnerability
- user has privilege
- asset belongs to critical service

What it shows:

- How attacker may move from one host to another.
- Which critical systems are at risk.
- Which node should be isolated to reduce blast radius.

Algorithms:

- Shortest path to critical asset.
- Betweenness centrality for choke points.
- Reachability analysis.
- Risk propagation.

### Module F: Simulated SOAR response

Inputs:

- Incident severity.
- Confidence.
- Criticality of asset.
- Blast radius.

Possible actions:

- Disable account.
- Force password reset.
- Block IP/domain.
- Isolate host.
- Kill process.
- Snapshot VM.
- Open ticket.
- Escalate to human.

Response policy:

- Low confidence: monitor and ask analyst.
- Medium confidence: create ticket, request MFA reset, enrich evidence.
- High confidence: simulate containment action.
- Critical asset involved: require human approval.

This is important because autonomous response can cause operational harm.

## 8. Architecture

```text
Data Sources
  - network flows
  - authentication logs
  - DNS logs
  - endpoint/process logs
  - asset inventory
  - vulnerability feed
  - MITRE ATT&CK knowledge base
        |
        v
Ingestion and Normalization
  - parse logs
  - unify timestamps
  - map users/hosts/assets
  - build time windows
        |
        v
Detection Layer
  - anomaly model
  - rule engine
  - sequence correlation
  - graph risk features
        |
        v
Threat Intelligence Layer
  - ATT&CK mapping
  - CVE enrichment
  - asset criticality
  - attack path analysis
        |
        v
Response Layer
  - incident severity
  - recommended playbook
  - simulated containment
  - audit trail
        |
        v
SOC Dashboard
  - alert timeline
  - attack graph
  - MITRE tactic/technique
  - MTTD/MTTR improvement
  - incident report
```

## 9. Datasets

### 9.1 CIC-IDS2017

What it contains:

- Labeled network flows and PCAPs.
- Benign traffic plus attacks such as brute force, DoS, DDoS, web attack, infiltration, botnet, Heartbleed, and port scan.
- More than 80 network-flow features generated using CICFlowMeter.

Use for:

- Intrusion detection.
- Baseline supervised/unsupervised detection.
- Known vs unknown attack experiments.

Pros:

- Public and well-known.
- Easy to use CSV features.
- Good for showing metrics.

Cons:

- Older.
- Some attack distributions are not realistic.
- Network-flow only; not full SOC context.

### 9.2 UNSW-NB15

What it contains:

- Hybrid normal and attack network traffic generated in UNSW Canberra Cyber Range Lab.
- Attack types include Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode, and Worms.
- 49 generated features.
- Around 2.54 million records across CSV files.

Use for:

- Network intrusion detection.
- Comparison against CIC-IDS2017.
- Class imbalance handling.

Pros:

- Public.
- Multiple attack classes.

Cons:

- Synthetic attack generation.
- Class imbalance and overlap issues.

### 9.3 LANL Comprehensive Multi-Source Cyber-Security Events

What it contains:

- 58 days of de-identified event data from Los Alamos National Laboratory internal network.
- Authentication events.
- Process start/stop events.
- DNS lookups.
- Network flow data.
- Red-team events as ground truth.
- About 1.65 billion events across 12,425 users, 17,684 computers, and 62,974 processes.

Use for:

- User and entity behavior analytics.
- Lateral movement detection.
- Multi-source SOC-style correlation.

Pros:

- Much closer to enterprise behavior than simple flow datasets.
- Multi-source.
- Good for graph/timeline demo.

Cons:

- Large data size.
- De-identified fields can be hard for beginners.
- Red-team labels are sparse.

### 9.4 NSL-KDD

What it contains:

- Cleaned-up version of KDD Cup 1999 intrusion dataset.

Use for:

- Quick baseline only.

Cons:

- Very old.
- Do not rely on it as the main evidence of technical excellence.

### 9.5 TON_IoT / BoT-IoT

Use if adding IoT/OT flavor:

- IoT telemetry and network traffic.
- Useful for critical infrastructure simulation.

But for a clean MVP, CIC-IDS2017 + LANL is enough.

## 10. Feature engineering

### 10.1 Network flow features

Examples:

- duration
- protocol
- source/destination port
- packet count
- byte count
- flow rate
- packet size statistics
- inbound/outbound ratio
- failed connection count
- rare destination flag

### 10.2 Authentication features

Examples:

- login success/failure count
- unusual login hour
- new source host for user
- new destination host for user
- number of unique hosts accessed
- failed-before-success pattern
- privilege account used from unusual host

### 10.3 DNS features

Examples:

- rare domain
- domain generation algorithm suspicion
- high query volume
- newly seen domain
- internal host resolving unusual destination

### 10.4 Process features

Examples:

- rare process for host
- rare process for user
- suspicious command interpreter
- process start after unusual login
- process followed by network connection

### 10.5 Graph features

Examples:

- node degree
- betweenness centrality
- number of paths to critical assets
- new edge compared to historical graph
- community anomaly

## 11. Model options

### 11.1 Isolation Forest

Good for:

- Tabular anomaly detection.
- Quick baseline.
- Explainable feature contribution if combined with SHAP or feature inspection.

Weakness:

- May produce many false positives if features are poor.

### 11.2 Autoencoder

Good for:

- Learning normal patterns and flagging high reconstruction error.

Weakness:

- Needs enough normal data.
- Harder to explain.

### 11.3 LSTM/Transformer sequence model

Good for:

- Modeling event sequences.
- Detecting abnormal order of activities.

Weakness:

- More engineering effort.
- Needs careful sequence construction.

### 11.4 Graph anomaly detection

Good for:

- Lateral movement.
- Attack path risk.
- Unusual user-host relationships.

Weakness:

- More complex.
- Harder to complete in a short hackathon.

### 11.5 Hybrid approach

Recommended:

- Isolation Forest for first anomaly score.
- Rules for specific cyber behaviors.
- Graph analysis for blast radius.
- LLM/RAG only for explanation and report generation.

This gives technical depth without becoming fragile.

## 12. Detection examples

### Example 1: Brute force to valid account

Signals:

- Many failed logins.
- One success.
- Same source, same destination.
- Followed by access to new host.

ATT&CK mapping:

- Credential Access: Brute Force
- Initial Access or Persistence: Valid Accounts

Response:

- Force password reset.
- Disable account if high confidence.
- Investigate source host.

### Example 2: Lateral movement

Signals:

- One user logs into many hosts in short time.
- New admin share or remote service access.
- Destination hosts are in different segment.

ATT&CK mapping:

- Lateral Movement: Remote Services
- Defense Evasion or Discovery may also appear depending on logs.

Response:

- Isolate source host.
- Review credential use.
- Block remote service temporarily.

### Example 3: Data exfiltration

Signals:

- Large outbound data transfer.
- Rare external destination.
- After unusual file server access.

ATT&CK mapping:

- Collection
- Exfiltration

Response:

- Block outbound destination.
- Snapshot involved server.
- Escalate to incident commander.

### Example 4: Ransomware precursor

Signals:

- Discovery commands.
- Unusual process execution.
- Many file modifications.
- Network share enumeration.

ATT&CK mapping:

- Discovery
- Execution
- Impact

Response:

- Isolate host.
- Disable compromised account.
- Validate backups.

## 13. Evaluation plan

### 13.1 Detection metrics

Use:

- Precision
- Recall
- F1 score
- ROC-AUC
- PR-AUC
- False positive rate
- Detection lead time

Detection lead time is especially important for PS7. Show how early the system detects an attack stage before final impact.

### 13.2 MITRE mapping metrics

Use:

- Technique classification accuracy.
- Tactic classification accuracy.
- Top-k accuracy.
- Human review score if no labels.

### 13.3 Incident correlation metrics

Use:

- Number of alerts reduced into incidents.
- Correct grouping rate.
- Time saved in investigation.

### 13.4 Response metrics

Use:

- Mean time to detect (MTTD).
- Mean time to respond (MTTR).
- Playbook coverage.
- Number of actions requiring human approval.
- Audit completeness.

### 13.5 Baselines

Compare against:

- Static threshold alerts.
- Single-event detection.
- Signature-only detection.
- No correlation.

Winning technical claim:

"Our system detected the attack chain earlier than single-event thresholds and reduced analyst triage from N alerts to one incident timeline."

## 14. Dashboard design

Recommended screens:

### 14.1 SOC Overview

- Current incidents.
- Severity distribution.
- MTTD/MTTR.
- Top risky assets.
- Attack stages observed.

### 14.2 Incident Timeline

- Time-ordered attack events.
- Anomaly scores.
- ATT&CK tactic/technique labels.
- Evidence rows.

### 14.3 Attack Graph

- User -> host -> server -> critical asset path.
- Highlight compromised or suspicious nodes.
- Show recommended containment point.

### 14.4 MITRE Coverage

- ATT&CK matrix view.
- Techniques detected in current incident.
- Confidence per technique.

### 14.5 Response Playbook

- Recommended actions.
- Impact estimate.
- Human approval gate.
- Simulated execution log.

### 14.6 Incident Report

- Executive summary.
- Technical details.
- Evidence table.
- Recommended remediation.
- Audit trail.

## 15. LLM and RAG use

Good uses:

- Explain incident in plain English.
- Summarize timeline.
- Generate incident report.
- Retrieve ATT&CK technique descriptions.
- Recommend analyst questions.
- Draft remediation checklist.

Bad uses:

- Letting the LLM directly decide whether something is malicious without evidence.
- Letting the LLM invent ATT&CK techniques.
- Letting the LLM execute response actions.

Safe pattern:

1. Detection models and rules generate structured evidence.
2. ATT&CK mapper chooses from whitelist.
3. LLM explains the evidence and drafts report.
4. Report cites event IDs.

## 16. Innovation angles

Strong PS7 innovation should be more than "anomaly dashboard."

Good innovation claims:

1. Multi-source weak signal correlation.
2. Attack-path-aware prioritization.
3. MITRE ATT&CK mapping with evidence traceability.
4. Simulated SOAR with safety gates.
5. Critical-asset blast-radius scoring.
6. Detection lead-time measurement.

Weak claims:

- "We use AI to detect cyberattacks."
- "We built a chatbot for cyber logs."
- "We show alerts in a dashboard."

## 17. Business and national impact

Impact areas:

- Faster breach detection.
- Lower ransomware blast radius.
- Better prioritization for small SOC teams.
- Safer response for legacy infrastructure.
- Better audit and accountability.
- Better readiness for public-sector entities.

Important framing:

Critical infrastructure cannot simply "move fast and break things." Response must be careful. The platform should recommend actions with confidence and impact, not blindly automate shutdowns.

## 18. Risks and mitigations

### Risk: Cybersecurity domain complexity

Mitigation:

Keep one attack scenario and explain it clearly.

### Risk: Too many false positives

Mitigation:

Use incident correlation and severity scoring instead of showing every anomaly as an alert.

### Risk: Dataset does not match real critical infrastructure

Mitigation:

Be transparent. Use public enterprise/network datasets and simulate critical assets/topology.

### Risk: LLM hallucination

Mitigation:

Use structured evidence and technique whitelist.

### Risk: Autonomous response is dangerous

Mitigation:

Use simulated response and human approval gates.

### Risk: Demo feels dry

Mitigation:

Tell the story as a live attack timeline: "intrusion -> lateral movement -> critical asset at risk -> containment."

## 19. Suggested team split

M1 - Detection ML:

- Feature engineering.
- Isolation Forest / autoencoder.
- Metrics.

M2 - Graph and attack path:

- Asset graph.
- Lateral movement graph.
- Blast radius.

M3 - ATT&CK and LLM/RAG:

- Technique mapping.
- Report generation.
- Threat-intel explanation.

M4 - Data/UI/MLOps:

- Dataset loading.
- Dashboard.
- Scenario demo.
- Integration.

## 20. Build plan

### Day 1-2

- Choose dataset: CIC-IDS2017 for quick metrics, LANL for enterprise story.
- Define one attack scenario.
- Build event schema.
- Build Streamlit dashboard skeleton.

### Day 3-5

- Feature engineering.
- Train baseline anomaly model.
- Add simple rules for brute force/lateral movement/exfiltration.

### Day 6-8

- Build incident correlation.
- Build attack graph.
- Add asset criticality and blast radius.

### Day 9-11

- Add ATT&CK mapping.
- Add response playbook simulation.
- Add LLM report generation with evidence citations.

### Day 12-14

- Polish dashboard.
- Add metrics.
- Create deck and demo video.
- Rehearse story.

## 21. Demo storyboard

### Scene 1: Normal baseline

Dashboard shows normal user and host behavior.

### Scene 2: Initial suspicious activity

Failed logins spike, followed by a successful login from unusual host.

System output:

- Anomaly score rises.
- Maps to Credential Access / Brute Force and Valid Accounts.

### Scene 3: Lateral movement

Same user touches multiple internal hosts.

System output:

- Correlates multiple weak alerts into one incident.
- Shows attack path graph.

### Scene 4: Critical asset risk

The attacker reaches a server connected to a simulated critical service.

System output:

- Severity becomes critical.
- Blast radius shown.

### Scene 5: Response

System recommends:

- Disable account.
- Isolate source host.
- Block suspicious destination.
- Snapshot affected server.

Actions are shown as simulated SOAR playbook steps with audit log.

### Scene 6: Final report

Generate:

- Executive summary.
- ATT&CK mapping.
- Evidence table.
- Recommended remediation.

## 22. Recommended final project title

ResilienceGraph AI: ATT&CK-Aware Cyber Anomaly Detection and Response Simulation

Alternative titles:

- CyberSentinel AI
- APT Radar
- CriticalShield AI
- SOC Copilot for Critical Infrastructure
- SentinelGraph CNI

## 23. Final recommendation

PS7 is a strong choice if the team can explain cybersecurity clearly. It has good datasets and strong technical depth, but it is less instantly emotional than PS6. To win, the project must avoid being a generic anomaly detector.

The best PS7 build is:

1. Detect a multi-step attack chain.
2. Map each step to MITRE ATT&CK.
3. Show attack path to a critical asset.
4. Recommend safe response actions.
5. Prove improvement in detection lead time and alert triage.

If the team has no cyber domain confidence, PS6 is safer. If the team wants a technically serious SOC/graph/anomaly project and can present it well, PS7 can be very strong.

## 24. References

Official/local:

- ET AI Hackathon 2026 Problem Statements PDF in this repo: `6a38ce305640d_ET_AI_Hackathon_2026_Problem_Statements.pdf`
- Local analysis file: `ET_Hackathon_2026_Analysis.md`

Cybersecurity frameworks:

- MITRE ATT&CK official site: https://attack.mitre.org/
- MITRE ATT&CK Enterprise Matrix: https://attack.mitre.org/matrices/enterprise/
- MITRE ATT&CK Data and Tools: https://attack.mitre.org/resources/attack-data-and-tools/

India cyber context:

- CERT-In official site: https://www.cert-in.org.in/
- CERT-In advisories: https://www.cert-in.org.in/s2cMainServlet?pageid=PUBADVLIST
- Ministry of Electronics and IT: https://www.meity.gov.in/

Datasets:

- CIC-IDS2017, Canadian Institute for Cybersecurity: https://www.unb.ca/cic/datasets/ids-2017.html
- UNSW-NB15 dataset: https://research.unsw.edu.au/projects/unsw-nb15-dataset
- LANL Comprehensive Multi-Source Cyber-Security Events: https://csr.lanl.gov/data/cyber1/
- NSL-KDD: https://www.unb.ca/cic/datasets/nsl.html
- TON_IoT dataset: https://research.unsw.edu.au/projects/toniot-datasets
- BoT-IoT dataset: https://research.unsw.edu.au/projects/bot-iot-dataset

Tools and implementation references:

- scikit-learn anomaly detection: https://scikit-learn.org/stable/modules/outlier_detection.html
- PyTorch: https://pytorch.org/
- PyTorch Geometric: https://pytorch-geometric.readthedocs.io/
- NetworkX: https://networkx.org/documentation/stable/
- Streamlit: https://docs.streamlit.io/
- Elastic Security documentation: https://www.elastic.co/guide/en/security/current/index.html
- Sigma detection rules: https://sigmahq.io/
- Sigma GitHub repository: https://github.com/SigmaHQ/sigma

## 25. Papers

This section explains the research papers most relevant to PS7. These papers help justify the methods, the evaluation design, and the security framing for the final deck.

### 25.1 MITRE ATT&CK: State of the Art and Way Forward

Link: https://arxiv.org/abs/2308.14016

What the paper is about:

This paper surveys research that uses the MITRE ATT&CK framework. It reviews how ATT&CK has been used for threat modelling, detection, risk analysis, cyber threat intelligence, and security operations.

Why it matters for PS7:

PS7 explicitly asks for mapping attack progression to known frameworks. ATT&CK is the obvious framework. This paper helps explain that ATT&CK is not just a list of techniques; it is a shared language for detection, investigation, and response.

How to use it in our project:

- Use ATT&CK tactics/techniques as the explanation layer for alerts.
- Structure the incident timeline around ATT&CK stages.
- Mention that ATT&CK mapping improves communication between analysts, leadership, and responders.

Practical takeaway:

The dashboard should not only show "anomaly detected." It should show "Credential Access -> Lateral Movement -> Exfiltration risk" with supporting evidence.

### 25.2 SoK: The MITRE ATT&CK Framework in Research and Practice

Link: https://arxiv.org/abs/2304.07411

What the paper is about:

This systematization-of-knowledge paper studies how MITRE ATT&CK is used in research and industry. It discusses its strengths, limitations, use cases, and open challenges.

Why it matters for PS7:

It helps avoid shallow ATT&CK usage. Many demos simply paste an ATT&CK label on an alert. This paper supports a more careful approach: ATT&CK mapping must be evidence-based, auditable, and tied to actual telemetry.

How to use it in our project:

- Build a whitelist of ATT&CK techniques instead of letting an LLM invent mappings.
- Show evidence rows behind each tactic/technique.
- Use ATT&CK as an analyst aid, not as proof by itself.

Practical takeaway:

Use ATT&CK to organize the investigation story, but always connect the label to specific events.

### 25.3 Robust Anomaly Detection in Network Traffic: Evaluating Machine Learning Models on CICIDS2017

Link: https://arxiv.org/abs/2506.19877

What the paper is about:

This paper compares multiple anomaly/intrusion detection approaches on CICIDS2017, including supervised neural models and unsupervised approaches such as One-Class SVM and Local Outlier Factor. It emphasizes the difference between detecting known attacks and generalizing to unseen attacks.

Why it matters for PS7:

Critical infrastructure attacks may not match known signatures. The paper supports using anomaly detection and testing whether models generalize beyond known attack labels.

How to use it in our project:

- Use CICIDS2017 for model evaluation.
- Compare a simple baseline with an anomaly model.
- Show performance on known attack classes and a held-out/unseen attack scenario if possible.

Practical takeaway:

Do not only report high accuracy on a random train/test split. Also show detection lead time, false positives, and how the system behaves on attacks not directly seen during training.

### 25.4 UNSW-NB15 Computer Security Dataset: Analysis through Visualization

Link: https://arxiv.org/abs/2101.05067

What the paper is about:

This paper analyzes the UNSW-NB15 dataset using visualization and preprocessing methods. It identifies issues such as class imbalance and class overlap.

Why it matters for PS7:

Hackathon teams often train a classifier on a cybersecurity dataset and report impressive metrics without discussing dataset limitations. This paper reminds us that cyber datasets are messy and require careful preprocessing.

How to use it in our project:

- Discuss class imbalance in the dataset section.
- Use precision/recall/F1 and PR-AUC instead of only accuracy.
- Include preprocessing steps: encoding categorical variables, scaling, balancing, and removing leakage.

Practical takeaway:

If using UNSW-NB15, do not claim "99% accuracy" as the main result. Show realistic metrics and explain false positives.

### 25.5 Security Assessment Rating Framework for Enterprises using MITRE ATT&CK Matrix

Link: https://arxiv.org/abs/2108.06559

What the paper is about:

This paper proposes a security assessment/rating framework using the MITRE ATT&CK matrix. It uses ATT&CK coverage to create a structured risk view of an enterprise.

Why it matters for PS7:

PS7 is not only about detecting one attack. It is also about cyber resilience posture. A scorecard based on ATT&CK coverage can help executives understand which tactics are covered and which are weak.

How to use it in our project:

- Add a "MITRE coverage" dashboard panel.
- Show which tactics have detections and which are blind spots.
- Turn technical alerts into a risk posture score.

Practical takeaway:

Useful stretch feature: after the incident demo, show a resilience scorecard.

### 25.6 Your ATs to Ts: MITRE ATT&CK Attack Technique to P-SSCRM Task Mapping

Link: https://arxiv.org/abs/2507.18037

What the paper is about:

This paper maps MITRE ATT&CK techniques to proactive software supply chain risk management tasks. It focuses on connecting attack techniques to concrete defensive actions.

Why it matters for PS7:

PS7 requires response orchestration, not just detection. This paper is useful because it shows how technique mapping can lead to practical mitigation tasks.

How to use it in our project:

- Map each detected technique to a response playbook.
- Show recommended tasks such as patch, isolate, rotate credentials, review logs, or harden configuration.
- Keep response recommendations specific and actionable.

Practical takeaway:

Detection without action is incomplete. Use ATT&CK mapping to drive playbook recommendations.

### 25.7 Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization

Link: https://www.unb.ca/cic/datasets/ids-2017.html

What the paper is about:

This is the core paper behind CIC-IDS2017, listed by the Canadian Institute for Cybersecurity. It explains the dataset design, network environment, benign user profiles, attack execution, labels, and extracted network-flow features.

Why it matters for PS7:

If we use CIC-IDS2017, we need to understand what it actually contains. It includes benign traffic and attacks such as brute force, DoS, DDoS, web attacks, infiltration, botnet, Heartbleed, and port scans.

How to use it in our project:

- Cite it when describing dataset validity.
- Use its attack schedule to create a demo incident timeline.
- Use CICFlowMeter-style features for tabular intrusion detection.

Practical takeaway:

CIC-IDS2017 is good for measurable detection, but it is not enough for a full SOC story. Pair it with a simulated asset graph or LANL-style multi-source events.

### 25.8 Cybersecurity Data Sources for Dynamic Network Research

Link: https://csr.lanl.gov/data/cyber1/

What the paper is about:

This is the paper cited by the LANL Comprehensive Multi-Source Cyber-Security Events dataset. The dataset contains authentication events, process events, DNS lookups, network flows, and red-team events collected over 58 days.

Why it matters for PS7:

PS7 wants weak-signal correlation across heterogeneous logs. LANL is much closer to that than a simple network-flow-only dataset.

How to use it in our project:

- Use LANL structure as inspiration for multi-source event correlation.
- Build user-host authentication graphs.
- Detect lateral movement and abnormal user behavior.

Practical takeaway:

LANL is powerful but large. For a hackathon, use a subset or create a smaller synthetic LANL-like sample.

### 25.9 UNSW-NB15: A Comprehensive Data Set for Network Intrusion Detection Systems

Link: https://research.unsw.edu.au/projects/unsw-nb15-dataset

What the paper/dataset is about:

The UNSW-NB15 dataset was created in the UNSW Canberra Cyber Range Lab. It includes hybrid normal and attack traffic and attack categories such as Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode, and Worms.

Why it matters for PS7:

It is a useful second dataset for intrusion detection and for showing that the approach is not tied only to CIC-IDS2017.

How to use it in our project:

- Use it for model robustness testing if time permits.
- Use it to discuss class imbalance and attack-category classification.
- Compare model behavior across datasets.

Practical takeaway:

Use CIC-IDS2017 for fast MVP metrics; use UNSW-NB15 as stretch validation.
