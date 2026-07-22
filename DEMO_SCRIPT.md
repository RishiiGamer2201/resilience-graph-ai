# nextATT&CKs — Demo Video Script (full feature walkthrough)

> **For the speaker:** read slow. Take a small pause at each `/`. Say the numbers
> clearly, they carry the demo. Practise the numbers out loud a few times first.
>
> **Format:** **[SHOW]** = what is on the screen · **SAY** = what you speak ·
> **(feature)** = the feature you are showing, so nothing is missed.
>
> **Length:** about **4 minutes 30 seconds**. This version shows **every** feature.
> Sections marked **(core)** are the must-keep ones if you ever need a 3-minute cut.
>
> **Order** follows the sidebar top to bottom, so it is easy to follow while recording.

---

## 0:00 – 0:20 · Intro + the problem **(core)**

**[SHOW]** Login screen. Point at the name **nextATT&CKs** and **SOC Command Center**.

**SAY:**
"Hi. This is nextATT&CKs.
An attacker steals one password. / Then they log in, machine by machine. / Every login looks normal.
So they hide for about ten days.
Old tools show thousands of alerts. / But not the attack.
We fix that. Let me show you."

---

## 0:20 – 0:55 · Analyze Log **(core)**

**[SHOW]** Click **Analyze Log**. Show the scenario list. Point at the **Upload CSV** button. Pick the **LANL campaign** scenario. Click Analyze. Point at the **LIVE ANALYSIS** badge on top.

**SAY:**
"First, Analyze Log.
You can pick a ready attack, / or upload your own log file as a CSV. *(feature: analyze any log + CSV upload)*
The whole app then runs on your data.
I pick the real red-team attack. / And I click Analyze.
See this badge on top / it says LIVE ANALYSIS. *(feature: LIVE / SAMPLE badge)*
That means everything you see now / is computed right now. Not fake.
It scored two thousand seven hundred events. / It found one thousand two hundred alerts. / And joined them into just **one** incident."

---

## 0:55 – 1:20 · Overview

**[SHOW]** Click **Overview**. Point at the time-to-detect number, the active incident, and the detector benchmark cards.

**SAY:**
"This is the Overview. / A quick summary.
Here is the time to the first alert, / measured from the log itself. *(feature: measured MTTD)*
Here is the active incident. / One attack, one story.
And here are our model scores, / from honest testing. *(feature: detector benchmarks)*"

---

## 1:20 – 1:50 · Attackers (campaign view + drill-down)

**[SHOW]** Click **Attackers**. Show the long list. Say the count. Then click **one account** to open its own incident.

**SAY:**
"Now, Attackers.
The attacker used one hundred four accounts. / We show all of them together, as one campaign. *(feature: campaign view)*
Not one victim. The whole picture.
And I can open any single account / to see only its own attack, its own graph, its own report. *(feature: per-account drill-down)*"

---

## 1:50 – 2:30 · Live Incident (replay + live scoring + report + gated SOAR)

**[SHOW]** Click **Live Incident**. Press the **replay / stream** button so events appear one by one. Then point at the **Live event scoring** card and score one event. Then scroll to the **incident report** and its **Download / Print** buttons, and the **Recommended response (simulated, gated)** part.

**SAY:**
"This is the Live Incident.
I can replay the attack, / event by event, live. *(feature: event-by-event replay, live stream)*
Watch the scores come in.
Here I can also score one single event by hand. *(feature: live event scoring)*
The model gives it a danger score, from zero to one hundred.
Below is a full report. / I can download it or print it, for records. *(feature: audit-ready report)*
And here are the response steps. / But see the label / it says simulated and human-gated. *(feature: gated SOAR)*
We never touch a real network. / A human must approve. We are honest about that."

---

## 2:30 – 3:10 · Attack Graph **(core — your strongest moment)**

**[SHOW]** Click **Attack Graph**. Let it draw. Click host **C17693**. Point at the blast-radius / recommended-isolation panel.

**SAY:**
"This is the attack map. / Four hundred seventy three machines. *(feature: attack-path graph)*
I click any machine to see everything it did.
Four machines were the attacker's base. *(feature: all pivots)*
This one, C17693, / ran almost the whole attack.
Now watch this.
If we isolate this one machine, / we cut off four hundred sixty three machines. *(feature: blast radius + recommended isolation)*
One click. / Most of the attack, gone."

*(Pause here. Let it sit.)*

---

## 3:10 – 3:40 · Threat Intel & Attribution

**[SHOW]** Click **Threat Intel & Attribution**. Point at the mapped ATT&CK techniques, then the **Predict next technique** widget, then the ranked **Actor attribution** list.

**SAY:**
"Next, Threat Intel.
Every action is mapped to the MITRE ATT&CK standard. / Real technique IDs, never made up. *(feature: ATT&CK mapping)*
The system predicts the attacker's next move, / with a real number. *(feature: next-technique prediction)*
And it names the likely attacker group, / and shows why it thinks so. *(feature: actor attribution)*
You can check the reason. It is not a black box."

---

## 3:40 – 4:00 · Threat Radar

**[SHOW]** Click **Threat Radar**. Show the feed items, India-first. Point at one item matched to your incident.

**SAY:**
"This is Threat Radar.
It reads real threat news from the outside world. / India first. *(feature: India-first external CTI)*
And it matches that news / to your own attack. *(feature: cross-reference to your incident)*
So you see where you are exposed, right now."

---

## 4:00 – 4:20 · Models & Metrics + Data & Methodology (honesty) **(core)**

**[SHOW]** Click **Models & Metrics**. Point at the LANL card (0.992, 616/702). Then click **Data & Methodology**.

**SAY:**
"And we are honest.
Our detector scores zero point nine nine two. *(feature: models & metrics)*
It catches six hundred sixteen out of seven hundred two real attacks.
Every number here is real.
And in Data and Methodology / we list our data, our honest limits, / and our India examples like AIIMS and CBSE. *(feature: data & methodology, India scenarios)*
Where a thing is only a demo, / we say so on the screen."

---

## 4:20 – 4:30 · Close **(core)**

**[SHOW]** Back to the Attack Graph or the home screen.

**SAY:**
"The logs already know an attack is happening.
nextATT&CKs is the layer that listens.
Thank you."

---

## Feature coverage checklist (tick while recording)

Every feature in the product, and the section that shows it:

- [ ] LIVE / SAMPLE badge — *Intro / Analyze Log*
- [ ] Analyze any log (pick scenario) — *Analyze Log*
- [ ] Upload your own CSV — *Analyze Log*
- [ ] Score every event → 1 incident — *Analyze Log*
- [ ] Measured time-to-detect (MTTD) — *Overview*
- [ ] Active incident summary — *Overview*
- [ ] Detector benchmarks — *Overview*
- [ ] Campaign view (104 accounts) — *Attackers*
- [ ] Per-account drill-down — *Attackers*
- [ ] Event-by-event live replay (SSE stream) — *Live Incident*
- [ ] Live single-event scoring — *Live Incident*
- [ ] Audit-ready report (download / print) — *Live Incident*
- [ ] Gated SOAR (simulated, human-approved) — *Live Incident*
- [ ] Attack-path graph + click a host — *Attack Graph*
- [ ] All 4 attacker pivots — *Attack Graph*
- [ ] Blast radius + recommended isolation (cut 463) — *Attack Graph*
- [ ] ATT&CK technique mapping — *Threat Intel*
- [ ] Next-technique prediction — *Threat Intel*
- [ ] Actor attribution (ranked, explainable) — *Threat Intel*
- [ ] Threat Radar (India-first CTI, cross-referenced) — *Threat Radar*
- [ ] Models & Metrics (honest scores) — *Models & Metrics*
- [ ] Data & Methodology + India scenarios (AIIMS, CBSE) — *Data & Methodology*

That is all **9 sidebar screens** and every feature inside them.

---

## Tips for speaking

- **Practise these numbers out loud:** "zero point nine nine two", "four hundred sixty three", "six hundred sixteen out of seven hundred two". Say each one five times.
- If a sentence feels hard, **cut it.** Every line here can be shorter.
- Record in **short clips**, one section at a time. Join them later. Do not try one long take.
- Slightly **slow** always sounds more confident than fast.
- If you stumble: **stop, breathe, redo that one line.** Nobody sees the retakes.
- If you need a **3-minute cut**, keep only the sections marked **(core)**: Intro,
  Analyze Log, Attack Graph, Models & Metrics, Close.

---

## The numbers, for quick reference (all current & verified)

| What | Number |
|---|---|
| Events analysed | 2,732 |
| Alerts | 1,243 |
| Incidents | 1 |
| Compromised accounts | 104 |
| Machines in the graph | 473 |
| Attacker foothold machines | 4 |
| Isolate C17693, machines cut | 463 |
| Detection score (ROC-AUC) | 0.992 |
| Attacks caught at 1% false alarms | 616 of 702 |
| Threat groups ranked for attribution | 172 |
