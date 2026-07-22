# nextATT&CKs — Demo Video Script (3 minutes)

> **For the speaker:** read slow. Take a small pause at each `/`. The numbers are
> your friends, say them clearly. Practise the numbers out loud a few times first.
>
> **Format:** **[SHOW]** = what is on the screen · **SAY** = what you speak.
>
> Total speaking time is about 2 minutes 50 seconds, which leaves room for the
> screen to load between clicks.

---

## 0:00 – 0:20 · The problem

**[SHOW]** Login / home screen.

**SAY:**
"Hi. This is nextATT&CKs.
An attacker steals one password. / Then they log in, machine by machine. / Every login looks normal.
So they stay hidden for about ten days.
Old tools show thousands of alerts. / But not the attack."

---

## 0:20 – 0:35 · The idea

**[SHOW]** Click **Analyze Log**.

**SAY:**
"We do it differently.
We read the normal login logs a company already has. / And we find the story hidden inside them.
Let me show you. This is real red-team attack data."

---

## 0:35 – 1:20 · Live analysis (the core)

**[SHOW]** Pick the LANL campaign scenario, click Analyze. Wait for it to load. Point at the **LIVE ANALYSIS** badge.

**SAY:**
"This is running live, right now. / Not a video, not fake.
It scored two thousand seven hundred events. / It found one thousand two hundred alerts.
And here is the important part / it joined them into just **one** incident.
One attack. Not a thousand alarms."

**[SHOW]** Open the incident / overview. Point at 104 accounts.

**SAY:**
"The attacker used one hundred four accounts. / We see all of them together."

---

## 1:20 – 2:00 · The attack graph (your strongest moment)

**[SHOW]** Go to **Attack Graph**. Let the graph draw. Click host **C17693**.

**SAY:**
"This is the attack map. / Four hundred seventy three machines.
This one machine, C17693, / ran almost the whole attack.
Now watch this.
If we isolate this one machine, / we cut off four hundred sixty three machines.
One click. / Most of the attack, gone."

*(Pause here. Let it sit. This is the wow moment.)*

---

## 2:00 – 2:35 · Predict, attribute, outside world

**[SHOW]** Go to **Threat Intel & Attribution**. Point at next-technique prediction, then the ranked actor.

**SAY:**
"The system also looks ahead.
It predicts the attacker's next move, / with a real number.
It names the likely attacker group, / and it shows why.
And on Threat Radar, / we match outside threats to your own attack. India first."

---

## 2:35 – 2:55 · Honesty (judges love this)

**[SHOW]** Go to **Models & Metrics**. Point at the LANL card.

**SAY:**
"And we are honest.
This detects real attacks / score zero point nine nine two.
It catches six hundred sixteen out of seven hundred two attacks.
Every number here is real. / Nothing is faked.
Where something is only a demo, / we say so on the screen."

---

## 2:55 – 3:00 · Close

**[SHOW]** Back to the graph or home screen.

**SAY:**
"The logs already know an attack is happening.
We built the layer that listens.
Thank you."

---

## Tips for speaking

- **Practise these numbers out loud:** "zero point nine nine two", "four hundred sixty three", "six hundred sixteen out of seven hundred two". Say each one five times.
- If a sentence feels hard, **cut it.** Every line here can be shorter.
- Record in **short clips**, one section at a time. Join them later. Do not try one long take.
- Slightly **slow** always sounds more confident than fast.
- If you stumble: **stop, breathe, redo that one line.** Nobody sees the retakes.

---

## The numbers, for quick reference

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
