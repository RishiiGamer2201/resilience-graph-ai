# The three-minute demo

One scenario, one story, one decision. Do not tour the app.

**Primary route:** local container or local dev server — no network, no cold start.
**Backup route:** the recorded walkthrough (<https://youtu.be/vouw0dOcj2k>) plus the
offline steps at the foot of this page.

---

## Before you stand up (5 minutes, every time)

See [`../operations/runbook.md`](../operations/runbook.md) for the full checklist.
The short version:

1. `python -m uvicorn api.main:app --port 8000` and `cd frontend && npm run dev`
   (or one container on `:8000`).
2. Open `/api/readiness` — expect `"ready": true` and an empty `degraded_optional`.
3. Open `/investigate`, run the AIIMS scenario **once** to warm every import, then
   press **Reset demo**.
4. Set the role picker to **Analyst**. Set the theme to match the projector.
5. If demoing on Render, load the URL ~3 minutes early and let it wake.

---

## The 30-second hook

> Ten weak signals in an authentication log are not ten alerts. They are one attack.
> nextATT&CKs turns them into a single verified attack story: what the attacker did,
> what MITRE says they will do next, which crown jewel is exposed, which official
> advisory proves it, and which one containment action a human should approve — with
> the cost of that outage shown next to its benefit. No API keys, no cloud account,
> no model guessing at any number on the screen.

---

## The run (2 min 30 s)

### 0:00 — Set the stage (15 s)
**Investigation** screen, AIIMS-style hospital ransomware selected.

> A phished ward PC in a hospital. 125 authentications. The crown jewels are the
> patient database and the domain controller.

Press **Run investigation**.

### 0:15 — The seven stages (20 s)
The rail fills with real per-node timings; the whole thing lands in about a tenth of
a second.

> Seven bounded stages, not an agent loop. Understand, Plan, Evidence, Signals,
> Replan, Impact, Action. Each one is timed, and each one reports what it could
> **not** do. Notice stage five: the first evidence pass missed three techniques, so
> Replan re-ran retrieval once — exactly once, that limit is in the code.

### 0:35 — The two numbers (25 s)
Point at the headline pair.

> Attack progression confidence, and crown-jewel exposure.

Click **Show the arithmetic** on exposure.

> Not a vibe. Mean over each designated crown jewel of 100 × 0.9 to the power of
> hops minus one. PATIENT-DB-01 is one hop from the attacker's pivot, so it scores
> 100. Every term is on screen. You can check my arithmetic from your seat.

### 1:00 — Evidence (20 s)
Scroll to stage 3.

> Every ATT&CK conclusion carries an official citation: MITRE, CISA KEV or CERT-In.
> Publisher, the document's own date, when we retrieved it, the section, and a
> SHA-256 of the text we indexed. Click the title, you land on attack.mitre.org.
> Recall@5 on our gold query set is 0.857 — measured, and on the scoreboard.

### 1:20 — Impact and the counterfactual (40 s)
Scroll to stage 6, the digital twin.

> Now the responder's actual question. Isolate WARD-PC-013 —

Click **Simulate** on the top candidate.

> — and we clone the attack graph, remove that host and recompute reachability.
> Blast radius 28 → 8. DC-AIIMS-01 protected. And here is the part most tools skip:
> the cost. One host offline, 26 sessions severed, one account disrupted. In a
> hospital, that is a decision, not a free win. It also tells you the truth —
> PATIENT-DB-01 is *still* reachable, so one action is not enough.

Scroll to the vulnerability queue.

> Same estate, ranked by what matters here: asset criticality, whether CISA lists it
> as actively exploited, and whether the attacker can actually reach it in *this*
> graph. Expand one — every factor shows the fact behind it, and CVSS says
> **unknown**, because CISA KEV does not publish one and we would rather show a gap
> than a number we made up.

### 2:00 — The human gate (25 s)
Scroll to stage 7. Set the role picker to **Analyst** and press **Approve**.

> Refused. 403, from the server, not the UI — an analyst cannot approve an action
> that touches a crown jewel.

Switch to **Responder**, press **Approve** with no reason.

> Still refused. A gated action needs a written reason.

Type `Ward PC, out of hours, owner contacted`, approve.

> Recorded. Executed: **no**. Every action in this product is simulated. That is a
> design decision for critical national infrastructure, not a limitation we are
> apologising for.

### 2:25 — Prove it (20 s)
In the audit panel, press **Prove tamper-evidence**.

> The chain exports and verifies. We edit one record in the browser, send it back,
> and the server tells us exactly which record was altered. Tamper-**evident** — we
> detect it, we do not claim to prevent it, and we are not calling this a blockchain.

Press **Report** to download the audit-ready Markdown.

### 2:45 — Land it
> Weak signals, one verified story, a predicted next move, a costed containment, a
> human decision, and a hash-linked record. Running with no API key, no account and
> nothing that costs money. Every number is on the PS7 scoreboard with its baseline
> and the report that produced it — including the two we could not measure and say so.

---

## If you have 30 more seconds

Open **PS7 Scoreboard** and scroll to `Mean time to respond`.

> Not measured. We never execute an action, so there is no repair to time. We would
> rather show you an empty card than the headline number the brief asks for.

---

## Offline backup route

If the network or the host is unavailable:

1. `docker run --rm -p 8000:8000 nextattacks` on the laptop, open `localhost:8000`.
   Nothing in the primary route needs the internet.
2. If Docker is unavailable: the recorded walkthrough at <https://youtu.be/vouw0dOcj2k>.
3. If everything is unavailable: `reports/ps7_eval.md`, `reports/retrieval_eval.md`
   and `RESULTS.md` carry every number in this script, generated by scripts a judge
   can re-run.

## Do not do these on stage

- Do not press **Refresh** on the Threat Radar. It is the only thing that needs the
  internet, and it is not part of the story.
- Do not open the force graph on the full LANL campaign — 473 nodes looks like
  spaghetti on a projector. AIIMS at 31 hosts reads cleanly.
- Do not narrate the other seven screens. One investigation, told well.
