# Likely judge questions, and defensible answers

Every answer here is checkable in the repo. Where the honest answer is "we did not
measure that", it says so — that is the strongest answer available, not the weakest.

---

## On the detection

**"What is your accuracy?"**
We do not report accuracy, and we would not trust a system that did. LANL red-team
prevalence is 0.006% — a model that says "benign" every time scores 99.994%. We
report ROC-AUC 0.992, and more importantly TPR at a fixed 1% false-positive rate:
**87.7%**, 616 of 702 real red-team events, at the operating point an analyst can
actually staff. The IsolationForest we replaced caught 361 at the same point.
*Scoreboard → Detection. `reports/lanl_redteam_detection.md`.*

**"Isn't this just detecting NTLM?"**
Substantially, yes, and that is the honest answer. 100% of the red-team logins
used NTLM against about 6% of benign, so it is a powerful signal and a trivially
evadable one: the attacker switches to Kerberos. We ablated it. ROC-AUC barely
moves, **0.992 to 0.906**, and for a while we quoted only that and said NTLM was
"not a crutch". That was the wrong metric to quote. At the 1% false-positive
operating point an analyst actually runs at, recall goes **87.7% to 22.8%**, a
74% relative collapse. ROC-AUC integrates over every threshold including ones
nobody would use, which is exactly why it hid this.

So: the behavioural features alone are a much weaker detector than our headline
suggests, and the fix is more signal rather than better framing. Kerberos
service-ticket behaviour, process telemetry and flow records are the next
features, and the LANL corpus ships all three, we simply have not used them yet.
Both numbers are now in `RESULTS.md`; `src/engine1/lanl_detect.py` emits the
ablated operating point alongside the ROC so the pair cannot be separated again.
*`reports/lanl_redteam_detection.md`.*

**"Did you train on the attack labels?"**
No. Engine 1 is trained on benign traffic only; labels are used for evaluation and
never for training. That is why resampling and SMOTE are not applicable here by
design, and why the model transfers to a log it has never seen.

**"Is it just a big model?"**
The shipped detector is an autoencoder trained offline in PyTorch and **exported to
NumPy weight matrices** — 5 KB. The deployed container has no deep-learning
framework and no GPU. Inference is a few matrix multiplies.

---

## On the AI claims

**"Where is the LLM?"**
There isn't one, and that is deliberate. `/api/capabilities` reports
`llm.provider: "none"`. Every score, ranking, gate, path and hash is deterministic
Python over typed inputs. An LLM could reword an explanation behind the
`ExplanationProvider` interface; it would be labelled non-authoritative and it would
never calculate a number or approve an action.

**"Then what is the AI?"**
Three learned components, each measured against a baseline: an unsupervised
benign-trained autoencoder for detection; an interpolated Markov model over 205 real
attack sequences for next-technique prediction (top-3 **38.1%** against a
kill-chain-order baseline of **7.1%** — 5.4×); and MiniLM embeddings for actor
attribution by transparent profile retrieval. The orchestration around them is
deliberately not AI, because a security decision should be reproducible.

**"Why does the kill-chain baseline matter?"**
Anti-circularity. Our sequences are tactic-ordered, so a model could score well by
re-learning that ordering rather than learning anything about attacks. We built the
baseline specifically to catch ourselves cheating. Beating it 5.4× is evidence of
real technique-to-technique transitions. We also publish the harder, non-circular
test: on four analyst-verified CERT-In sequences in the order the advisories
actually report, top-3 drops to **10%**. We publish it *because* it is worse.

**"Is the attribution a classifier?"**
No, and we say so on the screen. It is weighted retrieval over 172 public MITRE
group profiles with a printed justification. We deliberately never headline a
"100% attribution" number — that eval is near-trivial by construction, and the
scoreboard lists that claim among the ones we refuse to make.

---

## On the evidence layer

**"Is this RAG, or just a search box?"**
It is retrieval with citations, and we measured it rather than naming it: recall@1
0.643, recall@5 **0.857**, MRR 0.717, zero citation-integrity failures, over a
14-query hand-written gold set against 1,545 official chunks. The per-query results,
including every miss, are in `reports/retrieval_eval.md`.

**"Why no vector database?"**
Measured trade-off, written up in ADR 0003. At 1,545 chunks the queries are
identifier-shaped — an analyst investigating T1550.002 wants the T1550.002 page —
and exact-ID matching wins that every time. A vector store would add a managed
service that pauses after a week of inactivity, or an embedding model in an image
we keep at nine packages. It would not add one field of provenance, which is the
part that actually makes a citation useful.

**"How do I know a citation is real?"**
Click it — it opens attack.mitre.org, nvd.nist.gov or cert-in.org.in. Each card
shows publisher, authority tier, section, the document's own date, our retrieval
time, the extraction method and a SHA-256 of the indexed text. The retrieval
evaluator re-verifies every hash on every run.

**"What if an advisory contains a prompt injection?"**
Then it does nothing, because there is no LLM to inject into. Structurally,
retrieved text is data and never reaches an agent control message. For display we
neutralise instruction-shaped text; there are parametrised tests for the usual
payloads.

---

## On the response and governance

**"Does it actually contain anything?"**
No. Every action is simulated, and the scoreboard has a card whose measured value is
**zero actions executed against real systems**. For critical national infrastructure
that is the right default: an AI that can isolate a hospital domain controller on its
own is a new attack surface, not a defence.

**"So the human gate is just a disabled button?"**
Switch the role picker to Analyst and press Approve. You get a 403 from the API. Try
as Responder with an empty reason: 422. The UI is not the control —
`rbac.require()` runs on every mutating endpoint, and the refusal is itself written
to the audit chain as `action.denied`.

**"Is the audit chain a blockchain?"**
No, and the export says so in its own `claim` field. It is a hash-linked append-only
log: each record's SHA-256 covers the record and the previous hash, over a documented
canonical serialisation. Press "Prove tamper-evidence" — we export it, edit one
record in your browser, send it back, and the server names the altered record.
Tamper-**evident**, not tamper-proof. It is session-scoped and in memory, because the
free host has an ephemeral filesystem and we will not imply persistence we do not have.

**"What is the counterfactual actually doing?"**
Cloning the incident's attack graph, removing the candidate host, and recomputing
reachability, crown-jewel exposure and choke points with NetworkX. No model, no
randomness — run it twice, get identical output. And it reports the **cost** next to
the benefit: hosts offline, sessions severed, accounts disrupted. It will also tell
you an action is not worth the outage, and that a crown jewel is still reachable
afterwards.

---

## On the metrics

**"What is your MTTR improvement?"**
Not measured, and the card says so on the scoreboard. We never execute a response, so
there is no repair to time. Reporting an MTTR here would mean fabricating the exact
number the brief asks for. MTTD we do measure — from each log's own timestamps, first
event to first correlated alert — and the industry dwell-time comparison is labelled
as a Mandiant citation, not our measurement.

**"Your ATT&CK mapping coverage is 100%. Is that precision?"**
No, and we separate them deliberately. 100% is *coverage* — every correlated alert
carries a technique — plus 100% *ID validity*, meaning every emitted ID exists in the
parsed ATT&CK STIX, which is how you would catch a hallucinated technique.
Event-to-technique **precision** is on the board as **Not measured**, because no
public dataset we use labels individual events with an ATT&CK technique.

**"How do I know the numbers on screen match the reports?"**
Because they are the same file. The eval scripts write `reports/metrics.json`; the
scoreboard and the UI scorecard read it. There is a test that fails if they diverge —
and it exists because they *had* diverged: the UI claimed LANL ROC 0.988 (an
IsolationForest we no longer ship) against a measured 0.992. `scripts/audit_stale.py`
fails the build if any document cites an out-of-date number.

---

## On the engineering

**"Will this scale?"**
Measured at nine input sizes: 2,732 events in 0.131 s, 50,000 in 2.19 s, on a laptop
CPU with no GPU. The full seven-node investigation is 51 ms p50, 224 ms p95.
In-memory graph analytics are comfortable to about 50,000 events per analysis — that
is the documented cap, enforced at the trust boundary — and beyond it we shard or move
to a graph database behind the existing repository boundary.

**"What does it cost to run?"**
Zero. No API key, no account, no credit card, no database. Nine Python packages, no
torch, no GPU. It runs offline from a fresh clone. The full ledger, including every
optional component and what happens when it is absent, is in
`docs/operations/cost-and-limits.md` with dated sources.

**"What happens if the internet drops mid-demo?"**
Nothing. There is a test that disables outbound HTTP entirely and asserts the whole
investigation still completes with citations. The only feature that needs the network
is the Threat Radar refresh, and it falls back to a timestamped bundled snapshot
labelled `cache`.

**"Your detector flags an unusual login. How do you know that is an attacker?"**
We do not, and the screen says so. That produces a `T1078 Valid Accounts` claim
with status **inferred**, confidence 0.19, marked **not actionable**, listing what
would settle it (endpoint process telemetry, device management state, MFA result)
and the benign explanations we have not excluded (role change, travel,
maintenance, new device enrollment). An anomaly establishes that behaviour is
unusual for an account; T1078 additionally asserts adversarial use of a
legitimate account, and an authentication log cannot tell those apart. A maximum
anomaly score still cannot make that claim actionable, because the ceiling is the
rule's strength rather than the detector's certainty.

**"Why four numbers instead of one risk score?"**
Because they disagree, and the disagreement is the useful part. On the AIIMS
scenario: anomaly 79, likelihood 53, impact 100, evidence confidence 64. A single
blended score would read "moderate" and hide that the impact is critical while
the evidence is only moderate. The summary line is the one an analyst reads:
"likelihood moderate, impact critical, confidence moderate; strongest missing
evidence is whether the destination is in this account's normal scope of work."

**"If two of your detectors agree, is the finding twice as likely?"**
No, and the arithmetic prevents it. Confidence is noisy-OR across *independence
groups*. The ATT&CK rule fires because of the detector's own features, so they
share a group and cannot corroborate each other — ten copies of one signal give
exactly the confidence of one. Independent telemetry would be a second group and
would genuinely raise it. That is the guard against a system talking itself into
certainty by repetition.

**"You have two pipelines. Which one is right?"**
The workflow is authoritative; the ten-agent lane is a cross-check. They are built
differently on purpose — the workflow takes severity from the peak calibrated
anomaly score, the agent lane from a prioritiser's risk band over ranked attack
chains — so when they agree, that is corroboration from a different method rather
than the same signal counted twice. On the AIIMS scenario they read *high* and
*medium*: adjacent, sharing T1021, which the system scores as "partially
corroborates" and which lifts evidence confidence from 63.5 to 73.4. If they
differed by two severity bands it would read *contradicts*, contribute nothing,
and the disagreement would be on screen.

**"Isn't agreeing with yourself just double-counting?"**
It would be, and the cap exists for exactly that reason. The two lanes read the
same log and share the same ATT&CK rule table, so they are a second opinion, not
a second sensor. Corroboration between them is capped at 0.45, the shared
components are listed in every result, and a degraded agent lane halves its own
contribution. Genuinely independent telemetry — endpoint process data rather than
the same authentication log — would justify raising that cap, and that is written
into the ADR as what would change our mind.

**"Is that a digital twin?"
It is a **counterfactual containment twin** and we call it that on the screen. It
clones the attack graph, removes a candidate host and recomputes reachability. A
full cyber-resilience twin would also carry synchronised asset, identity,
dependency and control state, expected behaviour per operating mode, and for OT a
validated process model with uncertainty. Renaming more graph analytics "digital
twin" would be the easy and dishonest way to claim that.

**"What is the weakest part?"
Three things, in order. One: the retriever is lexical, so a fully paraphrased query
with no shared vocabulary misses — measured, published, with the upgrade path written
down. Two: default authorisation is role-declaration without authentication, which is
right for a keyless demo and wrong for production; bearer tokens are one environment
variable away. Three: there is no rate limiting, so a free-tier deployment could be
exhausted by a flood. All three are in `docs/security/threat-model.md` under
"residual".
