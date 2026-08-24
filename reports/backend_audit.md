# Backend and pipeline audit

Audited on main at `3562682`, against a running instance with the Groq provider
enabled and the RAG vector store absent (the shipped deploy configuration).
19,432 lines of Python across `src/` and `api/`.

Every finding below was reproduced, not inferred. Reproduction is given inline.
Findings already disclosed somewhere in the repo are marked **[disclosed]** and
kept in the list anyway, because a reader auditing the backend should see them
in one place.

---

## P0 — What the pipeline reports about a uniform log

Two independent defects, both undisclosed. They are separable, and separating
them matters: my first pass conflated them and overstated the first.

### P0-1 · A uniform log always reports "1 alert, critical" — whatever it contains

The output is invariant to **volume** and to **content**:

```
uniform ATTACK, growing volume:
  10   NTLM failures A->B        alerts=1  sev=critical
  60   NTLM failures A->B        alerts=1  sev=critical
  200  NTLM failures A->B        alerts=1  sev=critical
  1000 NTLM failures A->B        alerts=1  sev=critical

uniform BENIGN, growing volume:
  10   identical Kerberos successes   alerts=1  sev=critical
  60   identical Kerberos successes   alerts=1  sev=critical
  200  identical Kerberos successes   alerts=1  sev=critical
  1000 identical Kerberos successes   alerts=1  sev=critical
```

A thousand failed NTLM logons against one host and ten ordinary Kerberos logons
produce **identical output**. The product cannot tell them apart, and calls both
critical.

**Mechanism.** In a log where every row is the same, only `new_dst_for_user` and
`new_src_for_user` vary, and only on the first row. Exactly one event therefore
has a distinct feature vector, so exactly one is an outlier, so the answer is
always one alert — scored 100 by `relative_anchors`, because the log's own p99
is the only thing it can be measured against.

The underlying calibration behaviour, in isolation:

```
all identical      p50=0.420 p99=0.420  max=  0.0  alerting= 0/60
59 same + 1 high   p50=0.420 p99=0.420  max=100.0  alerting= 1/60
spread             p50=1.050 p99=1.620  max=100.0  alerting=12/60
```

When `p50 == p99` the scale has collapsed: there is no distribution left to rank
against, so every event is either 0 or 100 and nothing in between is reachable.
`relative_anchors` is used precisely when the log is out of distribution, which
is precisely when it is unfamiliar or user-supplied.

**What I got wrong first time.** I initially reported this as "a brute force
produces zero alerts". That measurement was contaminated by P0-2 below: my test
log spelled the status `failure`, so `is_fail` never fired. With the correct
vocabulary the brute force does alert — once. The volume- and content-invariance
above is the real defect, and it is the sharper one.

**PARTIALLY FIXED.** Severity is now capped when `sample_confidence` is
`insufficient` (`live_analyze._cap_severity`), and the cap carries its reason on
the incident, so a twelve-row log reports `medium` with an explanation instead of
`critical` with none.

Residual, still open:

```
  10 identical failures -> alerts=1  sev=medium     (capped)
 200 identical failures -> alerts=1  sev=critical
1000 identical failures -> alerts=1  sev=critical
```

`alert_count` is still **1** for a thousand identical events. Severity now moves
with sample size, so the output is no longer fully invariant, but the count is.
The remaining fix is to refuse to score when `p50 == p99` and say so, rather
than emitting a confident 100 from a collapsed scale.

Only `insufficient` caps, not `low`. That is the detector's own distinction:
below `MIN_SAMPLE=30` "no corpus statistic means anything", while below
`RELIABLE_SAMPLE=300` it is "noisy, not absent". Capping `low` as well was tried
and reverted -- it downgraded both shipped 125-event scenarios from critical to
high on a sample the code itself calls usable, trading a real finding for a
caveat already printed beside it.

### P0-2 · `is_fail` and `is_ntlm` are exact string matches

`src/engine1/lanl_detect.py:57-58`

```python
df["is_fail"] = (df["status"].astype(str).str.lower() == "fail").astype("int8")
df["is_ntlm"] = (df["protocol"].astype(str).str.upper() == "NTLM").astype("int8")
```

The same 60-event brute force, changing **only** the spelling of the status:

```
60 failures, status='fail'      alerts=1  sev=critical  max=100
60 failures, status='failure'   alerts=0  sev=low       max=0
```

Measured across the vocabularies real logs use, 5 events each:

| `status` | `is_fail` fires |
|---|---|
| `fail`, `Fail`, `FAIL` | 5/5 |
| `failure`, `failed`, `Failure`, `denied`, `0`, `false` | **0/5** |

| `protocol` | `is_ntlm` fires |
|---|---|
| `NTLM`, `ntlm`, `Ntlm` | 5/5 |
| `NTLMv2`, `NTLM-v2` | **0/5** |

Every shipped scenario uses `fail`, so the demo is unaffected. **Upload your own
log is a shipped feature**, and a CSV that says `failure` silently loses two of
seven features — including the only one representing a failed authentication —
with no warning anywhere. `normalize.py` maps neither vocabulary.

`NTLMv2` is the worse half. The repo's own ablation puts the NTLM feature at
**74% of TPR@1%FPR (87.7% → 22.8%)**. A negotiated-package field reporting
`NTLMv2`, which is what Windows commonly logs, silently removes the single most
load-bearing feature in the detector.

**FIXED.** `FAIL_WORDS` is a frozenset covering the vocabularies real exports
use, and `is_ntlm` is now `startswith("NTLM")`. All 14 spellings measured above
fire correctly.

Still worth adding: a warning when any feature column resolves to a single
constant across the whole log. A feature that never varies should be reported,
not silently carried -- that is the general form of this bug and it would have
caught it without anyone knowing the vocabulary in advance.

Repro for both: `python3 reports/repro/uniform_scores.py`

---

## P1 — Authorisation, egress and input bounds

### P1-1 · 21 of 48 API routes make no authorisation call

Most are read-only cached GETs, which is defensible. Three are not:

- ~~**`POST /api/threat-radar`** — returned **200 with no role header**, and
  `refresh: true` triggers outbound fetches to CTI feeds.~~ **FIXED**: now on
  the stricter finalist principal, not `analyze_principal`, because an egress
  trigger should not inherit the demo-headers concession that exists for
  EventSource. 403 without a role, 200 with one.
- ~~**`POST /api/retrieve`**, **`POST /api/retrieve/incident`**~~ **FIXED**:
  both now require `read`.

The remaining 18 are read-only cached GETs.

```
$ curl -o /dev/null -w "%{http_code}" -XPOST localhost:8000/api/threat-radar \
    -H 'Content-Type: application/json' -d '{"refresh":false}'
200
```

### P1-2 · The RAG evidence signal is permanently 0 in the deployed image

`src/agents/validator.py:38-57` — two of the five confidence signals depend on
retrieval, and both swallow every exception into `0`:

```python
except Exception:
    return 0
```

`requirements-deploy.txt` deliberately excludes `chromadb` and
`sentence-transformers`. So in the shipped container `_rag_search` returns 0 for
every technique, and `_tag_confidence(len(signals))` scores confidence **out of
4 signals while presenting it as 5** — systematically depressed by up to 20%,
with nothing on screen saying so.

`return 0` also makes *"the store is not installed"* indistinguishable from
*"no evidence corroborates this technique"*. Those are different facts and the
second one is a finding.

```
$ curl -s localhost:8000/api/rag/status
{"ready":false,"note":"Run: python -m src.retrieval.ingest && ..."}
```

### P1-3 · Unbounded strings and integers on the retrieval models

`api/main.py:894-907`

```python
class RetrieveRequest(BaseModel):
    query: str            # no max_length
    top_k: int = 10       # no ge/le

class IncidentRetrieveRequest(BaseModel):
    technique_ids: list[str] = []   # no max_items
    incident_text: str = ""         # no max_length
    top_k: int = 15                 # no ge/le
```

**FIXED.** `query` is `max_length=4096`, `incident_text` is `max_length=8192`,
`technique_ids` is `max_length=64`, and both `top_k` are `ge=1, le=100`.
`top_k=999999999` now returns 422 instead of 200.

Contrast with `EventFeatures`, which main tightened correctly during the merge:
required fields, `ge`/`le` on all seven.

### P1-4 · No rate limiting anywhere

No limiter, no token bucket, nothing. `POST /api/analyze` runs a multi-second
CPU pipeline; `POST /api/agents/reason` makes up to fourteen provider calls and
spends third-party quota. Both are reachable by any caller with a header.

---

## P2 — Correctness and structure

### P2-1 · A shared library imports the API layer

`src/shared/enrich.py` reaches into `api.main` three times (lines 59, 82, 123).
That is backwards: `enrich` is a library, `api.main` is the deployment shim.
It is also why the call needs a bare `except Exception: pass` — the import is
circular-adjacent and cannot be allowed to fail.

### P2-2 · A silent `pass` hides a failed graph mapping

`src/shared/enrich.py:123-126`

```python
try:
    from api.main import _map_agent_bundle
    bundle = _map_agent_bundle(bundle, agent_summary)
except Exception:
    pass
```

If `_map_agent_bundle` raises, the bundle silently keeps the unmapped graph
while `meta.pipeline` still says `"standard+10-agent"`. The UI then shows the
standard graph and labels it as the agent-integrated one. No note, no flag.

This is the exact failure mode `src/shared/llm.py` warns about in its own
docstring: *"two silent excepts in this repo hid dead code for weeks."*

### P2-3 · Severity is not attenuated by sample confidence

The calibration block correctly reports `sample_confidence: "insufficient"`, and
the incident is still labelled **critical**:

| log | `sample_confidence` | severity |
|---|---|---|
| 12 self-authentications (A→A) | `insufficient` | **critical** |
| 30 identical benign successes | `low` | **critical** |

The caveat is computed and published; nothing consumes it. A severity derived
from a distribution the code has already declared too small to trust should be
capped, not printed at full confidence.

### P2-4 · The audit chain does not survive a restart **[disclosed]**

`src/shared/audit.py:239` — *"Process-wide session chain. Ephemeral by design
(free hosts have no disk)."* Honest, and measured:

```
records before restart: 8
records after restart:  1
```

The tension is that `scoreboard.py:367` publishes **"Audit tampering detected"**
as a capability. Tamper *detection* genuinely works; tamper-evident *retention*
does not exist. Those read as the same claim on the scoreboard and are not.

### P2-5 · Unsynchronised lazy singletons

`api/main.py` `_score_ref()` and `_markov()` both do check-then-set on a shared
`_state` dict with no lock. Sync handlers run in FastAPI's threadpool, so two
concurrent cold requests can both miss and both load — including a duplicate
`pickle.load` of the lookups file. Benign under the GIL (dict assignment is
atomic) but wasteful, and the pattern is a trap for the next person who stores
something non-atomic there. `audit.py` gets this right with `_chain_lock`.

### P2-6 · `_markov()` returns two permanent `None`s

```python
return None, _state["names"], None
```

Callers do `_, names, _ = _markov()`. The signature advertises a model and a
third value that never exist. Return the dict.

---

## P3 — Minor

- **No concurrency cap on six SSE endpoints.** Each holds a thread and a full
  analysis bundle for the life of the stream. Eight concurrent streams left the
  server responsive (health in 19 ms), so this is a capacity note rather than a
  DoS, but it is unbounded by construction.
- **`views.py:152`** caps `hosts` at 50 silently. Mitigated by an adjacent
  `hosts_reached: 129`, so the true count is available; the list truncation is
  not flagged.
- **`HEAD` on any SPA route returns 405.** `curl -I /` gives
  `405 Method Not Allowed`, which will confuse uptime probes that default to
  HEAD. This also invalidated my own first attempt at checking cache headers.

---

## What is already right, and worth not breaking

Recording this because an audit that lists only faults misrepresents the code.

- Upload bounds are enforced **before** parsing (413 at 64 MB, `api/main.py:418`).
- The four handlers that ran a synchronous multi-second pipeline are on
  `run_in_threadpool`; the SSE generators step through a threadpool too.
- Agent citations are filtered against tool output **in Python**, and the
  filter has already caught the model inventing `alert-001`/`alert-003`.
- The Critic defaults to `refuted` under uncertainty.
- `llm.py` is off unless explicitly enabled — a present key is not consent —
  and egress goes through the allowlisted fetcher with private-IP checks.
- A missing hashed asset returns a clean 404 rather than falling through to the
  SPA, so a stale tab fails legibly.
- `EventFeatures` requires and bounds all seven inputs, so an empty POST cannot
  score a fabricated all-default event.
- The clean-log false-positive rate (up to 48.2%) is measured, published in
  `reports/clean_log.md`, and pinned by a test that fails when it is fixed.

---

## Ranked fix order

| # | Finding | Cost |
|---|---|---|
| 1 | P0-2 vocabulary sets + warn on a constant feature column | ~1 hour |
| 2 | P0-1 refuse to score when `p50 == p99`, and say why | ~2 hours |
| 3 | P1-1 authorise the three unguarded POSTs | ~30 min |
| 4 | P1-3 `Field` bounds on the two retrieval models | ~15 min |
| 5 | P1-2 distinguish "retriever absent" from "no match", and disclose the signal count | ~1 hour |
| 6 | P2-3 cap severity when `sample_confidence` is `insufficient` | ~1 hour |
| 7 | P2-2 replace the silent `pass` with a recorded degradation | ~30 min |
| 8 | P2-1 invert the dependency: move `_map_agent_bundle` into `src/shared` | ~2 hours |
| 9 | P1-4 rate limit the analyze and agent endpoints | ~2 hours |

P0-1 and P0-2 are the two that change what the product detects. Everything else
changes how well it behaves.
