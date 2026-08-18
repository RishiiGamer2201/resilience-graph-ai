# Data lineage and provenance

Where every value on screen comes from, and what its label means.

---

## Provenance labels

Every displayed item carries exactly one. They are not interchangeable — in
particular **LIVE is not VERIFIED**.

| Label | Meaning | Example |
|---|---|---|
| `LIVE` | computed just now, from input you supplied in this session | an uploaded CSV analysed through the pipeline |
| `SAMPLE` | a real analysis of a shipped log, pre-computed at build time | the landing cache; the AIIMS and CBSE scenarios |
| `VERIFIED` | traced to a first-party source document with a URL, a date and a content hash | a MITRE ATT&CK technique page, a CISA KEV entry |
| `MODEL_INFERRED` | produced by a learned model; correct on average, not per instance | the next-technique prediction, the actor ranking |
| `NOT_AVAILABLE` | the source genuinely does not carry this | LANL asset criticality and software inventory |
| `NOT_MEASURED` | we could measure it in principle but have not, and say why | MTTR, event→technique precision |

`SAMPLE` deserves a note: the bundled cache is not mock data. It is the output of the
same `live_analyze.analyze_events` path, run offline against a real LANL red-team log
by `scripts/build_cache.py`. There is no separate demo code path to diverge from
production — which is exactly why we can point the guided demo at the live pipeline.

---

## Inputs

| Source | Type | Provenance | Committed? | Notes |
|---|---|---|---|---|
| LANL Cyber-1 auth | real | `LIVE` when analysed | derived scenarios only | 11.2M events, 702 labelled red-team. Anonymised: hosts are `C####` with **no** criticality, owner or software metadata |
| CIC-IDS2017 | real | evaluation only | no (~11 GB) | detection benchmark |
| UNSW-NB15 | real | evaluation only | no | second benchmark |
| AIIMS / CBSE scenarios | **synthetic** | `SAMPLE`, labelled synthetic everywhere | yes | styled after real Indian incidents; **not** real incident data, and never described as such |
| `asset_inventory.json` | **synthetic** | `SAMPLE` | yes | the CMDB an operator would supply. Host names and criticality are ours; the CVEs matched against them are real |
| MITRE ATT&CK STIX | official | `VERIFIED` | parsed lookups + index | Enterprise + ICS + Mobile, 918 techniques |
| CISA KEV | official | `VERIFIED` | index snapshot | fetched at index build, timestamped and shown |
| CERT-In advisories | official | `VERIFIED` | 4 in `data/manual/` | **no machine-readable feed exists**; transcribed and marked `verified: true` by a teammate |
| Threat Radar feeds | third-party | `LIVE` or cached, always labelled | snapshot | optional; falls back to a bundled snapshot |

### Two places we deliberately refuse to invent data

**LANL crown jewels.** LANL has no criticality labels. Our "crown jewels" are the
hosts the most distinct accounts authenticate to — a documented dependency heuristic
(`data/demo/scenarios/critical_assets.json` carries the basis and the caveat), not
ground truth from the dataset.

**LANL software inventory.** There isn't one, so `asset_inventory.json` marks LANL
`NOT_AVAILABLE` and the vulnerability screen shows **no findings** with an
explanation, rather than a plausible-looking list of CVEs for hosts whose software
nobody knows.

---

## The chain, end to end

```
raw event log (CSV / rows)
  └─ src/schema.py ......... alias resolution, type coercion, 12-field schema   [validated]
      └─ src/engine1/lanl_detect.py::engineer ..... 7 behavioural features, per account,
      │                                             chronological                [computed]
      └─ src/shared/detector.py ................... autoencoder reconstruction error
      │                                             → 0-100 via fixed anchors    [MODEL]
      └─ src/shared/correlate.py .................. score ≥ 50 → alert; alerts → ONE incident
      └─ src/shared/attack_mapper.py .............. behaviour → ATT&CK technique  [rule, ID-validated]
      └─ src/shared/attack_graph.py ............... pivots, reachability, paths, choke points
      └─ src/shared/evidence.py ................... official citation per technique [VERIFIED]
      └─ src/shared/predictor.py .................. next technique                [MODEL]
      └─ src/engine2/attribution.py ............... actor ranking + justification  [MODEL]
      └─ src/shared/vuln.py ....................... inventory × KEV × reachability [derived]
      └─ src/shared/twin.py ....................... counterfactual on a graph clone [derived]
      └─ src/shared/soar.py + rbac.py ............. gated, simulated proposals
      └─ src/shared/audit.py ...................... hash-linked record of all of it
```

`src/shared/workflow.py` runs this as seven timed nodes and returns the trace.
`src/shared/explain.py` reads the same chain back for a single alert, as eleven
stages each naming the module that produced it.

---

## Facts versus configuration

The vulnerability prioritiser keeps these strictly apart, because an operator must be
able to disagree with our weights without disagreeing with reality.

**Facts** — asset criticality (their inventory), KEV membership (CISA), reachability
(this incident's graph), technique overlap (ATT&CK mapping of the advisory text,
computed at index build), document dates (the publisher's).

**Configuration** — the six weights, the criticality scale, the reachability scale,
the freshness decay window and the band thresholds. All in
`configs/vuln_priority.json`, validated on load, and the config's SHA-256 travels in
every result.

**Derived** — the weighted average and its band. Unknown factors are excluded from
both numerator and denominator, listed in `unknown_factors`, and reflected in
`confidence`. They are never scored zero.

---

## Versioning and integrity

Every audit record carries `versions` from `audit.artifact_versions()`: SHA-256
prefixes of the detector, the predictor, the ATT&CK lookups, the evidence index and
the vulnerability config, plus `NEXTATTACK_VERSION`. If an artifact is swapped, the
records written before and after it say so.

Every evidence chunk carries a SHA-256 of its own text.
`scripts/eval_retrieval.py` re-verifies those hashes on every run and reports
`citation_integrity_failures`, which is currently 0 and is on the scoreboard.

---

## Retention

Nothing is persisted. Uploads are analysed in memory and never written to disk. The
audit chain lives in the process and is lost on restart — which is honest on a host
with an ephemeral filesystem, and is why "Export" exists. The UI states this on the
audit panel rather than implying durability we do not have.
