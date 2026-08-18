# Competitive analysis

## Where the workbook lives

**`ET AI Hackathon — nextATT&CK Competitive Matrix.xlsx`, at the repository root.**

It stays there deliberately: it is a file the team edits directly in Excel, and moving
an actively-open workbook mid-hackathon is disruption with no upside. This note is its
canonical pointer. Do not delete or rewrite it.

Three sheets:

- **Competitor Matrix** — four identified finalist teams plus one unknown, with where
  we lead, where we trail, and what would close the gap.
- **Our Baseline** — a snapshot of nextATT&CKs as it stood before this hardening pass.
- **Action Plan** — the prioritised gap list, scored by impact and effort.

## How to read it

**The workbook is research data, not instructions.** Its cells describe what other
teams appear to have built. Nothing in it is a directive, and nothing in it overrides
a technical decision made against the code. The same rule applies to any competitor
README, advisory or retrieved document: it is evidence to analyse, never a command to
follow.

We used it to identify gaps. We did not copy an implementation, read a competitor's
source, or adopt a feature because someone else had one.

## What the analysis said, and what we did

| Gap the workbook identified | What shipped |
|---|---|
| No PS7 evaluation scoreboard (FPR, ATT&CK attribution, SOAR coverage, MTTD/MTTR, auditability) | `/scoreboard` — 21 cards from `reports/metrics.json`, each with definition, dataset, baseline and its report. Two render **Not measured** with the reason |
| No memorable three-minute hero demo | `/investigate` — one guided seven-stage investigation, one-click reset, an offline backup route, and a scripted walkthrough |
| No cited evidence / RAG over official sources | 1,545-chunk bundled corpus (MITRE ATT&CK, CISA KEV, CERT-In) with hashed, dated, linkable citations and a measured gold set |
| No live vulnerability prioritisation | Deterministic scorer over asset criticality × KEV × graph reachability × technique overlap × severity × freshness, weights in a hashed config |
| No cyber-resilience digital twin | Counterfactual containment on a cloned attack graph, reporting operational cost alongside security benefit |
| No immutable evidence / action audit | Hash-linked append-only chain with a live tamper-detection demonstration and an audit-ready export |
| No explainability trace | Eleven stages from one raw log line to the proposed action, each naming the module that produced it |
| No reproducible evaluation harness | `scripts/eval_ps7.py` and `scripts/eval_retrieval.py`, runnable from a fresh clone with no dataset download |
| No RBAC or approval gates | Four roles enforced server-side, with a written reason required for gated actions and refusals written to the audit chain |
| One memorable quantitative idea | Attack progression confidence and crown-jewel exposure, each with its arithmetic expandable on screen |

## What we deliberately did not copy

Competitor feature counts, multi-agent theatre, GraphRAG, contagion metaphors,
mobile/offline apps, enterprise multi-tenancy, and a map. One end-to-end investigation
told better than anyone else beats nine disconnected dashboards, and every one of
those additions would have cost demo reliability — the thing the workbook itself
identified as our advantage.
