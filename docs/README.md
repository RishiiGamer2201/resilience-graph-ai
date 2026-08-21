# Documentation index

Start at the root [`README.md`](../README.md) to run the thing. This is the map of
everything else.

## Read these three first

| If you are | Read |
|---|---|
| Presenting it | [demo/three-minute-script.md](demo/three-minute-script.md) then [demo/judge-qa.md](demo/judge-qa.md) |
| Judging it | [evaluation/methodology.md](evaluation/methodology.md) and the PS7 Scoreboard screen |
| Reviewing the engineering | [architecture/adr/](architecture/adr/) then [security/threat-model.md](security/threat-model.md) |

## By area

### Product
- [product/data-lineage.md](product/data-lineage.md) — provenance labels, where every
  value comes from, facts vs configuration, and the two places we refuse to invent data
- [../prd.md](../prd.md) — what we are building, users, features *(root)*

### Architecture and decisions
- [architecture/adr/0001-networkx-and-single-container.md](architecture/adr/0001-networkx-and-single-container.md)
  — why NetworkX stays required and Neo4j does not
- [architecture/adr/0002-hand-rolled-workflow.md](architecture/adr/0002-hand-rolled-workflow.md)
  — why the seven-node graph is plain Python and not LangGraph
- [architecture/adr/0003-lexical-evidence-index.md](architecture/adr/0003-lexical-evidence-index.md)
  — why a bundled BM25 index beats a vector database at this corpus size
- [architecture/adr/0004-frontend-stays-as-is.md](architecture/adr/0004-frontend-stays-as-is.md)
  — why no TypeScript migration, no Tailwind, no shadcn, no map
- [architecture/adr/0005-semantic-retrieval-supersedes-0003.md](architecture/adr/0005-semantic-retrieval-supersedes-0003.md)
  — the measurement that overturned ADR 0003: semantic retrieval leads, lexical
  becomes the fallback
- [architecture/adr/0006-evidence-calibrated-claims.md](architecture/adr/0006-evidence-calibrated-claims.md)
  — ATT&CK conclusions become claims with status, missing evidence and benign
  alternatives; the single attack score splits into four numbers
- [architecture/adr/0007-two-pipelines-one-authority.md](architecture/adr/0007-two-pipelines-one-authority.md)
  — two analysis lanes, one authority: the 10-agent pipeline becomes a
  partially-independent cross-check rather than a competing verdict
- [../architecture.md](../architecture.md) — full system architecture, folder tree,
  tech stack *(root)*
- [../design.md](../design.md) — design tokens, palette, components *(root)*

### Evaluation
- [evaluation/methodology.md](evaluation/methodology.md) — how every number is
  produced, every baseline, and what we deliberately do not measure
- [../RESULTS.md](../RESULTS.md) — the consolidated results sheet *(root, generated)*
- `../reports/` — the generated evidence each script writes

### Security
- [security/threat-model.md](security/threat-model.md) — assets, trust boundaries,
  nine threats with the control, the test, and the honest residual risk
- [../SECURITY.md](../SECURITY.md) — reporting and scope *(root)*

### Operations
- [operations/cost-and-limits.md](operations/cost-and-limits.md) — the zero-cost
  ledger: required vs optional, quotas, sleep behaviour, licences
- [operations/runbook.md](operations/runbook.md) — warm-up checklist, degraded
  states, rebuild commands, troubleshooting

### Research
- [../research/codex/it_ot_attack_detection_digital_twin_research.md](../research/codex/it_ot_attack_detection_digital_twin_research.md)
  — the IT/OT deep research this claim model implements (§6 claim vocabulary,
  §7 four numbers, §15 the T1078 correctness risk)
- [research/free-tier-and-stack.md](research/free-tier-and-stack.md) — primary-source
  provider facts with URLs and access dates. **Nothing says "free forever."**
- `../research/claude/` and `../research/codex/` — earlier build specs and plans *(root)*

### Demo and pitch
- [demo/three-minute-script.md](demo/three-minute-script.md) — click-by-click, with
  the 30-second hook and the offline backup route
- [demo/judge-qa.md](demo/judge-qa.md) — likely questions and defensible answers
- [../DEMO_SCRIPT.md](../DEMO_SCRIPT.md), [../PITCH_DECK.md](../PITCH_DECK.md),
  [../EXPLAINER.md](../EXPLAINER.md), [../BRIEF.md](../BRIEF.md) — the earlier
  narrative set *(root)*

### Competition
- [competition/README.md](competition/README.md) — where the competitive matrix lives
  and how to read it

---

## Why some documents are still at the repository root

`README.md`, `architecture.md`, `rules.md`, `prd.md`, `phases.md`, `design.md`,
`memory.md`, `RESULTS.md`, `BRIEF.md`, `EXPLAINER.md`, `PITCH_DECK.md`,
`DEMO_SCRIPT.md` and the competitive workbook stay where they are.

They are referenced from between 2 and 9 other files each — including
`scripts/make_submission_doc.py`, which generates the submission deliverable, and
`scripts/audit_stale.py`, which enforces metric freshness. Moving them mid-hardening
would mean rewriting those link maps for no judge-visible benefit and a real chance of
breaking the submission generator. This index is the map instead; new documentation
goes under `docs/`.
