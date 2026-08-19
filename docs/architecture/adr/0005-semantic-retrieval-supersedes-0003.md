# ADR 0005 — Semantic retrieval leads; lexical becomes the fallback

- **Status:** accepted
- **Date:** 2026-08-19
- **Supersedes:** the retriever choice in
  [ADR 0003](0003-lexical-evidence-index.md). The provenance, artifact and
  offline requirements from 0003 still stand.

## What 0003 claimed, and why it was wrong

ADR 0003 chose a bundled BM25 index over an embedding retriever, and justified it
like this:

> At this corpus size the retrieval bottleneck is not semantics, it is
> identifiers. […] A vector store would not add one field to it.

That was an argument, not a measurement. A teammate then built the embedding
retriever anyway (`feature/rag-retrieval-system`), which forced the comparison,
and the comparison went against 0003.

## The measurement

Same 10 gold queries, same scoring, `reports/retrieval_compare.md`, reproducible
with `python -m scripts.eval_retrieval_compare`. Queries answerable only from the
bundled index (the four analyst-verified CERT-In advisories) are excluded from
both sides rather than counted against the corpus that lacks them.

| Retriever | Corpus | Recall@1 | Recall@5 | MRR | p50 |
|---|---|---|---|---|---|
| Lexical BM25 | 1,545 | 0.600 | 0.800 | 0.683 | 2.7 ms |
| Lexical BM25 | 3,692 | 0.500 | 0.800 | 0.633 | 5.1 ms |
| **MiniLM + ChromaDB** | **3,692** | **0.700** | **1.000** | **0.850** | **6.3 ms** |

The third row is the one that decided it. The obvious objection to row three is
that it also has 2.4× the corpus, so the win might be data rather than method.
Giving the lexical retriever that same larger corpus made it **worse** —
recall@1 fell from 0.600 to 0.500, because the added CISA KEV and NVD entries are
short, near-duplicate, vocabulary-dense text that BM25 happily ranks above the
ATT&CK page a query is actually about. The embeddings are earning their keep.

Cost of the win: 3.6 ms per query, and two dependencies.

## Decision

**Semantic retrieval leads when it is available. Lexical remains the guaranteed
fallback and stays the only thing the deploy image needs.**

- `src.shared.evidence.search()` dispatches: semantic when the vector store and
  its dependencies are present, lexical otherwise, and lexical again if a
  semantic call throws at request time.
- **Exact technique lookup stays lexical.** Asked for `T1550.002`, an analyst
  wants the T1550.002 page, not its nearest neighbour in embedding space. This is
  the one part of 0003's reasoning that survived contact with the data, and
  `test_exact_technique_lookup_stays_lexical` pins it.
- Both backends emit the identical citation dict, so nothing downstream — the
  workflow, the scoreboard, the audit chain — knows or cares which answered.
- `chromadb` goes in `requirements.txt`, **not** `requirements-deploy.txt`. It
  pulls torch, which would take the slim image from nine packages to gigabytes
  and lengthen a free-tier cold start we already warn judges about.
- `/api/capabilities` reports `evidence.backend` with the measured numbers for
  whichever one is answering.

## Consequences

- **The hosted demo and the local demo retrieve differently, and say so.** The
  slim container runs lexical (recall@5 0.80); a full local install runs semantic
  (recall@5 1.00). Both numbers are published. This is the honest cost of keeping
  a zero-dependency deployment, and it is stated rather than averaged away.
- `corpus.jsonl` (3.8 MB) is committed so anyone can rebuild the vector store
  offline with one command. The 31 MB Chroma sqlite store is derived and
  gitignored.
- A fresh clone with no extra install still works, offline, with citations.
- The gold set is 10 shared queries. That is small, and a 0.1 difference in
  recall@1 is one query. The recall@5 and MRR gaps are wider and consistent, but
  nobody should treat these as tight estimates.

## What would change our mind

- A larger gold set where the gap closes — the honest reason this ADR could be
  overturned in turn, exactly as it overturned 0003.
- A way to run MiniLM inference without torch in the deploy image (ONNX Runtime
  with an exported model is the obvious candidate), which would remove the reason
  the deployed demo runs the weaker retriever.
- Retrieval latency mattering. It does not today: 6.3 ms inside a ~120 ms
  investigation.
