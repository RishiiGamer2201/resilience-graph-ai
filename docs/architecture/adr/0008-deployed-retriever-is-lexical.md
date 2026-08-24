# ADR 0008 -- The deployed retriever is lexical, and the headline number says so

- **Status:** accepted
- **Date:** 2026-08-23
- **Amends:** [ADR 0005](0005-semantic-retrieval-supersedes-0003.md). 0005's
  measurement stands and its dispatch design stands. What changes is which
  number is allowed to be the published one.

## Context

ADR 0005 measured MiniLM + ChromaDB ahead of BM25 (recall@5 1.00 vs 0.80, MRR
0.85 vs 0.68) and concluded "semantic leads, lexical is the fallback." In the
same breath it kept `chromadb` out of `requirements-deploy.txt`. Both halves were
correct, and together they produced a reporting problem: the retriever the
project called its leader is not the retriever any deployed container has ever
run.

This project's rule is that the number on the page must be the number the
container produces. A better number measured on a developer laptop, published
without the qualifier, fails that rule regardless of how honestly it was
measured.

## The measurement (why semantic is not shipped)

Not a guess. Measured on this repository, 2026-08-23:

| Question | Measured answer |
|---|---|
| Installed size of `chromadb` + `sentence-transformers` and their transitive deps | **1.09 GB** across 93 packages |
| Largest contributors | torch 372 MB, transformers 107 MB, scipy 100 MB, kubernetes 79 MB, onnxruntime 70 MB, sympy 70 MB, grpcio 42 MB |
| Render free web service memory | 512 MB (<https://render.com/docs/free>) |
| Is the Chroma store in the image? | **No.** `data/processed/rag_corpus/chroma/` is gitignored (~31 MB of sqlite) and the Dockerfile never `COPY`s `rag_corpus` at all |
| Are the MiniLM weights vendored or pre-fetched? | **No.** No `*.safetensors` or `pytorch_model.bin` anywhere in the repo, and nothing sets `HF_HOME`, calls `snapshot_download`, or warms a cache in the Dockerfile or any script |
| When are the weights needed? | **At query time.** `src/retrieval/query.py::_embed_query` constructs `SentenceTransformer(EMBED_MODEL)` to embed the *user's query string* |

Three independent blockers, any one of which is sufficient:

1. **Size.** 1.09 GB of dependencies against a 512 MB instance. The deploy image
   is currently nine packages and no torch.
2. **Offline.** Precomputing the corpus embeddings does not help. The query
   itself must be embedded with the same model, so the model must be present in
   the container. It is not, and nothing fetches it at build time, so the first
   query in a fresh container would hit the HuggingFace Hub. The product's
   headline promise is that it "runs entirely offline after a clone"
   (`docs/operations/cost-and-limits.md`). A runtime model download breaks that
   promise on the first query of the demo.
3. **The index does not exist in the image.** Even with both dependencies added,
   `evidence.semantic_available()` checks `CHROMA_DIR.exists()` first and would
   return `False`, so the container would install 1.09 GB and still answer
   lexically. Fixing that means also building or shipping the 31 MB store.

## Decision

**The deployed retriever is lexical BM25, by deliberate choice, and the published
retrieval numbers are the lexical ones.**

- `requirements-deploy.txt` is unchanged. It keeps excluding `chromadb` and
  `sentence-transformers`, and the comment there already says why.
- `scripts/make_results_md.py` labels the retrieval rows in RESULTS.md section 6
  as **"lexical, the shipped backend"**, and prints the head-to-head table
  underneath with the semantic row marked **"full install only, not in the
  deployed image."** Both numbers stay published; only the unqualified one goes
  away.
- Those rows were already lexical in fact -- `scripts/eval_retrieval.py` calls
  `repository().search()`, the BM25 method, over the 1,545-chunk bundled index.
  They were simply unlabelled, which let ADR 0005's "semantic leads" framing
  attach itself to numbers semantic never produced.
- ADR 0005's dispatch stands: a full local install still gets the better
  retriever, and `/api/capabilities` still reports `evidence.backend`.

## Consequences

- **What it costs: 20 percentage points of recall@5** (0.80 shipped vs 1.00 with
  a full install), 10 points of recall@1, and 0.167 of MRR, on a 10-query shared
  subset. That is the price of an image that boots in a minute on a free tier and
  never touches the network, and it is now stated on the results page instead of
  being averaged away.
- The gold set is 10 shared queries. A 0.1 difference in recall@1 is one query.
  Nobody should treat the gap as a tight estimate -- in either direction.
- The hosted demo and a full local install still retrieve differently. That was
  already true and disclosed via `/api/capabilities`; what is new is that the
  headline no longer contradicts it.
- `docs/research/free-tier-and-stack.md` does not currently record the Render
  free-tier memory limit, only spin-down, hours, filesystem and bandwidth. The
  512 MB figure above is cited from Render's docs directly and should be folded
  into that research table on its next `as_of` refresh.

## What would change our mind

- **An ONNX export of MiniLM.** This is the live candidate and ADR 0005 already
  named it. `onnxruntime` is 70 MB against torch's 372 MB, the MiniLM ONNX
  weights are ~90 MB, and both could be vendored into the image, which fixes the
  size blocker and the offline blocker at once. It still needs the 31 MB Chroma
  store committed or built in the Dockerfile, or a flat numpy matrix and a brute
  force cosine scan over 3,692 chunks, which at that corpus size is likely
  simpler than Chroma and removes the third blocker too.
- **A paid instance.** If the demo ever stops targeting a free tier, blocker 1
  disappears and only the offline promise needs solving.
- **A larger gold set that closes the gap**, which would remove the reason to
  want semantic in the image at all.

Until one of those lands, the shipped retriever is lexical and the page says so.
