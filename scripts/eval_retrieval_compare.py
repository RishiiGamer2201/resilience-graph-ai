"""Head-to-head: the bundled lexical retriever vs the ChromaDB semantic one.

Two retrievers now exist in this repo and only one can be the default. This
decides it on the same gold queries rather than on taste:

  lexical   src/shared/evidence.py  -- BM25 + exact-identifier boost over a
            1,545-chunk bundled index. No model, no network, no dependency.
  semantic  src/retrieval/query.py  -- MiniLM embeddings in ChromaDB over the
            3,692-chunk corpus built by src/retrieval/ingest.py.

Scoring is corpus-agnostic on purpose. The two indexes use different chunk ids,
so a hit counts when the chunk it returns REFERS to the expected thing: the same
ATT&CK technique family, or a document from the expected publisher. Anything
else is a miss for both. Latency is wall time per query, warm.

Queries the semantic corpus cannot answer at all (the four analyst-verified
CERT-In advisories are only in the bundled index) are reported separately rather
than silently counted against it.

Writes reports/retrieval_compare.md and the `retrieval.comparison` section of
reports/metrics.json.

Run:
    ./.venv/Scripts/python.exe -m scripts.eval_retrieval_compare
"""
from __future__ import annotations

import re
import statistics
import time
from pathlib import Path

from scripts.eval_retrieval import GOLD
from src.shared.metrics_store import update
from src.shared.timeutil import fmt_ist

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "reports" / "retrieval_compare.md"
K = 5

TID_RE = re.compile(r"\bT(\d{4})(?:\.\d{3})?\b")

# Gold entries whose answer exists only in the bundled index.
BUNDLED_ONLY = {"certin:0", "certin:1", "certin:2", "certin:3"}


def _family(text: str) -> str | None:
    """Parent ATT&CK technique referred to by a chunk id, title or text."""
    m = TID_RE.search(text or "")
    return m.group(1) if m else None


def _expected_family(expected) -> str | None:
    if isinstance(expected, str) and expected.startswith("attack:"):
        return _family(expected)
    return None


def _lexical_hit_refers_to(hit: dict) -> tuple[str | None, str]:
    return _family(hit["chunk_id"]) or _family(hit["title"]), hit["publisher"]


def _semantic_hit_refers_to(hit: dict) -> tuple[str | None, str]:
    meta = hit.get("metadata") or {}
    tid = meta.get("technique_id") or ""
    fam = _family(tid) or _family(hit.get("title", "")) or _family(hit.get("text", "")[:200])
    source = str(meta.get("source") or hit.get("source") or "")
    publisher = ("MITRE" if "attack" in source or "atlas" in source else
                 "CISA" if "kev" in source or "cisa" in source else
                 "NVD" if "nvd" in source else
                 "CERT-In" if "india" in source or "certin" in source else source)
    return fam, publisher


def _correct(refers_to: tuple[str | None, str], expected) -> bool:
    fam, publisher = refers_to
    if isinstance(expected, tuple) and expected[0] == "publisher":
        return publisher == expected[1]
    exp_fam = _expected_family(expected)
    if exp_fam:
        return fam == exp_fam
    return False            # CERT-In chunk ids: only the bundled index has them


def _score(runs: list[tuple[int | None, float]]) -> dict:
    ranks = [r for r, _ in runs]
    return {
        "queries": len(runs),
        "recall_at_1": round(sum(1 for r in ranks if r == 1) / max(1, len(ranks)), 4),
        "recall_at_5": round(sum(1 for r in ranks if r) / max(1, len(ranks)), 4),
        "mrr": round(sum(1.0 / r for r in ranks if r) / max(1, len(ranks)), 4),
        "latency_ms_median": round(statistics.median(t for _, t in runs), 1),
        "latency_ms_max": round(max(t for _, t in runs), 1),
    }


def run() -> dict:
    from src.shared.evidence import repository

    repo = repository()
    shared = [(q, e) for q, e in GOLD if e not in BUNDLED_ONLY]

    lex_runs, lex_rows = [], []
    for query, expected in shared:
        t = time.perf_counter()
        hits = repo.search(query, k=K)
        ms = (time.perf_counter() - t) * 1000
        rank = next((i + 1 for i, h in enumerate(hits)
                     if _correct(_lexical_hit_refers_to(h), expected)), None)
        lex_runs.append((rank, ms))
        lex_rows.append((query, expected, rank, hits[0]["title"] if hits else "—"))

    sem_available, sem_error = True, None
    sem_runs, sem_rows = [], []
    try:
        from src.retrieval.query import retrieve
        retrieve("warm up the model and the collection", top_k=1)   # exclude load cost
        for query, expected in shared:
            t = time.perf_counter()
            hits = retrieve(query, top_k=K)
            ms = (time.perf_counter() - t) * 1000
            rank = next((i + 1 for i, h in enumerate(hits)
                         if _correct(_semantic_hit_refers_to(h), expected)), None)
            sem_runs.append((rank, ms))
            sem_rows.append((query, expected, rank, hits[0].get("title", "—") if hits else "—"))
    except Exception as e:
        sem_available, sem_error = False, f"{type(e).__name__}: {e}"

    out = {
        "evaluated_at": fmt_ist(),
        "k": K,
        "shared_queries": len(shared),
        "bundled_only_queries": len(GOLD) - len(shared),
        "lexical": {**_score(lex_runs), "corpus_chunks": len(repo),
                    "needs": "nothing (bundled, offline, no dependency)"},
        "semantic": ({**_score(sem_runs), "needs": "chromadb + sentence-transformers"}
                     if sem_available else
                     {"state": "unavailable", "error": sem_error}),
        "note": ("Scored on what the retrieved chunk REFERS to (ATT&CK technique "
                 "family, or publisher), because the two indexes use different "
                 "chunk ids. The four analyst-verified CERT-In advisories exist "
                 "only in the bundled index and are excluded from both sides."),
    }
    out["_rows"] = {"lexical": lex_rows, "semantic": sem_rows}
    return out


def write_report(m: dict) -> None:
    lex, sem = m["lexical"], m["semantic"]
    lines = [
        "# Retrieval head-to-head: lexical vs semantic", "",
        f"Evaluated: {m['evaluated_at']}  ·  k={m['k']}  ·  "
        f"{m['shared_queries']} shared gold queries "
        f"({m['bundled_only_queries']} excluded: answerable only by the bundled index)",
        "", "| Metric | Lexical (BM25, bundled) | Semantic (MiniLM + ChromaDB) |",
        "|---|---|---|",
    ]
    if sem.get("state") == "unavailable":
        lines.append(f"| available | yes | **no** — {sem['error']} |")
    else:
        for key, label in [("recall_at_1", "Recall@1"), ("recall_at_5", f"Recall@{m['k']}"),
                           ("mrr", "MRR"), ("latency_ms_median", "Latency p50 (ms)"),
                           ("latency_ms_max", "Latency max (ms)")]:
            lines.append(f"| {label} | {lex[key]} | {sem[key]} |")
        lines.append(f"| Requires | {lex['needs']} | {sem['needs']} |")
    lines += ["", m["note"], "", "## Per query", "",
              "| Query | Expected | Lexical rank | Semantic rank |", "|---|---|---|---|"]
    sem_by_q = {q: r for q, _, r, _ in m["_rows"]["semantic"]}
    for query, expected, rank, _top in m["_rows"]["lexical"]:
        exp = expected if isinstance(expected, str) else f"any {expected[1]} doc"
        sr = sem_by_q.get(query, "n/a")
        lines.append(f"| {query} | `{exp}` | {rank or 'MISS'} | "
                     f"{sr if sr else 'MISS'} |")
    lines.append("")
    REPORT.write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    m = run()
    write_report(m)
    update("retrieval", "comparison", {k: v for k, v in m.items() if k != "_rows"})
    lex, sem = m["lexical"], m["semantic"]
    print(f"lexical : recall@1 {lex['recall_at_1']}  recall@{K} {lex['recall_at_5']}  "
          f"MRR {lex['mrr']}  p50 {lex['latency_ms_median']} ms")
    if sem.get("state") == "unavailable":
        print(f"semantic: UNAVAILABLE — {sem['error']}")
    else:
        print(f"semantic: recall@1 {sem['recall_at_1']}  recall@{K} {sem['recall_at_5']}  "
              f"MRR {sem['mrr']}  p50 {sem['latency_ms_median']} ms")
