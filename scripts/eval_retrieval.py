"""Evaluate the evidence retriever against a gold query set.

We do not get to call something "RAG" because it searches text. This measures it:

  recall@1 / recall@5   did the right official document come back, and how high
  MRR                   mean reciprocal rank of the first correct hit
  citation integrity    every hit's stored SHA-256 still matches its text, and
                        every hit carries a URL, publisher and section

The gold set is small and hand-written (that is honest for a bundled corpus of
this size) and lives in this file so a reviewer can see exactly what was asked.

Writes `reports/retrieval_eval.md` and the `retrieval` section of
`reports/metrics.json` via the canonical metrics store — the scoreboard reads it
from there, never from a constant in the UI.

Run:
    ./.venv/Scripts/python.exe -m scripts.eval_retrieval
"""
from __future__ import annotations

from pathlib import Path

from src.shared.evidence import repository, sha256_text
from src.shared.metrics_store import update
from src.shared.timeutil import fmt_ist

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "reports" / "retrieval_eval.md"
K = 5

# (query, expected chunk id OR ("publisher", name) when any document from that
#  authority is a correct answer)
GOLD: list[tuple[str, object]] = [
    ("how do attackers reuse stolen password hashes to move between hosts",
     "attack:T1550.002"),
    ("adversary logs in with a legitimate account instead of malware",
     "attack:T1078"),
    ("lateral movement using remote services like SMB and RDP", "attack:T1021"),
    ("repeated failed logins guessing passwords", "attack:T1110"),
    ("collecting data from internal wikis and databases", "attack:T1213"),
    ("stealing data out over the command and control channel", "attack:T1041"),
    ("enumerating other machines on the network", "attack:T1018"),
    ("what does MITRE recommend to mitigate pass the hash", "attack:T1550.002"),
    ("WhatsApp distributed VBScript loader taking over remote management tools",
     "certin:0"),
    ("Android banking trojan disguised as an RTO eChallan alert", "certin:1"),
    ("malicious npm and PyPI packages in a software supply chain attack",
     "certin:2"),
    ("Fortigate SSL VPN administrator credential exposure", "certin:3"),
    ("actively exploited vulnerability that CISA requires federal agencies to patch",
     ("publisher", "CISA")),
    ("known exploited Microsoft Windows privilege escalation flaw",
     ("publisher", "CISA")),
]


def _correct(hit: dict, expected) -> bool:
    """Is this hit an acceptable answer?

    For a technique we accept the exact chunk OR another chunk in the same
    technique family — retrieving `T1110.001 Password Guessing` for "repeated
    failed logins guessing passwords" is a correct answer, not a miss, because
    it is a sub-technique of the expected `T1110 Brute Force`. Scoring it as a
    failure would understate the retriever; scoring an unrelated technique as a
    pass would overstate it, so only the family counts.
    """
    if isinstance(expected, tuple) and expected[0] == "publisher":
        return hit["publisher"] == expected[1]
    if hit["chunk_id"] == expected:
        return True
    if expected.startswith("attack:") and hit["chunk_id"].startswith("attack:"):
        return (expected.split(":")[1].split(".")[0]
                == hit["chunk_id"].split(":")[1].split(".")[0])
    return False


def evaluate() -> dict:
    repo = repository()
    rows, r1, r5, rr = [], 0, 0, 0.0
    integrity_failures: list[str] = []

    for query, expected in GOLD:
        hits = repo.search(query, k=K)
        rank = next((i + 1 for i, h in enumerate(hits) if _correct(h, expected)), None)
        r1 += int(rank == 1)
        r5 += int(rank is not None)
        rr += (1.0 / rank) if rank else 0.0
        for h in hits:
            chunk = repo.get(h["chunk_id"])
            if chunk and sha256_text(chunk.text) != chunk.sha256:
                integrity_failures.append(f"{h['chunk_id']}: stored hash != text hash")
            if not (h["url"].startswith("http") and h["publisher"] and h["section"]):
                integrity_failures.append(f"{h['chunk_id']}: incomplete citation")
        rows.append({
            "query": query,
            "expected": expected if isinstance(expected, str) else f"any {expected[1]} doc",
            "rank": rank,
            "top_hit": hits[0]["title"] if hits else "—",
            "top_score": hits[0]["score"] if hits else 0.0,
        })

    n = len(GOLD)
    return {
        "queries": n,
        "recall_at_1": round(r1 / n, 4),
        "recall_at_5": round(r5 / n, 4),
        "mrr": round(rr / n, 4),
        "k": K,
        "corpus_chunks": len(repo),
        "citation_integrity_failures": len(integrity_failures),
        "integrity_detail": integrity_failures[:10],
        "rows": rows,
        "evaluated_at": fmt_ist(),
        "note": ("Hand-written gold set over the bundled corpus. Small by construction; "
                 "reported as-is rather than inflated with auto-generated queries that "
                 "restate the document they came from."),
    }


def write_report(m: dict) -> None:
    lines = [
        "# Evidence retrieval evaluation", "",
        f"Evaluated: {m['evaluated_at']}  ·  corpus {m['corpus_chunks']} chunks  ·  k={m['k']}",
        "",
        "| Metric | Value |", "|---|---|",
        f"| Queries | {m['queries']} |",
        f"| Recall@1 | {m['recall_at_1']:.3f} |",
        f"| Recall@{m['k']} | {m['recall_at_5']:.3f} |",
        f"| MRR | {m['mrr']:.3f} |",
        f"| Citation integrity failures | {m['citation_integrity_failures']} |",
        "", "## Per-query", "",
        "| Query | Expected | Rank | Top hit |", "|---|---|---|---|",
    ]
    for r in m["rows"]:
        lines.append(f"| {r['query']} | `{r['expected']}` | "
                     f"{r['rank'] if r['rank'] else 'MISS'} | {r['top_hit']} |")
    lines += ["", m["note"], "",
              "Scoring: a technique query is correct if the retrieved chunk is the "
              "expected technique or another member of the same technique family "
              "(a sub-technique of the expected parent). Unrelated techniques never "
              "count.", "",
              "Known limitation: this is a lexical retriever. A fully paraphrased "
              "query that shares no vocabulary with the document (\"logs in with a "
              "legitimate account instead of malware\" vs \"Valid Accounts\") still "
              "misses. The documented upgrade path is a local embedding re-rank over "
              "the ATT&CK chunks using the MiniLM technique embeddings this repo "
              "already ships; it is not enabled because it needs the encoder in the "
              "deploy image, which the slim runtime deliberately excludes.", "",
              "Retriever: BM25 over chunk text plus an exact-identifier boost for ATT&CK "
              "technique IDs and CVE IDs. No embedding model, no vector database, no "
              "network at query time.", ""]
    REPORT.write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    m = evaluate()
    write_report(m)
    update("retrieval", "gold_set", {k: v for k, v in m.items()
                                     if k not in ("rows", "integrity_detail")})
    print(f"retrieval: recall@1 {m['recall_at_1']:.3f} · recall@{K} {m['recall_at_5']:.3f} "
          f"· MRR {m['mrr']:.3f} · integrity failures {m['citation_integrity_failures']}")
    for r in m["rows"]:
        if r["rank"] != 1:
            print(f"  rank {r['rank'] or 'MISS'}: {r['query'][:64]}  ->  {r['top_hit'][:52]}")
