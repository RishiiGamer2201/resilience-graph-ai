"""The two retrieval backends, the dispatch between them, and the corpus builder.

The semantic backend is optional by design: the slim deploy image ships neither
chromadb nor sentence-transformers. Everything here must hold whether or not it
is installed, which is why most tests either skip cleanly or exercise the
fallback path explicitly.
"""
from __future__ import annotations

import pytest

from src.retrieval.ingest import _chunk_text
from src.shared import evidence as ev

CITATION_KEYS = {"chunk_id", "title", "url", "publisher", "authority", "section",
                 "published", "retrieved_at", "excerpt", "sha256", "identifiers",
                 "extraction_method", "classification", "match_reason", "score"}


# --------------------------------------------------------------------------- #
# corpus chunker — regression tests for the MemoryError                        #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("text,label", [
    ("one short sentence.", "short"),
    ("x" * 1800, "exactly max_chars"),
    ("y" * 1801, "one over max_chars"),
    ("z" * 12000, "long with no sentence boundary"),
    ("This is a sentence about lateral movement. " * 400, "long with boundaries"),
    ("MITRE ATT&CK Technique: T1550.002\n" + "Adversaries may abuse hashes. " * 300,
     "ATT&CK shaped"),
])
def test_chunker_terminates(text, label):
    """It used to loop forever once the tail was reached, appending the same
    chunk until the process died. Every MITRE ATT&CK technique over 1800 chars
    hit it, which is why the corpus contained zero ATT&CK chunks."""
    chunks = _chunk_text(text)
    assert chunks, label
    assert len(chunks) < 200, f"{label}: runaway chunk count {len(chunks)}"


def test_chunker_covers_the_whole_input():
    text = "Sentence number %d about credential access. " % 0 + \
           "".join(f"Sentence number {i} about credential access. " for i in range(1, 300))
    chunks = _chunk_text(text)
    assert text.strip()[:40] in chunks[0]
    assert text.strip()[-40:] in chunks[-1], "the tail of the document was dropped"


def test_chunker_overlaps_rather_than_cutting_mid_thought():
    text = "A. " * 2000
    chunks = _chunk_text(text)
    assert len(chunks) > 1
    assert sum(len(c) for c in chunks) > len(text.strip()) * 0.9


# --------------------------------------------------------------------------- #
# dispatch                                                                     #
# --------------------------------------------------------------------------- #
def test_active_backend_is_one_of_two_known_values():
    assert ev.active_backend() in ("semantic", "lexical")


def test_semantic_availability_is_honest():
    """It must not claim availability without both the store and the deps."""
    if ev.semantic_available():
        assert ev.CHROMA_DIR.exists()
        import chromadb            # noqa: F401
        import sentence_transformers   # noqa: F401


@pytest.mark.skipif(not ev.available(), reason="evidence index not built")
def test_search_returns_full_citations_from_whichever_backend():
    hits = ev.search("lateral movement using stolen credentials", k=3)
    assert hits
    for h in hits:
        assert CITATION_KEYS <= set(h), sorted(CITATION_KEYS - set(h))
        assert h["backend"] in ("semantic", "lexical")
        assert h["publisher"]
        assert isinstance(h["identifiers"], list)


@pytest.mark.skipif(not ev.available(), reason="evidence index not built")
def test_a_semantic_failure_falls_back_instead_of_propagating(monkeypatch):
    """Losing the retriever must not lose the investigation."""
    monkeypatch.setattr(ev, "semantic_available", lambda: True)
    import src.retrieval.query as q
    monkeypatch.setattr(q, "retrieve",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("store gone")))
    hits = ev.search("brute force password guessing", k=3)
    assert hits, "fallback produced nothing"
    assert all(h["backend"] == "lexical" for h in hits)


@pytest.mark.skipif(not ev.available(), reason="evidence index not built")
def test_forcing_lexical_still_works(monkeypatch):
    monkeypatch.setattr(ev, "semantic_available", lambda: False)
    hits = ev.search("remote services lateral movement", k=3)
    assert hits and all(h["backend"] == "lexical" for h in hits)


@pytest.mark.skipif(not ev.available(), reason="evidence index not built")
def test_exact_technique_lookup_stays_lexical():
    """Asked for T1550.002 an analyst wants that page, not a near neighbour."""
    hits = ev.search_for_techniques(["T1550.002"], k_each=1)
    assert hits
    assert any("T1550.002" in h["identifiers"] for h in hits), hits[0]["identifiers"]
    assert hits[0]["chunk_id"].startswith("attack:")


# --------------------------------------------------------------------------- #
# semantic backend proper                                                      #
# --------------------------------------------------------------------------- #
semantic_only = pytest.mark.skipif(
    not ev.semantic_available(),
    reason="vector store not built — run src.retrieval.ingest then src.retrieval.embed")


@semantic_only
def test_semantic_citations_carry_provenance():
    hits = ev.search("how do attackers disable backups before encrypting", k=3)
    assert hits and hits[0]["backend"] == "semantic"
    for h in hits:
        assert h["url"].startswith("http"), h["title"]
        assert len(h["sha256"]) == 64
        assert h["excerpt"]
        assert h["authority"] in ("primary-framework", "government-authoritative", "unrated")


@semantic_only
def test_semantic_beats_lexical_on_the_shared_gold_set():
    """Locks in the comparison that justified making semantic the default.
    If a change makes it no worse than lexical, this fails and the ADR is wrong
    again — which is exactly when we want to know."""
    from scripts.eval_retrieval_compare import run
    m = run()
    lex, sem = m["lexical"], m["semantic"]
    assert sem.get("state") != "unavailable", sem
    assert sem["recall_at_5"] >= lex["recall_at_5"], (sem, lex)
    assert sem["mrr"] > lex["mrr"], (sem, lex)
