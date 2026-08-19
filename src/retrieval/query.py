"""
RAG Query Engine — src/retrieval/query.py

Semantic retrieval over the ChromaDB vector store built by embed.py.
Supports:
  - Free-text semantic search
  - Filter by source, severity, domain, actor, family, technique_id
  - Hybrid reranking: semantic score + keyword bonus + freshness boost
  - ATT&CK technique lookup shortcut (T1234 -> get all chunks for that technique)

Usage (Python):
    from src.retrieval.query import retrieve, technique_lookup

    results = retrieve("how does LockBit disable backups", top_k=5)
    for r in results:
        print(r["score"], r["title"], r["source"])

    # get all info about T1486
    chunks = technique_lookup("T1486")
"""
from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any

log = logging.getLogger("rag.query")

ROOT = Path(__file__).resolve().parents[2]   # src/retrieval/query.py -> project root
_collection_cache: Any = None

TECHNIQUE_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b")

# Same model as the corpus was embedded with. Importing it rather than
# retyping the string means the two can never drift apart.
from src.retrieval.embed import EMBED_MODEL  # noqa: E402


def _get_collection() -> Any:
    global _collection_cache
    if _collection_cache is not None:
        return _collection_cache
    from src.retrieval.embed import get_collection
    _collection_cache = get_collection()
    return _collection_cache


_model_cache: Any = None


def _embed_query(text: str) -> list[float]:
    """Embed a query string using the same model as the corpus.

    The model is loaded ONCE per process. It used to be constructed on every
    call, which re-read ~90 MB of weights from disk per query and made semantic
    search several seconds slower than the lexical retriever it is meant to
    improve on.
    """
    global _model_cache
    if _model_cache is None:
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as e:
            raise ImportError(
                "semantic query needs sentence-transformers: pip install -r requirements.txt"
            ) from e
        _model_cache = SentenceTransformer(EMBED_MODEL)
    vec = _model_cache.encode([text], normalize_embeddings=True)
    return vec[0].tolist()


def _freshness_boost(date_str: str) -> float:
    """Give a small relevance boost to more recent documents."""
    if not date_str:
        return 0.0
    try:
        year = int(date_str[:4])
        if year >= 2026:
            return 0.05
        if year >= 2025:
            return 0.03
        if year >= 2024:
            return 0.01
    except ValueError:
        pass
    return 0.0


def _keyword_bonus(text: str, query: str) -> float:
    """Small bonus if query keywords appear literally in chunk text."""
    keywords = [w.lower() for w in query.split() if len(w) > 3]
    text_lower = text.lower()
    matches = sum(1 for k in keywords if k in text_lower)
    return min(0.1, matches * 0.02)


def retrieve(
    query: str,
    top_k: int = 10,
    source_filter: str | None = None,
    domain_filter: str | None = None,
    severity_filter: str | None = None,
    actor_filter: str | None = None,
    family_filter: str | None = None,
) -> list[dict]:
    """
    Semantic retrieval with optional metadata filters.

    Returns list of dicts with keys:
        score, text, source, title, url, date, technique_ids,
        severity, actor, domain, family, tags
    """
    col = _get_collection()

    # Build ChromaDB where clause
    where: dict = {}
    filters = [
        ("source", source_filter),
        ("domain", domain_filter),
        ("severity", severity_filter),
        ("actor", actor_filter),
        ("family", family_filter),
    ]
    active = [(k, v) for k, v in filters if v]
    if len(active) == 1:
        where = {active[0][0]: {"$eq": active[0][1]}}
    elif len(active) > 1:
        where = {"$and": [{k: {"$eq": v}} for k, v in active]}

    # Embed the query
    query_embedding = _embed_query(query)

    # Fetch more than top_k for reranking
    fetch_k = min(top_k * 3, 50)
    kwargs: dict = dict(
        query_embeddings=[query_embedding],
        n_results=fetch_k,
        include=["documents", "metadatas", "distances"],
    )
    if where:
        kwargs["where"] = where

    results = col.query(**kwargs)

    docs      = results["documents"][0]
    metas     = results["metadatas"][0]
    distances = results["distances"][0]  # cosine distance (lower = better)

    # Convert distance to similarity score
    scored = []
    for doc, meta, dist in zip(docs, metas, distances):
        semantic_score = max(0.0, 1.0 - dist)
        freshness      = _freshness_boost(meta.get("date", ""))
        keyword        = _keyword_bonus(doc, query)
        final_score    = round(min(1.0, semantic_score + freshness + keyword), 4)

        scored.append({
            "score":         final_score,
            "semantic_score": round(semantic_score, 4),
            "text":          doc,
            "source":        meta.get("source", ""),
            "title":         meta.get("title", ""),
            "url":           meta.get("url", ""),
            "date":          meta.get("date", ""),
            "severity":      meta.get("severity", ""),
            "actor":         meta.get("actor", ""),
            "domain":        meta.get("domain", ""),
            "family":        meta.get("family", ""),
            "technique_ids": [t for t in meta.get("technique_ids", "").split(",") if t],
            "tags":          [t for t in meta.get("tags", "").split(",") if t],
        })

    # Sort by final score descending
    scored.sort(key=lambda x: x["score"], reverse=True)
    return scored[:top_k]


def technique_lookup(technique_id: str) -> list[dict]:
    """Retrieve all chunks specifically about a given ATT&CK technique ID."""
    col = _get_collection()
    # Use ChromaDB $contains on technique_ids string
    try:
        results = col.query(
            query_texts=[f"ATT&CK technique {technique_id}"],
            n_results=20,
            where={"technique_ids": {"$contains": technique_id}},
            include=["documents", "metadatas", "distances"],
        )
    except Exception:
        # Fallback: full text search if metadata filter fails
        return retrieve(f"ATT&CK {technique_id}", top_k=10)

    out = []
    for doc, meta, dist in zip(results["documents"][0],
                                results["metadatas"][0],
                                results["distances"][0]):
        out.append({
            "score": round(max(0.0, 1.0 - dist), 4),
            "text": doc,
            "source": meta.get("source", ""),
            "title": meta.get("title", ""),
            "url": meta.get("url", ""),
            "date": meta.get("date", ""),
            "technique_ids": [t for t in meta.get("technique_ids", "").split(",") if t],
            "tags": [t for t in meta.get("tags", "").split(",") if t],
        })
    return sorted(out, key=lambda x: -x["score"])


def extract_techniques_from_query(query: str) -> list[str]:
    """Extract ATT&CK technique IDs mentioned explicitly in a query."""
    return list(dict.fromkeys(TECHNIQUE_RE.findall(query)))


def retrieve_for_incident(
    incident_techniques: list[str],
    incident_text: str = "",
    top_k: int = 15,
) -> list[dict]:
    """
    Retrieve RAG context most relevant to a running incident.
    Combines technique-specific lookups with free-text semantic search.
    """
    results: list[dict] = []
    seen_ids: set = set()

    # 1. Technique-specific lookups (highest precision)
    for tid in incident_techniques[:5]:
        for chunk in technique_lookup(tid)[:3]:
            if chunk["title"] not in seen_ids:
                seen_ids.add(chunk["title"])
                results.append(chunk)

    # 2. Free-text semantic search over combined incident description
    combined_query = f"{' '.join(incident_techniques)} {incident_text}"[:500]
    for chunk in retrieve(combined_query, top_k=top_k):
        if chunk["title"] not in seen_ids:
            seen_ids.add(chunk["title"])
            results.append(chunk)

    return sorted(results, key=lambda x: -x["score"])[:top_k]


if __name__ == "__main__":
    import sys
    query = " ".join(sys.argv[1:]) or "ransomware disable backup encryption"
    print(f"\nQuery: {query!r}\n{'='*60}")
    for r in retrieve(query, top_k=5):
        print(f"[{r['score']:.3f}] ({r['source']}) {r['title']}")
        print(f"         {r['text'][:120]}...")
        print()
