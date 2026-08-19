"""
RAG Embedding & Vector Store — src/retrieval/embed.py

Reads corpus.jsonl produced by ingest.py, embeds every chunk with
sentence-transformers/all-MiniLM-L6-v2 (already in the project), and stores
in a ChromaDB persistent vector store under data/processed/rag_corpus/chroma/.

Also maintains a SHA-256 fingerprint file so incremental re-runs only
re-embed genuinely new/changed chunks (not the whole ~15k-chunk corpus).

Usage:
    python -m src.retrieval.embed                    # full build
    python -m src.retrieval.embed --batch-size 256   # tune GPU/CPU
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]  # src/retrieval/embed.py -> project root
DATA_DIR = ROOT / "data" / "processed" / "rag_corpus"
CORPUS_PATH = DATA_DIR / "corpus.jsonl"
CHROMA_DIR  = DATA_DIR / "chroma"
HASHES_FILE = DATA_DIR / "embedded_hashes.json"

log = logging.getLogger("embed")
logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")

EMBED_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
COLLECTION_NAME = "cyberknowledge"


def _load_hashes() -> dict[str, str]:
    if HASHES_FILE.exists():
        return json.loads(HASHES_FILE.read_text())
    return {}


def _save_hashes(hashes: dict[str, str]) -> None:
    HASHES_FILE.write_text(json.dumps(hashes, indent=2))


def _chunk_hash(chunk: dict) -> str:
    return hashlib.sha256(chunk["text"].encode()).hexdigest()[:16]


def load_corpus(path: Path = CORPUS_PATH) -> list[dict]:
    if not path.exists():
        raise FileNotFoundError(f"Corpus not found: {path}\nRun: python -m src.retrieval.ingest")
    chunks = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                chunks.append(json.loads(line))
    log.info("Loaded %d chunks from %s", len(chunks), path)
    return chunks


def build_vector_store(batch_size: int = 128, force: bool = False) -> Any:
    """Embed corpus and upsert into ChromaDB. Returns the collection."""
    try:
        import chromadb
        from chromadb.config import Settings
        from sentence_transformers import SentenceTransformer
    except ImportError:
        print("\nMissing dependencies. Run:\n  pip install chromadb sentence-transformers\n")
        sys.exit(1)

    chunks = load_corpus()
    known_hashes = {} if force else _load_hashes()

    # filter to only new/changed chunks
    new_chunks = []
    for c in chunks:
        h = _chunk_hash(c)
        if c["doc_id"] not in known_hashes or known_hashes[c["doc_id"]] != h:
            new_chunks.append(c)

    log.info("%d total chunks, %d new/changed to embed", len(chunks), len(new_chunks))

    if not new_chunks and not force:
        log.info("All chunks already embedded. Use --force to rebuild.")
        client = chromadb.PersistentClient(path=str(CHROMA_DIR))
        return client.get_collection(COLLECTION_NAME)

    # Load embedding model
    log.info("Loading embedding model: %s", EMBED_MODEL)
    model = SentenceTransformer(EMBED_MODEL)

    # Connect to ChromaDB
    CHROMA_DIR.mkdir(parents=True, exist_ok=True)
    client = chromadb.PersistentClient(path=str(CHROMA_DIR))

    try:
        collection = client.get_collection(COLLECTION_NAME)
        log.info("Found existing collection with %d docs", collection.count())
    except Exception:
        collection = client.create_collection(
            name=COLLECTION_NAME,
            metadata={"hnsw:space": "cosine"},
        )
        log.info("Created new collection: %s", COLLECTION_NAME)

    # Embed in batches
    total = len(new_chunks)
    embedded_count = 0
    new_hashes = dict(known_hashes)

    for i in range(0, total, batch_size):
        batch = new_chunks[i: i + batch_size]
        texts = [c["text"] for c in batch]
        ids   = [c["doc_id"] for c in batch]

        log.info("  Embedding batch %d-%d / %d ...", i + 1, min(i + batch_size, total), total)
        embeddings = model.encode(texts, batch_size=batch_size,
                                  show_progress_bar=False, normalize_embeddings=True)

        # Build ChromaDB metadata (only primitive types allowed)
        metadatas = []
        for c in batch:
            meta = {
                "source":     c.get("source", ""),
                "title":      c.get("title", "")[:200],
                "url":        c.get("url", "")[:500],
                "date":       c.get("date", ""),
                "severity":   c.get("severity", ""),
                "actor":      c.get("actor", ""),
                "domain":     c.get("domain", ""),
                "family":     c.get("family", ""),
                "chunk_index": str(c.get("chunk_index", 0)),
                # store list fields as comma-separated strings (ChromaDB limitation)
                "technique_ids": ",".join(c.get("technique_ids", [])),
                "tags":          ",".join(c.get("tags", [])),
            }
            metadatas.append(meta)

        collection.upsert(
            ids=ids,
            embeddings=embeddings.tolist(),
            documents=texts,
            metadatas=metadatas,
        )

        for c in batch:
            new_hashes[c["doc_id"]] = _chunk_hash(c)
        embedded_count += len(batch)

    _save_hashes(new_hashes)
    log.info("Done. Embedded %d chunks. Collection size: %d", embedded_count, collection.count())
    return collection


def get_collection() -> Any:
    """Get the existing ChromaDB collection (for querying)."""
    try:
        import chromadb
    except ImportError:
        raise ImportError("Run: pip install chromadb")
    client = chromadb.PersistentClient(path=str(CHROMA_DIR))
    return client.get_collection(COLLECTION_NAME)


def main() -> None:
    parser = argparse.ArgumentParser(description="Embed corpus into ChromaDB vector store")
    parser.add_argument("--batch-size", type=int, default=128)
    parser.add_argument("--force", action="store_true", help="Re-embed all chunks")
    args = parser.parse_args()
    col = build_vector_store(batch_size=args.batch_size, force=args.force)
    print(f"\nVector store ready: {col.count()} documents in '{COLLECTION_NAME}'")
    print(f"Location: {CHROMA_DIR}")


if __name__ == "__main__":
    main()
