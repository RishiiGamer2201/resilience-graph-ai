#!/usr/bin/env python
"""
scripts/build_rag_corpus.py

One-shot pipeline that:
  1. Ingests all cybersecurity sources  (ingest.py)
  2. Embeds them into ChromaDB          (embed.py)

Run from project root:
    python -m scripts.build_rag_corpus
    python -m scripts.build_rag_corpus --sources attack cisa nvd malware_kb india
    python -m scripts.build_rag_corpus --force-embed   # re-embed all existing chunks
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main() -> None:
    parser = argparse.ArgumentParser(description="Build RAG corpus (ingest + embed)")
    parser.add_argument(
        "--sources", nargs="*",
        choices=["attack", "atlas", "cisa", "nvd", "malwarebazaar",
                 "threatfox", "rss", "malware_kb", "india"],
        help="Which sources to ingest (default: all except nvd/malwarebazaar/threatfox which need keys or are large)",
    )
    parser.add_argument("--fast", action="store_true",
                        help="Quick build: skip NVD, MalwareBazaar, ThreatFox, RSS (offline-friendly)")
    parser.add_argument("--batch-size", type=int, default=128,
                        help="Embedding batch size (lower = less RAM)")
    parser.add_argument("--force-embed", action="store_true",
                        help="Re-embed all chunks even if unchanged")
    parser.add_argument("--nvd-start", default="2025-01-01T00:00:00.000")
    parser.add_argument("--nvd-max", type=int, default=200)
    args = parser.parse_args()

    # Determine which sources to run
    if args.sources:
        sources = args.sources
    elif args.fast:
        sources = ["attack", "atlas", "cisa", "malware_kb", "india"]
        print("Fast mode: skipping NVD/MalwareBazaar/ThreatFox/RSS")
    else:
        sources = ["attack", "atlas", "cisa", "nvd", "malwarebazaar",
                   "threatfox", "rss", "malware_kb", "india"]

    print(f"\n{'='*60}")
    print(f"Building RAG corpus — sources: {sources}")
    print(f"{'='*60}\n")

    # Step 1: Ingest
    t0 = time.time()
    from src.retrieval.ingest import run_ingest, save_corpus, SOURCE_MAP, ingest_nvd
    import functools
    SOURCE_MAP["nvd"] = functools.partial(
        ingest_nvd, pub_start=args.nvd_start, max_results=args.nvd_max
    )

    chunks = run_ingest(sources)
    corpus_path = save_corpus(chunks)
    ingest_time = time.time() - t0

    print(f"\nIngest complete in {ingest_time:.1f}s — {len(chunks)} chunks")

    # Step 2: Embed
    t1 = time.time()
    from src.retrieval.embed import build_vector_store
    collection = build_vector_store(batch_size=args.batch_size, force=args.force_embed)
    embed_time = time.time() - t1

    print(f"\nEmbedding complete in {embed_time:.1f}s")
    print(f"\n{'='*60}")
    print(f"RAG corpus ready!")
    print(f"  Documents in vector store : {collection.count()}")
    print(f"  Corpus JSONL              : {corpus_path}")
    print(f"  Total time                : {(ingest_time + embed_time):.1f}s")
    print(f"{'='*60}")
    print("\nTest with:")
    print("  python -m src.retrieval.query 'how does LockBit disable backups'")
    print("  curl http://localhost:8000/api/rag/status")


if __name__ == "__main__":
    main()
