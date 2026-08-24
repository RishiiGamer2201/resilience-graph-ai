"""Public ATT&CK history used to explain actor-profile retrieval results.

The actor ranking is computed from technique overlap.  This module adds the
human context that was missing from the UI: what MITRE's public group profile
actually says the group did previously.  It reads the already-built RAG corpus;
no live lookup and no language-model invention is involved.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "data" / "processed" / "rag_corpus" / "corpus.jsonl"

_LINK = re.compile(r"\[([^]]+)]\([^)]+\)")
_CITATION = re.compile(r"\(Citation:[^)]+\)")
_SPACE = re.compile(r"\s+")


def _clean(text: str) -> str:
    text = _LINK.sub(r"\1", text)
    text = _CITATION.sub("", text)
    return _SPACE.sub(" ", text).strip()


def _short_history(text: str, limit: int = 760) -> str:
    marker = "Description:"
    if marker in text:
        text = text.split(marker, 1)[1]
    if "Known Techniques" in text:
        text = text.split("Known Techniques", 1)[0]
    text = _clean(text)
    if len(text) <= limit:
        return text
    cut = text[:limit]
    sentence_end = max(cut.rfind(". "), cut.rfind("; "))
    return (cut[:sentence_end + 1] if sentence_end > limit // 2 else cut.rstrip()) + "…"


@lru_cache(maxsize=1)
def _histories() -> dict[str, dict]:
    if not CORPUS.exists():
        return {}
    grouped: dict[str, list[dict]] = {}
    with CORPUS.open(encoding="utf-8") as handle:
        for line in handle:
            try:
                row = json.loads(line)
            except (json.JSONDecodeError, TypeError):
                continue
            actor = str(row.get("actor") or "").strip()
            if actor and row.get("source") == "mitre_attack_groups":
                grouped.setdefault(actor, []).append(row)

    out: dict[str, dict] = {}
    for actor, rows in grouped.items():
        rows.sort(key=lambda row: int(row.get("chunk_index") or 0))
        first = str(rows[0].get("text") or "")
        out[actor] = {
            "summary": _short_history(first),
            "source_url": rows[0].get("url") or "",
            "source": "MITRE ATT&CK public group profile",
        }
    return out


def history_for(actor: str) -> dict:
    """Return sourced public history, or an explicit absence."""
    return _histories().get(actor, {
        "summary": "No narrative history was present in the bundled ATT&CK group profile.",
        "source_url": "",
        "source": "MITRE ATT&CK public group profile",
    })
