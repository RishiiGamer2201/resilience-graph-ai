"""
Single source of truth for evaluation metrics (reports/metrics.json).

The Models & Metrics screen used to carry numbers hand-copied from the reports;
they drifted (the UI claimed a 5.1x anti-circularity lift when the report said
4.7x). This module removes the copy: eval scripts call `update()` to write their
section, and build_cache calls `load()` to serve it. No hand-typed numbers.

    from src.shared.metrics_store import update, load
    update("engine1", "lanl", {"roc_auc": 0.988, ...})     # from an eval script
    metrics = load()                                        # in build_cache
"""
from __future__ import annotations

import json
from pathlib import Path

STORE = Path(__file__).resolve().parents[2] / "reports" / "metrics.json"


def load() -> dict:
    data = json.loads(STORE.read_text(encoding="utf-8"))
    data.pop("_comment", None)
    return data


def update(engine: str, key: str, values: dict) -> None:
    """Merge one eval result into the store (e.g. update('engine1','lanl',{...}))."""
    data = json.loads(STORE.read_text(encoding="utf-8")) if STORE.exists() else {}
    data.setdefault(engine, {})[key] = values
    STORE.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"  metrics_store: updated {engine}.{key}")
