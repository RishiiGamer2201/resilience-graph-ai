"""
Milestone 3 · Task E2.2 — Build the attack-sequence dataset (Engine 2).

Turns the ATT&CK lookups (from task 0.3) into ordered technique sequences used to
train the next-technique predictor. Uses ALL groups + campaigns with >= MIN_LEN
techniques — ~196 sequences, not the 15-25 the first draft assumed.

⚠️ Honesty / anti-circularity notes (see research/claude/final_pipeline.md E2.4):
  * Sequences here are ordered by ATT&CK kill-chain tactic order (a heuristic).
    A model trained to predict "next technique" on these can trivially re-learn
    that ordering. So downstream we must (a) predict the SPECIFIC technique the
    tactic-order rule cannot determine, and (b) always report lift over a
    kill-chain-order baseline and a most-frequent baseline. This script just
    records the ordering honestly and flags is_manual so the split is auditable.

Output schema (data/processed/engine2/sequences.json), list of:
    {source, actor, ordered_technique_ids, is_manual, split}

Run:
    ./.venv/Scripts/python.exe -m src.engine2.build_sequences
"""
from __future__ import annotations

import json
import pickle
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LOOKUPS = ROOT / "data" / "processed" / "mitre_attack" / "attack_lookups.pkl"
OUT_DIR = ROOT / "data" / "processed" / "engine2"
OUT_JSON = OUT_DIR / "sequences.json"
REPORT = ROOT / "reports" / "sequences.md"

MIN_LEN = 6            # min techniques for a usable sequence
SEED = 42
SPLIT = (0.7, 0.15, 0.15)   # train / val / test at the SEQUENCE level


def build() -> tuple[list[dict], dict]:
    with LOOKUPS.open("rb") as f:
        lk = pickle.load(f)

    seqs: list[dict] = []
    for actor, techs in lk["group_to_techniques"].items():
        if len(techs) >= MIN_LEN:
            seqs.append({"source": "group", "actor": actor,
                         "ordered_technique_ids": list(techs), "is_manual": False})
    for actor, techs in lk["campaign_to_techniques"].items():
        if len(techs) >= MIN_LEN:
            seqs.append({"source": "campaign", "actor": actor,
                         "ordered_technique_ids": list(techs), "is_manual": False})

    # sequence-level split (never split within a sequence — that would leak)
    rng = random.Random(SEED)
    rng.shuffle(seqs)
    n = len(seqs)
    n_tr = int(SPLIT[0] * n)
    n_va = int((SPLIT[0] + SPLIT[1]) * n)
    for i, s in enumerate(seqs):
        s["split"] = "train" if i < n_tr else "val" if i < n_va else "test"

    lengths = [len(s["ordered_technique_ids"]) for s in seqs]
    vocab = {t for s in seqs for t in s["ordered_technique_ids"]}
    stats = {
        "n_sequences": n,
        "n_groups": sum(s["source"] == "group" for s in seqs),
        "n_campaigns": sum(s["source"] == "campaign" for s in seqs),
        "vocab": len(vocab),
        "len_min": min(lengths), "len_max": max(lengths),
        "len_mean": round(sum(lengths) / n, 1),
        "split": {k: sum(s["split"] == k for s in seqs) for k in ("train", "val", "test")},
    }
    return seqs, stats


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    REPORT.parent.mkdir(parents=True, exist_ok=True)

    seqs, stats = build()
    OUT_JSON.write_text(json.dumps(seqs, indent=2), encoding="utf-8")

    lines = [
        "# Engine 2 — attack sequence dataset", "",
        f"- Sequences: **{stats['n_sequences']}** "
        f"({stats['n_groups']} groups + {stats['n_campaigns']} campaigns, >= {MIN_LEN} techniques)",
        f"- Prediction vocabulary: **{stats['vocab']}** distinct techniques",
        f"- Length: min {stats['len_min']} · mean {stats['len_mean']} · max {stats['len_max']}",
        f"- Split (sequence-level): {stats['split']}",
        "- All auto-ordered by kill-chain tactic order (is_manual=False).",
        "- TODO: add 3-5 hand-curated CERT-In advisory sequences (is_manual=True).",
        "",
        "⚠️ Anti-circularity: predictor must beat a kill-chain-order baseline + a",
        "most-frequent baseline (see E2.4), since ordering here is heuristic.",
    ]
    REPORT.write_text("\n".join(lines), encoding="utf-8")

    print("Engine 2 sequences built.")
    for k, v in stats.items():
        print(f"  {k:14s}: {v}")
    print(f"  -> {OUT_JSON.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
