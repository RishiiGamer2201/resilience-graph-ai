"""
Milestone 3 · Task E2.3 — Technique embeddings (Engine 2).

Encode each ATT&CK technique's description with a pretrained sentence-transformer
(all-MiniLM-L6-v2) → a 384-d vector per technique. No training here; a fixed
lookup that feeds the E2.4 sequence predictor and E2.5 attribution.

Sanity check: techniques sharing a tactic should be closer in embedding space
than random technique pairs (prints the gap).

Run:
    ./.venv/Scripts/python.exe -m src.engine2.build_embeddings
"""
from __future__ import annotations

import pickle
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
LOOKUPS = ROOT / "data" / "processed" / "mitre_attack" / "attack_lookups.pkl"
OUT_DIR = ROOT / "data" / "processed" / "engine2"
OUT_PKL = OUT_DIR / "technique_embeddings.pkl"
REPORT = ROOT / "reports" / "embeddings.md"
MODEL_NAME = "all-MiniLM-L6-v2"


def _cos(a: np.ndarray, b: np.ndarray) -> float:
    return float(a @ b / (np.linalg.norm(a) * np.linalg.norm(b) + 1e-9))


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    REPORT.parent.mkdir(parents=True, exist_ok=True)

    with LOOKUPS.open("rb") as f:
        lk = pickle.load(f)
    names = lk["technique_to_name"]
    descs = lk["technique_to_desc"]
    tactics = lk["technique_to_tactics"]

    techs = sorted(names)
    texts = [f"{names[t]}. {descs.get(t, '')}"[:1000] for t in techs]

    from sentence_transformers import SentenceTransformer
    print(f"Loading {MODEL_NAME} (first run downloads ~90MB) ...")
    model = SentenceTransformer(MODEL_NAME)
    print(f"Encoding {len(techs)} technique descriptions ...")
    emb = model.encode(texts, batch_size=64, show_progress_bar=False,
                       normalize_embeddings=False).astype("float32")

    embeddings = {t: emb[i] for i, t in enumerate(techs)}
    with OUT_PKL.open("wb") as f:
        pickle.dump(embeddings, f)

    # sanity: same-tactic vs random cosine similarity
    rng = np.random.default_rng(42)
    same, rand = [], []
    idx = {t: i for i, t in enumerate(techs)}
    for _ in range(3000):
        a, b = rng.choice(techs, 2, replace=False)
        ta, tb = set(tactics.get(a, [])), set(tactics.get(b, []))
        if not ta or not tb:
            continue
        c = _cos(emb[idx[a]], emb[idx[b]])
        (same if ta & tb else rand).append(c)
    same_m, rand_m = float(np.mean(same)), float(np.mean(rand))

    REPORT.write_text("\n".join([
        "# Engine 2 — technique embeddings",
        "",
        f"- Model: `{MODEL_NAME}` (384-d, pretrained; no fine-tuning).",
        f"- Techniques embedded: **{len(techs)}**.",
        "",
        "## Sanity check (same-tactic techniques should cluster)",
        f"- Mean cosine, **same-tactic** pairs: **{same_m:.3f}**",
        f"- Mean cosine, random pairs: {rand_m:.3f}",
        f"- Gap: **{same_m - rand_m:+.3f}** "
        f"({'PASS — same-tactic techniques are closer' if same_m > rand_m else 'WEAK'}).",
    ]), encoding="utf-8")

    try:
        from src.shared.metrics_store import update as _update
        _update("engine2", "embeddings", {"same_tactic_cos": round(same_m, 3),
                                          "random_cos": round(rand_m, 3)})
    except Exception as e:
        print(f"  [metrics_store skipped: {e}]")

    print(f"  embedded {len(techs)} techniques, dim {emb.shape[1]}")
    print(f"  same-tactic cos {same_m:.3f} vs random {rand_m:.3f} (gap {same_m-rand_m:+.3f})")
    print(f"  -> {OUT_PKL.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
