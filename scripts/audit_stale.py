"""
Staleness audit — find claims that the model promotions made obsolete.

Greps the repo for numbers and model names that changed when the autoencoder
and interpolated Markov were promoted, so a stale figure cannot quietly survive
in a doc, a screen, or a report.

Some hits are LEGITIMATE: the old numbers still appear where we deliberately
publish the previous model as a comparison. This script only locates them; a
human decides. Run it after any model change.

    ./.venv/Scripts/python.exe -m scripts.audit_stale
"""
from __future__ import annotations

import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
SKIP = {".venv", "node_modules", "__pycache__", ".git", "dist", "data",
        ".pytest_cache", "outputs", ".claude", "research", "testsprite_tests", "tmp"}
EXT = {".md", ".py", ".jsx", ".js", ".json", ".yaml", ".yml", ".html", ".txt"}

# token -> what it used to mean
STALE = {
    "1,192": "old alert count (now 1,243)",
    "479 host": "old host count (now 473)",
    "479 machines": "old host count (now 473)",
    "479-node": "old host count (now 473)",
    "502 movements": "old edge count (now 484)",
    "475 host": "old exposure (now 469)",
    "475 machines": "old exposure (now 469)",
    "18 crown jewels": "old crown jewels (now 16)",
    "51.4": "old TPR@1%FPR (now 87.7)",
    "0.929": "old behavioural-only ROC (now 0.906)",
    "96.9": "old TPR@5%FPR (now 96.6)",
    "680/702": "old catch count (now 678/702)",
    "680 / 702": "old catch count (now 678/702)",
    "36.5": "old shipped predictor (now 38.1)",
    "5.2x": "old anti-circularity (now 5.4x)",
    "5.2×": "old anti-circularity (now 5.4x)",
    "5.2 times": "old anti-circularity (now 5.4x)",
    "28.4": "old LSTM top-3 (now 27.2)",
    "5.3%": "old most-frequent top-3 (now 4.9%)",
    "the real IsolationForest": "IsolationForest described as the shipped detector",
    "Markov shipped": "first-order Markov described as shipped",
    "Markov (shipped)": "first-order Markov described as shipped",
}

# lines containing any of these are expected comparisons, not stale claims
ALLOW = (
    "previous", "iforest", "isolation forest", "isolationforest",
    "1st-order", "1st order", "first order", "first-order",
    "comparison", "replaced", "was ", "old ", "instead of", "against",
    "markov_top3", "lost", "bake-off", "experiment", "interpolated",
)


def main() -> None:
    import sys
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass
    findings, allowed = [], 0
    for p in sorted(ROOT.rglob("*")):
        if not p.is_file() or p.suffix.lower() not in EXT:
            continue
        if any(s in p.parts for s in SKIP):
            continue
        rel = p.relative_to(ROOT).as_posix()
        if (rel.startswith("reports/model_experiments") or rel == "scripts/audit_stale.py"
                or rel.endswith("package-lock.json")
                or rel == "PPT_CHANGES.md"):  # a change-list; it cites old->new on purpose
            continue                                  # the bake-off must cite old numbers
        try:
            txt = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for i, line in enumerate(txt.split("\n"), 1):
            low = line.lower()
            for tok, why in STALE.items():
                if tok in line:
                    if any(a in low for a in ALLOW):
                        allowed += 1
                        continue
                    findings.append((rel, i, tok, why, line.strip()[:100]))

    if not findings:
        print(f"CLEAN - no stale claims found ({allowed} legitimate comparison lines skipped)")
        return
    print(f"{len(findings)} possible stale claims "
          f"({allowed} legitimate comparison lines skipped)\n")
    cur = None
    for rel, i, tok, why, line in findings:
        if rel != cur:
            print(rel)
            cur = rel
        print(f"   {i:>4} [{tok}] {why}")
        print(f"        {line}")
    raise SystemExit(1)


if __name__ == "__main__":
    main()
