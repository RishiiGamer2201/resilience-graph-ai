"""Refresh only cached actor-profile and report attribution payloads.

The full cache builder also fetches external threat intelligence and rewrites
unrelated files. This targeted command reruns the shipped sample through the
live analysis path, writes only the two consumers affected by the attribution
contract, and preserves the report's display timestamp so repeated runs are
byte-identical.
"""
from __future__ import annotations

import json
import subprocess

import pandas as pd

from scripts.build_cache import CACHE, ROOT, SCENARIO, demo_critical
from src.shared.live_analyze import analyze_events


def _load(name: str) -> dict:
    path = CACHE / f"{name}.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def _committed_or_current(name: str) -> dict:
    """Read HEAD's payload so an earlier local refresh cannot leak unrelated drift."""
    result = subprocess.run(
        ["git", "show", f"HEAD:api/cache/{name}.json"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    return json.loads(result.stdout) if result.returncode == 0 else _load(name)


def _write(name: str, payload: dict) -> None:
    path = CACHE / f"{name}.json"
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"refreshed {path.relative_to(CACHE.parents[1])}")


def main() -> None:
    previous_report = _committed_or_current("report")
    events = pd.read_csv(SCENARIO)
    bundle = analyze_events(
        events,
        critical_assets=demo_critical(),
        incident_id="INC-PS7-LANL-CAMPAIGN",
    )
    current_report = bundle["report"]
    report = previous_report or current_report
    # This issue changes only the attribution contract. Preserve every other
    # cached report field byte-for-byte instead of allowing graph tie-breaking,
    # timestamps, or unrelated model output to drift into the PR.
    report["attributed_actor"] = current_report["attributed_actor"]
    report["attribution_assessment"] = current_report["attribution_assessment"]
    methodology = _committed_or_current("methodology")
    methodology["honesty_notes"] = [
        ("Crown jewels are a stated heuristic (hosts the most accounts depend on), "
         "not a dataset label; actor names are similar public ATT&CK profiles, and "
         "attribution abstains until independently calibrated thresholds exist."
         if note.startswith("Crown jewels are a stated heuristic") else note)
        for note in methodology.get("honesty_notes", [])
    ]
    _write("threat_intel", bundle["threat_intel"])
    _write("report", report)
    _write("methodology", methodology)


if __name__ == "__main__":
    main()
