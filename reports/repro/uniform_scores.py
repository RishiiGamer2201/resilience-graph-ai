#!/usr/bin/env python3
"""Reproduce the two P0 findings in reports/backend_audit.md.

    python3 reports/repro/uniform_scores.py

Prints a table per finding and exits non-zero while the defects are present, so
it doubles as a regression check once they are fixed.

FINDING P0-1. A uniform log always reports "1 alert, critical", whatever it
contains. Ten benign Kerberos logons and a thousand failed NTLM logons against
one host produce identical output. Only the first-occurrence flags vary in such
a log, so exactly one event is an outlier, and `relative_anchors` scores it 100
because the log's own p99 is the only thing available to rank against.

FINDING P0-2. `is_fail` and `is_ntlm` are exact string comparisons, so a log
that spells failure "failure" or a package "NTLMv2" silently loses the feature.
The repo's own ablation puts the NTLM feature at 74% of TPR@1%FPR, so the
second one is not cosmetic.
"""
from __future__ import annotations

import io
import pathlib
import sys
import warnings

warnings.filterwarnings("ignore")

# Runnable from anywhere, which is the point of a repro script.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

import numpy as np
import pandas as pd

from src.engine1.lanl_detect import engineer
from src.shared.detector import TRIAGE_PERCENTILE, calibrate, relative_anchors
from src.shared.live_analyze import analyze_events

COLS = ("timestamp,user,source_host,destination_host,event_type,status,"
        "protocol,port,bytes_out,command,asset_criticality,label")


def row(t, user="u@D", src="A", dst="B", status="success", proto="Kerberos"):
    return f"{t},{user},{src},{dst},auth,{status},{proto},445,0,,medium,0"


def frame(rows):
    return pd.read_csv(io.StringIO(COLS + "\n" + "\n".join(rows)))


def p0_1_uniform_collapse() -> bool:
    """A degenerate distribution calibrates to all zeros. Returns True if broken."""
    print("P0-1  uniform reconstruction error -> every score 0")
    print(f"      TRIAGE_PERCENTILE = {TRIAGE_PERCENTILE}\n")
    broken = False
    for name, raw in (
        ("all identical", np.full(60, 0.42)),
        ("59 same + 1 high", np.array([0.42] * 59 + [9.9])),
        ("spread", np.linspace(0.1, 2.0, 60)),
    ):
        ref = relative_anchors(raw, TRIAGE_PERCENTILE)
        s = np.asarray(calibrate(raw, ref))
        alerting = int((s >= 50).sum())
        degenerate = ref["p50"] == ref["p99"]
        print(f"      {name:18} p50={ref['p50']:.3f} p99={ref['p99']:.3f} "
              f"max={s.max():5.1f} alerting={alerting}/{len(s)}"
              f"{'   <-- p50 == p99' if degenerate else ''}")
        if degenerate and alerting == 0 and s.max() == 0:
            broken = True
    print()
    return broken


def p0_1_end_to_end() -> bool:
    """The same collapse through the shipped pipeline. Returns True if broken."""
    print("P0-1  end to end: what the product reports")
    print(f"      {'log':38} {'alerts':>6}  {'severity':<9} sample")
    cases = (
        ("10 NTLM failures A->B",
         [row(i, status="fail", proto="NTLM") for i in range(10)]),
        ("1000 NTLM failures A->B",
         [row(i, status="fail", proto="NTLM") for i in range(1000)]),
        ("10 identical BENIGN successes",
         [row(i) for i in range(10)]),
        ("1000 identical BENIGN successes",
         [row(i) for i in range(1000)]),
        # The control: give the same attack somewhere to fan out to and the
        # pipeline behaves, which is what isolates the defect above.
        ("60 failures spread over 20 hosts (control)",
         [row(i, dst=f"B{i % 20}", status="fail", proto="NTLM") for i in range(60)]),
    )
    seen = {}
    for name, rows in cases:
        b = analyze_events(frame(rows), critical_assets=set(), incident_id="X")
        inc = b["incident"]
        conf = (b["meta"].get("calibration") or {}).get("sample_confidence")
        print(f"      {name:38} {inc['alert_count']:>6}  {inc['severity']:<9} {conf}")
        seen[name] = (inc["alert_count"], inc["severity"])

    # The defect is that these are all the SAME. An attack of any size and a
    # benign log of any size both report one alert at critical.
    uniform = [v for k, v in seen.items() if "spread" not in k]
    print()
    broken = len(set(uniform)) == 1 and uniform[0][0] == 1
    if broken:
        n, sev = uniform[0]
        print(f"      BROKEN: every uniform log above reports {n} alert, {sev} --")
        print("              a 1,000-event brute force and 10 benign logons alike.")
    print()
    return broken


def p0_2_vocabulary() -> bool:
    """Exact-match features die on ordinary synonyms. Returns True if broken."""
    print("P0-2  exact string comparison in engineer()")
    broken = False
    for col, feat, values in (
        ("status", "is_fail",
         ["fail", "Fail", "FAIL", "failure", "failed", "Failure", "denied", "0", "false"]),
        ("protocol", "is_ntlm",
         ["NTLM", "ntlm", "Ntlm", "NTLMv2", "NTLM-v2"]),
    ):
        print(f"\n      {feat} from `{col}`")
        for v in values:
            rows = [row(i, dst=f"B{i}",
                        status=v if col == "status" else "success",
                        proto=v if col == "protocol" else "Kerberos")
                    for i in range(5)]
            fired = int(engineer(frame(rows))[feat].sum())
            flag = "" if fired else "   <-- SILENTLY DEAD"
            print(f"        {col}={v!r:12} -> fires {fired}/5{flag}")
            if not fired:
                broken = True
    print()
    return broken


def main() -> int:
    print(__doc__.split("\n\n")[0])
    print("=" * 72, "\n")
    bad = [
        p0_1_uniform_collapse(),
        p0_1_end_to_end(),
        p0_2_vocabulary(),
    ]
    if any(bad):
        print("=" * 72)
        print(f"{sum(bad)} of 3 checks reproduce a defect. See "
              "reports/backend_audit.md.")
        return 1
    print("all three checks are clean: the P0 findings are fixed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
