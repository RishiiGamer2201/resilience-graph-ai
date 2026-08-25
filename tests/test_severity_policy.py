"""One severity policy, asserted at every boundary and in every place it is used.

Issue #43: the bands were written out five times and two copies disagreed, so a
score of 72 was `high` on the single-event endpoint and the attacker table and
`medium` on the incident it belonged to. These tests fail if any copy comes
back.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from src.shared.severity import (BAND_CRITICAL, BAND_HIGH, BAND_MEDIUM,
                                 policy, severity_from_score)
from src.shared.thresholds import ALERT_SCORE

ROOT = Path(__file__).resolve().parents[1]

# The boundaries the issue asks for, plus the value either side of each band.
BOUNDARIES = [
    (44, "low"), (45, "low"), (49, "low"),          # 45 used to be `medium`
    (50, "medium"), (69, "medium"),
    (70, "medium"), (74, "medium"),                 # 70 used to be `high`
    (75, "high"), (89, "high"),
    (90, "critical"),
]


@pytest.mark.parametrize("score,expected", BOUNDARIES)
def test_the_bands_are_what_the_policy_says(score, expected):
    assert severity_from_score(score) == expected


@pytest.mark.parametrize("score,expected", BOUNDARIES)
def test_every_caller_agrees_at_every_boundary(score, expected):
    """The actual point of #43. Three implementations, one answer.

    Each of these had its own copy of the thresholds. They are called through
    their real entry points rather than the shared helper, so delegating in only
    two of the three would still fail here.
    """
    from api.main import _severity as api_severity
    from src.shared.correlate import _severity as incident_severity
    from src.shared.views import severity_from_score as attacker_severity

    assert api_severity(score) == expected
    assert incident_severity([{"anomaly_score": score}])[0] == expected
    assert attacker_severity(score) == expected


def test_medium_begins_exactly_at_the_alert_line():
    """Not a style choice. Under the old 45 bands a score of 47 was labelled
    `medium` while the detector declined to raise it as an alert -- the product
    asserting a severity and withholding the alert for the same number."""
    assert BAND_MEDIUM == ALERT_SCORE
    assert severity_from_score(ALERT_SCORE) == "medium"
    assert severity_from_score(ALERT_SCORE - 1) == "low"


def test_a_missing_score_does_not_raise():
    """Called while rendering a payload; a null score must not take down a
    response that has already done all of its real work."""
    for bad in (None, "", "n/a", float("nan")):
        assert severity_from_score(bad) in ("low", "medium", "high", "critical")


def test_the_policy_is_reported_as_data():
    p = policy()
    assert p["version"]
    assert p["bands"] == {"critical": BAND_CRITICAL, "high": BAND_HIGH,
                          "medium": BAND_MEDIUM, "low": 0}


def test_the_policy_version_reaches_the_audit_chain():
    """A stored severity is only meaningful against the bands that produced it."""
    from src.shared.audit import artifact_versions
    assert artifact_versions()["severity_policy"] == policy()["version"]


def test_the_policy_version_travels_with_an_analysis():
    import pandas as pd

    from src.shared.live_analyze import analyze_events
    scen = ROOT / "data" / "demo" / "scenarios" / "aiims_ransomware.csv"
    if not scen.exists():                      # pragma: no cover
        pytest.skip("demo scenario not exported")
    bundle = analyze_events(pd.read_csv(scen), critical_assets=set(),
                            incident_id="INC-SEV")
    assert bundle["meta"]["severity_policy"]["version"] == policy()["version"]


# --------------------------------------------------------------------------- #
# no copy of the bands may come back                                           #
# --------------------------------------------------------------------------- #
def test_no_module_carries_its_own_anomaly_bands():
    """Greps for the shape of the bug rather than its location.

    The five copies were spread over python and typescript; a sixth would be
    added the same way. Anything matching a literal band comparison in the
    files that render an anomaly severity fails here.
    """
    suspects = [
        ROOT / "api" / "main.py",
        ROOT / "src" / "shared" / "correlate.py",
        ROOT / "src" / "shared" / "views.py",
        ROOT / "frontend" / "src" / "lib" / "format.ts",
        ROOT / "frontend" / "src" / "components" / "AttackGraph2D.tsx",
    ]
    import re
    # a literal threshold compared against, next to a severity word
    pattern = re.compile(r">=\s*(45|70)\b")
    for path in suspects:
        if not path.exists():                  # pragma: no cover
            continue
        for i, line in enumerate(path.read_text().splitlines(), 1):
            if pattern.search(line) and re.search(r"critical|high|medium|sev", line, re.I):
                raise AssertionError(
                    f"{path.relative_to(ROOT)}:{i} carries its own severity band: {line.strip()}")


def test_the_typescript_bands_match_the_python_ones():
    """format.ts is the single TS source; it must not drift from severity.py."""
    fmt = (ROOT / "frontend" / "src" / "lib" / "format.ts").read_text()
    import re
    m = re.search(r"SEVERITY_BANDS\s*=\s*\{([^}]*)\}", fmt)
    assert m, "SEVERITY_BANDS not found in format.ts"
    got = dict(re.findall(r"(\w+)\s*:\s*(\d+)", m.group(1)))
    assert int(got["critical"]) == BAND_CRITICAL
    assert int(got["high"]) == BAND_HIGH
    assert int(got["medium"]) == BAND_MEDIUM


# --------------------------------------------------------------------------- #
# cached artifacts were built under the old policy                             #
# --------------------------------------------------------------------------- #
def test_the_cached_sample_agrees_with_the_current_policy():
    """The committed cache carries severities. Regenerating it is part of the
    change, because a cached bundle disagreeing with a freshly analysed log is
    the same bug wearing a different hat."""
    disagreements = []
    for name in ("incident.json", "attackers.json", "overview.json", "graph.json"):
        path = ROOT / "api" / "cache" / name
        if not path.exists():                  # pragma: no cover
            continue
        _walk(json.loads(path.read_text()), name, disagreements)
    assert not disagreements, (
        "cached severities disagree with the current policy -- rerun "
        "`python -m scripts.build_cache`:\n  " + "\n  ".join(disagreements[:10]))


def _walk(node, where, out):
    """Any dict whose severity came from an anomaly score must match the policy.

    `risk_band` marks the prioritiser's 0-1 chain risk, which is a different
    measurement with its own bands (src/agents/prioritizer.py). Those entries
    copy `risk_band` into `severity` and happen to carry `max_anomaly_score`
    alongside it, so comparing the two would flag correct data -- and unifying
    them would be the mistake src/shared/severity.py exists to prevent.
    """
    if isinstance(node, dict):
        chain_risk = "risk_band" in node or "risk_score" in node
        score = node.get("max_anomaly_score", node.get("max_score", node.get("anomaly_score")))
        sev = node.get("severity")
        if not chain_risk and isinstance(sev, str) and isinstance(score, (int, float)):
            want = severity_from_score(score)
            if sev != want:
                out.append(f"{where}: score {score} labelled {sev!r}, policy says {want!r}")
        for k, v in node.items():
            _walk(v, f"{where}/{k}", out)
    elif isinstance(node, list):
        for i, v in enumerate(node[:200]):
            _walk(v, f"{where}[{i}]", out)
