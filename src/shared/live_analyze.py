"""
Live analysis engine — run the WHOLE spine on an arbitrary event log at request
time. This is what makes the SOC Command Center actually work rather than replay
one pre-baked incident: feed it events (a CSV/rows in the common schema) and it
scores every event with the shipped autoencoder, correlates the alerts into
incidents, builds the attack-path graph, gates SOAR, attributes an actor, and
predicts the next technique — all computed live.

    from src.shared.live_analyze import analyze_events
    bundle = analyze_events(df, critical_assets={"C2388"}, incident_id="INC-LIVE-001")

`bundle` has the same per-screen shapes the cached endpoints serve
(overview / incident / graph / threat_intel / report) plus a `meta` block, so the
frontend renders a live result through the exact same screens.
"""
from __future__ import annotations

import pickle
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from src.engine1.lanl_detect import FEATURES, engineer
from src.schema import coerce, validate
from src.shared.attack_graph import analyze, build_graph
from src.shared.correlate import correlate
from src.shared.soar import recommend
from src.shared.timeutil import fmt_ist
from src.shared import views
from src.shared import detector

ROOT = Path(__file__).resolve().parents[2]
LANL_MODEL = ROOT / "models" / "iforest_lanl.joblib"
SCORE_REF = ROOT / "api" / "cache" / "score_ref.json"

MAX_ROWS = 50_000          # trust boundary: reject oversized uploads

_state: dict = {}


def _ref():
    if "ref" not in _state:
        import json
        _state["ref"] = json.loads(SCORE_REF.read_text())
    return _state["ref"]


def _score(df: pd.DataFrame) -> tuple[np.ndarray, dict]:
    """Score every row 0-100 with the shipped LANL detector.

    Fixed `score_ref` anchors by default, so a score means the same thing across
    two uploads and matches the /score-event endpoint.

    Out-of-distribution logs are the exception. The shipped anchors were measured
    on LANL, and a log whose host population is shaped differently lands entirely
    above the alert line regardless of content -- the measured failure on the
    synthetic India scenarios, where 125 of 125 events alerted. Those are scored
    by RANK within themselves, and the returned `calibration` block says so, so
    no surface can quote such a score as if it were comparable to a LANL one.

    Below MIN_SAMPLE events nothing is claimed at all: a corpus statistic taken
    over a handful of rows is not a measurement, and saying so is more useful
    than returning a confident zero.
    """
    X = df[FEATURES].to_numpy("float64")
    # Rows the detector cannot score at all: a blank destination makes dst_rarity
    # NaN, and a NaN feature makes the whole reconstruction error NaN. These were
    # silently coerced to 0 -- the lowest possible score -- so an event with a
    # missing field looked like the most ordinary event in the log, and nothing
    # anywhere said how many there were.
    unscorable = ~np.isfinite(X).all(axis=1)
    n_unscored = int(unscorable.sum())
    raw = detector.raw_scores(X)
    ref = _ref()

    counts = df["destination_host"].value_counts().to_numpy()
    ood, top1 = detector.out_of_distribution(X, dst_counts=counts)
    # The EFFECTIVE sample is the number of usable destination observations, not
    # the row count. A 40-row log with 18 blank destinations has 22 of them, and
    # judging the verdict on 22 while describing it as 40 produced a note that
    # argued against itself: "one destination takes 14%, against a 30% limit,
    # so the anchor does not transfer".
    usable = int(counts.sum())
    confidence = detector.sample_confidence(usable)

    if ood:
        ref = detector.relative_anchors(raw)

    scores = detector.calibrate(raw, ref).round()
    scores = np.nan_to_num(scores, nan=0.0, posinf=100.0, neginf=0.0)

    # The note states the ACTUAL trigger. It used to describe concentration in
    # every case, so a 40-row log that tripped the sample gate was told "one
    # destination takes 9% of the authentications, so the anchor does not
    # transfer" -- 9% against a 30% threshold argues the opposite, and a log with
    # no destinations at all was told one took 100%.
    if confidence == "insufficient":
        blanks = len(df) - usable
        shortfall = (f"Only {usable} of {len(df)} events name a destination"
                     if blanks else f"Only {usable} events")
        note = (f"{shortfall}. Below {detector.MIN_SAMPLE} there is no corpus to "
                f"compare against: host rarity, fan-out and the concentration test "
                f"all need a population. Scores are ranked within what you supplied "
                f"and should be read as an ordering, not as severities.")
    elif ood and top1 is not None:
        note = (f"One destination takes {top1:.0%} of the authentications in this log, "
                f"against a {detector.CONCENTRATION_LIMIT:.0%} limit. The corpus the "
                f"detector was calibrated on has a long tail (LANL's busiest "
                f"destination takes 6%), so the shipped 1%-false-positive anchor does "
                f"not transfer. Events are RANKED within this log and the top "
                f"{100 - ref.get('triage_percentile', 80)}% are surfaced for triage. "
                f"That cut is an operational choice, not a measured false-positive "
                f"rate, and these scores are not comparable with scores from another log.")
    elif ood:
        note = ("This log has no usable destination field, so the corpus test could "
                "not run. Events are ranked within the log rather than scored on the "
                "shipped scale.")
    elif confidence == "low":
        # The caveat FADES rather than switching off at exactly MIN_SAMPLE. One
        # extra benign row used to buy the difference between a 21% alert rate
        # with an explanation and a 73% one with none.
        note = (f"{len(df)} events. The corpus test passed, but a top-destination "
                f"share over this few events is noisy -- one busy host moves it "
                f"several points, where over {detector.RELIABLE_SAMPLE}+ it barely "
                f"moves. Scores use the shipped scale, and the judgement that this "
                f"log resembles the calibration corpus is low-confidence at this size.")
    else:
        note = ""

    if n_unscored:
        quality = (f"{n_unscored} of {len(df)} events could not be scored: a blank or "
                   f"unparseable field leaves the behavioural features undefined for "
                   f"that row. They are shown at 0 and are NOT evidence of anything "
                   f"-- an unscored event is missing data, not a quiet one.")
        note = f"{note} {quality}".strip() if note else quality

    return scores, {
        "basis": ref.get("basis", "fixed-anchors-lanl"),
        "out_of_distribution": ood,
        "insufficient_sample": confidence == "insufficient",
        "sample_confidence": confidence,
        "unscored_events": n_unscored,
        "top_destination_share": top1,
        # kept beside the verdict because it is informative, and explicitly not
        # the verdict: it is a log-size test, see detector.out_of_distribution
        "rarity_shift_sigma": detector.rarity_shift(X),
        "note": note,
    }


def _prepare(df: pd.DataFrame) -> pd.DataFrame:
    """Coerce to the common schema and ensure the columns engineer() reads exist."""
    if len(df) > MAX_ROWS:
        raise ValueError(f"too many events ({len(df)} > {MAX_ROWS}); upload a focused window")
    if df.empty:
        raise ValueError("no events provided")
    df = coerce(df)
    validate(df)
    for col, default in (("status", "success"), ("protocol", "")):
        if col not in df.columns:
            df[col] = default
    if not (df["user"].astype(str).str.len() > 0).any():
        raise ValueError(
            "events need a 'user' column (behavioral features are per-user). "
            "Accepted names: user, username, account, principal, src_user. "
            "Also need source_host/destination_host (aliases: src/dst, source/destination).")
    return df


# Only `insufficient` caps, and the reason is the detector's own definition of
# the two words: below MIN_SAMPLE=30 "no corpus statistic means anything", while
# below RELIABLE_SAMPLE=300 the statistic is "noisy, not absent". A noisy
# statistic still carries signal and should not have its verdict overridden; an
# absent one should.
#
# Capping `low` as well was tried and reverted. It is the stricter reading, but
# it downgraded both shipped 125-event scenarios from critical to high on a
# sample the code itself says is usable -- trading a real finding for a caveat
# that was already printed beside it.
_SEV_CAP = {"insufficient": "medium"}


def _cap_severity(incident: dict, cal: dict) -> None:
    """Do not report a severity the sample cannot support.

    `correlate._severity` is `max(anomaly_score)` and nothing else. Under
    `relative_anchors` the top of ANY distribution is 100, so a twelve-row log
    of self-authentications came back `critical` -- while the calibration block
    sitting beside it already said `sample_confidence: insufficient`.

    The caveat was computed and published and then nothing consumed it. This
    consumes it. The cap is stated in the incident so the reduction is visible
    rather than silent, and the original is kept so nothing is lost.
    """
    conf = cal.get("sample_confidence")
    cap = _SEV_CAP.get(conf)
    if not cap:
        return
    order = ["low", "medium", "high", "critical"]
    was = incident.get("severity")
    if was not in order or order.index(was) <= order.index(cap):
        return
    incident["severity"] = cap
    incident["severity_uncapped"] = was
    incident["severity_note"] = (
        f"reported as {cap}, not {was}: the sample is {conf} "
        f"({cal.get('note') and 'see the calibration note' or 'too small'}), "
        f"and a severity is only as good as the distribution behind it")


def analyze_events(df: pd.DataFrame, critical_assets: set[str] | None = None,
                   incident_id: str = "INC-LIVE-001", account: str | None = None) -> dict:
    """Run score → correlate → graph → SOAR → attribute → report on `df` live.

    `account` scopes the analysis to one compromised account within a campaign log
    (the per-account incident). Features are engineered on the FULL log first, then
    filtered — a user's behavioural baseline (fan-out, host rarity) must be computed
    against everything that happened, not against the slice we're looking at.
    """
    critical_assets = set(critical_assets or set())
    df = _prepare(df)
    df = engineer(df)                       # 7 behavioral features, per-user chronological
    scores, calibration = _score(df)
    # A row with a missing host yields a NaN feature and therefore a NaN score.
    # astype(int) turned that into 0 with only a RuntimeWarning, so the event we
    # would most want to look at scored lowest possible. Treat it as unscored.
    scores = np.nan_to_num(scores, nan=0.0, posinf=100.0, neginf=0.0)
    df["anomaly_score"] = scores.astype(int)
    if account:
        df = df[df["user"].astype(str) == account]
        if df.empty:
            raise ValueError(f"no events for account '{account}' in this log")

    incident = correlate(df, incident_id=incident_id)
    _cap_severity(incident, calibration)
    g = build_graph(incident, critical_assets=critical_assets)
    ga = analyze(g, critical_assets=critical_assets)
    soar = recommend(incident, ga)

    # victim = account with the most alerts (label-free); pivot = graph entry host
    alert_users = [s["user"] for s in incident["alerts"] if s["user"]]
    victim = max(set(alert_users), key=alert_users.count) if alert_users else (
        df["user"].dropna().iloc[0] if len(df) else "—")
    pivot = ga.get("entry_host") or "—"

    full = {
        "victim": victim, "pivot": pivot,
        "critical_assets": sorted(critical_assets),
        "incident": incident, "graph": ga, "soar": soar,
    }

    meta = {"source": "live", "n_events": int(len(df)),
            "analyzed_at": fmt_ist(),
            "account": account,
            "accounts_involved": len(incident.get("users_involved", [])),
            "critical_assets": sorted(critical_assets),
            # How these scores were calibrated, and whether they are comparable
            # with any other run. Travels with every bundle so a screen can never
            # present a log-relative score as if it were the shipped scale.
            "calibration": calibration}

    return {
        "overview": views.overview(full, views.SCORECARD),
        "incident": views.incident_view(full),
        "graph": views.graph_view(full),
        "threat_intel": views.threat_intel_view(full),
        "report": views.report_view(full),
        "attackers": views.attackers_view(full),
        # the raw gated-SOAR dict, so the investigation workflow can re-gate the
        # same actions against RBAC policy instead of re-deriving them
        "soar": soar,
        "meta": meta,
    }


def analyze_csv(path: str | Path, **kw) -> dict:
    return analyze_events(pd.read_csv(path), **kw)


if __name__ == "__main__":
    # self-check on the shipped LANL scenario (if exported)
    import json
    scen = ROOT / "data" / "demo" / "scenarios" / "lanl_redteam_u66.csv"
    if scen.exists():
        b = analyze_events(pd.read_csv(scen), critical_assets={"C2388"})
        print(json.dumps({k: (v if k == "meta" else "...") for k, v in b.items()}, indent=2))
        print("incident:", b["incident"]["alert_count"], "alerts,",
              b["incident"]["event_count"], "events, pivot", b["incident"]["pivot"])
    else:
        print(f"scenario not found: {scen} — run scripts/export_demo_events.py first")
