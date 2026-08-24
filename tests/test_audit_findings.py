"""Regression tests for the audit findings (GitHub issues #2 to #14).

One test per finding, each asserting the fixed behaviour rather than the
implementation, so a future refactor is free to change how and not whether.
"""
from __future__ import annotations

import io
import pathlib
import tempfile

import pandas as pd
import pytest
from fastapi.testclient import TestClient

from api.main import app
from src.engine1.lanl_detect import engineer
from src.shared.live_analyze import analyze_events

client = TestClient(app)
ANALYST = {"X-Role": "analyst", "X-Actor": "audit-tests@soc"}

COLS = ("timestamp,user,source_host,destination_host,event_type,status,"
        "protocol,port,bytes_out,command,asset_criticality,label")


def _frame(rows: list[str]) -> pd.DataFrame:
    return pd.read_csv(io.StringIO(COLS + "\n" + "\n".join(rows)))


def _row(t, dst="B", status="fail", proto="NTLM", user="u@D"):
    return f"{t},{user},A,{dst},auth,{status},{proto},445,0,,medium,0"


# --------------------------------------------------------------------------- #
# #2 -- exact string matching killed two of seven features                     #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("spelling", ["fail", "Fail", "FAIL", "failure",
                                      "failed", "Failure", "denied"])
def test_is_fail_fires_on_every_spelling_a_real_export_uses(spelling):
    got = engineer(_frame([_row(i, dst=f"B{i}", status=spelling) for i in range(5)]))
    assert got["is_fail"].sum() == 5, (
        f"status={spelling!r} left is_fail at 0. Every shipped scenario says "
        f"'fail', so this only ever broke on an uploaded log -- silently.")


@pytest.mark.parametrize("proto", ["NTLM", "ntlm", "Ntlm", "NTLMv2", "NTLM-v2"])
def test_is_ntlm_fires_on_negotiated_package_names(proto):
    got = engineer(_frame([_row(i, dst=f"B{i}", proto=proto) for i in range(5)]))
    assert got["is_ntlm"].sum() == 5, (
        f"protocol={proto!r} left is_ntlm at 0. Windows logs the negotiated "
        f"package, and the ablation puts this feature at 74% of TPR@1%FPR.")


def test_the_same_attack_scores_the_same_whichever_word_the_log_uses():
    a = analyze_events(_frame([_row(i, status="fail") for i in range(60)]),
                       critical_assets=set(), incident_id="X")["incident"]
    b = analyze_events(_frame([_row(i, status="failure") for i in range(60)]),
                       critical_assets=set(), incident_id="X")["incident"]
    assert a["alert_count"] == b["alert_count"]
    assert a["severity"] == b["severity"]


# --------------------------------------------------------------------------- #
# #3 -- a collapsed score scale must not assert a severity                     #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("n", [10, 200, 1000])
def test_a_uniform_log_reports_a_collapsed_scale_and_is_capped(n):
    """Volume must not buy confidence a uniform log cannot support.

    1,000 identical events have an `ok` sample and still no distribution, so
    sample_confidence alone could never catch this one.
    """
    b = analyze_events(_frame([_row(i) for i in range(n)]),
                       critical_assets=set(), incident_id="X")
    cal, inc = b["meta"]["calibration"], b["incident"]
    assert cal["scale_collapsed"] is True
    assert cal["operational"] is False
    assert inc["alert_count"] == 0
    assert inc["max_anomaly_score"] == 0
    assert inc["operational_status"] == "suppressed-collapsed-scale"
    assert inc["severity"] != "critical", (
        f"{n} identical events reported {inc['severity']} off a scale where "
        f"the median and the triage cut coincide")
    assert "no distribution to rank within" in cal["note"]


def test_a_varied_log_is_not_capped():
    b = analyze_events(_frame([_row(i, dst=f"B{i % 20}") for i in range(60)]),
                       critical_assets=set(), incident_id="X")
    assert b["meta"]["calibration"]["scale_collapsed"] is False
    assert "severity_uncapped" not in b["incident"]


def test_the_shipped_scenarios_are_untouched():
    """The fixes must not soften the demo. Both heroes stay critical."""
    root = pathlib.Path(__file__).resolve().parents[1]
    for name in ("aiims_ransomware", "cbse_exam_breach"):
        df = pd.read_csv(root / "data" / "demo" / "scenarios" / f"{name}.csv")
        b = analyze_events(df, critical_assets=set(), incident_id="X")
        assert b["meta"]["calibration"]["scale_collapsed"] is False, name
        assert b["incident"]["severity"] == "critical", name


# --------------------------------------------------------------------------- #
# #4 -- severity must respect the sample confidence already computed           #
# --------------------------------------------------------------------------- #
def test_an_insufficient_sample_caps_severity_and_says_why():
    b = analyze_events(_frame([_row(i, dst=f"A{i}") for i in range(12)]),
                       critical_assets=set(), incident_id="X")
    inc = b["incident"]
    assert inc["severity_uncapped"] == "critical"
    assert inc["severity"] != "critical"
    assert inc["severity_note"]


# --------------------------------------------------------------------------- #
# #5 -- the three unguarded POSTs                                             #
# --------------------------------------------------------------------------- #
def test_threat_radar_refuses_a_viewer_because_it_can_trigger_egress():
    """It answered 200 with NO header at all, and refresh:true fetches from
    third-party CTI feeds. An unknown role now falls back to `viewer`, and a
    viewer cannot reach an egress trigger."""
    r = client.post("/api/threat-radar", json={"refresh": False},
                    headers={"X-Role": "nobody"})
    assert r.status_code == 403, r.status_code
    assert client.post("/api/threat-radar", json={"refresh": False},
                       headers=ANALYST).status_code == 200


@pytest.mark.parametrize("path", ["/api/retrieve", "/api/retrieve/incident"])
def test_the_retrieval_routes_authorise_at_all(path):
    """These had no authorisation call whatsoever. They require `read` now --
    which a viewer legitimately has, so the assertion is about the call
    existing, not about refusing a reader."""
    import inspect

    from api.main import app

    route = next(r for r in app.routes if getattr(r, "path", None) == path)
    src = inspect.getsource(route.endpoint)
    assert '_require(p, "read")' in src, f"{path} does not authorise"
    assert "Depends(analyze_principal)" in src, f"{path} resolves no principal"


# --------------------------------------------------------------------------- #
# #8 -- retrieval models were the only unbounded ones                          #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("body", [
    {"query": "x", "top_k": 999999999},
    {"query": "x", "top_k": 0},
    {"query": "A" * 5000, "top_k": 5},
])
def test_retrieval_bounds_are_enforced_by_validation(body):
    assert client.post("/api/retrieve", json=body, headers=ANALYST).status_code == 422


# --------------------------------------------------------------------------- #
# #6 / #7 -- an honest denominator, and a fraction instead of magic numbers    #
# --------------------------------------------------------------------------- #
def test_an_unavailable_probe_shrinks_the_denominator_not_the_score():
    from src.agents.validator import TOTAL_SIGNALS, _tag_confidence

    _, all_probes = _tag_confidence(2, 0)
    _, one_missing = _tag_confidence(2, 1)
    assert one_missing > all_probes, (
        "a probe that could not run must not be scored as a failure: the "
        "deploy image ships without the vector store")
    assert _tag_confidence(TOTAL_SIGNALS, 0)[1] == 1.0
    assert 0.0 <= _tag_confidence(0, 0)[1] <= 1.0


def test_the_evidence_probes_can_say_they_could_not_answer():
    from src.agents import validator

    assert validator.UNAVAILABLE is None
    # A nonsense id must be a real 0 or an honest UNAVAILABLE, never a crash.
    assert validator._evidence_search("T0000") in (0, 1, validator.UNAVAILABLE)
    assert validator._rag_search("T0000", "") in (0, 1, validator.UNAVAILABLE)


# --------------------------------------------------------------------------- #
# #10 -- a library must not import the API layer                               #
# --------------------------------------------------------------------------- #
def test_no_module_under_src_imports_the_api_layer():
    root = pathlib.Path(__file__).resolve().parents[1] / "src"
    offenders = [
        f"{p.relative_to(root)}:{i}"
        for p in root.rglob("*.py")
        for i, line in enumerate(p.read_text().split("\n"), 1)
        if line.strip().startswith(("from api.", "import api."))
    ]
    assert not offenders, (
        f"src/ must not depend on api/: {offenders}. That inversion is why the "
        f"call had to be wrapped in a bare except, which then hid a failed "
        f"graph mapping behind a bundle still claiming standard+10-agent.")


# --------------------------------------------------------------------------- #
# #11 -- the audit chain survives a restart                                    #
# --------------------------------------------------------------------------- #
def test_a_durable_chain_resumes_and_still_detects_tampering():
    from src.shared.audit import AuditChain

    path = pathlib.Path(tempfile.mkdtemp()) / "chain.db"
    first = AuditChain({"detector": "x"}, path=path)
    first.append("analysis.completed", actor="a@soc", role="analyst", reason="one")
    assert first.durable is True

    resumed = AuditChain({"detector": "x"}, path=path)      # a restart
    assert len(resumed) == len(first)
    assert resumed.head() == first.head()
    assert resumed.verify()[0] is True

    recs = resumed.records()
    recs[1]["reason"] = "tampered"
    ok, problem = AuditChain.verify_records(recs)
    assert ok is False and problem

    assert AuditChain({"detector": "x"}, path=None).durable is False


def test_the_verify_endpoint_reports_whether_the_chain_is_durable():
    """Durability is opt-in, so the endpoint has to SAY which mode is running.

    Durable-by-default was tried and reverted: it pointed every process at one
    file, two AuditChain objects assigned the same seq, and the linkage broke
    at record 463 of 572. An audit log a second writer can corrupt is worse
    than one that does not persist -- so the default is off and a seq collision
    now raises instead of silently replacing a row.
    """
    body = client.get("/api/audit/verify", headers=ANALYST).json()
    assert "durable" in body
    assert body["verified"] is True
    if not body["durable"]:
        assert "NEXTATTACK_AUDIT_DB" in body["claim"]


def test_a_second_writer_on_one_chain_file_is_refused():
    from src.shared.audit import AuditChain

    path = pathlib.Path(tempfile.mkdtemp()) / "chain.db"
    a = AuditChain({"x": "1"}, path=path)
    b = AuditChain({"x": "1"}, path=path)       # a resume, which is fine
    assert b.verify()[0] is True
    a.append("k", actor="a", role="analyst")
    with pytest.raises(RuntimeError, match="already exists"):
        b.append("k", actor="a", role="analyst")


# --------------------------------------------------------------------------- #
# #9 -- rate limiting                                                          #
# --------------------------------------------------------------------------- #
def test_a_token_bucket_refuses_and_then_refills():
    from src.shared.ratelimit import Bucket

    b = Bucket(capacity=3, per_seconds=60.0)
    assert all(b.take()[0] for _ in range(3))
    allowed, wait = b.take()
    assert not allowed and wait > 0, "a refusal must say how long to wait"
    b.updated -= 60.0
    assert b.take()[0], "a full window must refill the bucket"


def test_buckets_are_per_principal():
    from src.shared.ratelimit import Limiter

    lim = Limiter()
    cap = int(Limiter.LIMITS["agents"][0])
    assert sum(lim.check("agents", "a@soc")[0] for _ in range(cap + 5)) == cap
    assert lim.check("agents", "b@soc")[0], "one caller must not exhaust another"


# --------------------------------------------------------------------------- #
# #12 -- engine3 is reachable, and honest about what it is                      #
# --------------------------------------------------------------------------- #
def test_the_world_model_is_reachable_and_scoped():
    body = client.get("/api/netstate/status").json()
    assert "ready" in body and body["n_states"] > 0
    assert "API only" in body["surface"]
    assert "not a claim" in body["claim"] or "never a claim" in body["claim"]


def test_the_world_model_refuses_input_it_cannot_window():
    r = client.post("/api/netstate/analyze",
                    json={"flows": [{"FIN Flag Count": 1.0}] * 5}, headers=ANALYST)
    assert r.status_code in (422, 503)


# --------------------------------------------------------------------------- #
# #13 -- the misleading signature is gone                                      #
# --------------------------------------------------------------------------- #
def test_technique_names_returns_a_mapping_not_a_padded_tuple():
    from api.main import _technique_names

    names = _technique_names()
    assert isinstance(names, dict) and names
    assert not hasattr(__import__("api.main", fromlist=["x"]), "_markov")


# --------------------------------------------------------------------------- #
# #14 -- per-entity baselines, and the cold start that has to come with them   #
# --------------------------------------------------------------------------- #
def test_a_thin_baseline_refuses_to_be_used():
    """A store with two days in it is worse than none: everything still looks
    new, but now it looks new authoritatively."""
    from src.shared import baseline

    path = pathlib.Path(tempfile.mkdtemp()) / "profiles.db"
    day = baseline.SECONDS_PER_DAY

    def log(n, t0):
        return pd.DataFrame({
            "timestamp": [t0 + i * 60 for i in range(n)],
            "user": ["asha@corp"] * n, "source_host": ["LAPTOP-7"] * n,
            "destination_host": ["FILES-01"] * n, "is_fail": [0] * n})

    baseline.observe(log(200, 0), path)
    baseline.observe(log(200, 2 * day), path)
    assert baseline.status(path)["state"] == "learning"
    out, st = baseline.apply(log(30, 3 * day), path)
    assert st["state"] == "learning"
    assert st["allow_operational_alerts"] is False
    assert 0 <= st["progress_percent"] < 100
    assert "new_dst_for_user" not in out.columns, (
        "learning mode must leave features alone rather than half-apply them")


def test_a_mature_baseline_makes_routine_traffic_boring():
    """The acceptance criterion from the issue: 0 alerts, not 1."""
    from src.shared import baseline

    path = pathlib.Path(tempfile.mkdtemp()) / "profiles.db"
    day = baseline.SECONDS_PER_DAY

    def log(n, t0, dst="FILES-01"):
        return pd.DataFrame({
            "timestamp": [t0 + i * 60 for i in range(n)],
            "user": ["asha@corp"] * n, "source_host": ["LAPTOP-7"] * n,
            "destination_host": [dst] * n, "is_fail": [0] * n})

    for d in range(31):
        baseline.observe(log(200, d * day), path)
    assert baseline.status(path)["state"] == "ready"

    routine, _ = baseline.apply(log(30, 31 * day), path)
    assert routine["new_dst_for_user"].sum() == 0
    assert routine["user_fail_rate_sofar"].max() == 0.0

    novel, _ = baseline.apply(log(5, 32 * day, dst="FINANCE-DB-01"), path)
    assert novel["new_dst_for_user"].sum() == 5, "an unseen host IS still new"
    assert novel["dst_rarity"].iloc[0] > routine["dst_rarity"].iloc[0]


def test_baseline_counts_each_new_destination_once_per_user():
    """#38: row-level novelty must not inflate distinct-destination fan-out."""
    from src.shared import baseline

    path = pathlib.Path(tempfile.mkdtemp()) / "profiles.db"
    day = baseline.SECONDS_PER_DAY

    def history(day_n, user="asha@corp", dst="FILES"):
        return pd.DataFrame({
            "timestamp": [day_n * day],
            "user": [user],
            "source_host": ["LAPTOP-7"],
            "destination_host": [dst],
            "is_fail": [0],
        })

    for d in range(8):
        for _ in range(5):
            baseline.observe(history(d), path)
    assert baseline.status(path)["state"] == "ready"

    repeated = pd.DataFrame({
        "timestamp": [9 * day + i for i in range(5)],
        "user": ["asha@corp"] * 5,
        "source_host": ["LAPTOP-7"] * 5,
        "destination_host": ["NEWDB"] * 5,
        "is_fail": [0] * 5,
    })
    out, _ = baseline.apply(repeated, path)
    assert out["new_dst_for_user"].tolist() == [1, 1, 1, 1, 1]
    assert out["user_distinct_dst_sofar"].tolist() == [2, 2, 2, 2, 2]

    second_host = repeated.copy()
    second_host["destination_host"] = ["NEWDB", "NEWDB", "HRDB", "NEWDB", "HRDB"]
    out, _ = baseline.apply(second_host, path)
    assert out["user_distinct_dst_sofar"].tolist() == [2, 2, 3, 3, 3]


def test_baseline_new_destination_fanout_is_scoped_to_interleaved_users():
    from src.shared import baseline

    path = pathlib.Path(tempfile.mkdtemp()) / "profiles.db"
    day = baseline.SECONDS_PER_DAY

    for d in range(8):
        for offset in range(5):
            baseline.observe(pd.DataFrame({
                "timestamp": [d * day + 2 * offset, d * day + 2 * offset + 1],
                "user": ["asha@corp", "ben@corp"],
                "source_host": ["LAPTOP-7", "LAPTOP-9"],
                "destination_host": ["FILES", "MAIL"],
                "is_fail": [0, 0],
            }), path)
    assert baseline.status(path)["state"] == "ready"

    current = pd.DataFrame({
        "timestamp": [9 * day + i for i in range(6)],
        "user": ["asha@corp", "ben@corp", "asha@corp",
                 "ben@corp", "asha@corp", "ben@corp"],
        "source_host": ["LAPTOP-7", "LAPTOP-9"] * 3,
        "destination_host": ["NEWDB", "NEWDB", "NEWDB", "NEWDB", "HRDB", "HRDB"],
        "is_fail": [0] * 6,
    })

    out, _ = baseline.apply(current, path)
    assert out["user_distinct_dst_sofar"].tolist() == [2, 2, 2, 2, 3, 3]


def test_the_baseline_is_off_by_default_and_says_so():
    """Off is the honest default: every published metric was measured on
    file-local features."""
    body = client.get("/api/capabilities").json()["capabilities"]["entity_baseline"]
    assert body["state"] == "off"
    assert "48.2%" in body["note"]
