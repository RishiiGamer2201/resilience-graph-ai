"""The agent lane's inputs must actually reach its rules.

Four defects shipped here at once, and the existing suite missed all four
because every test fed the agents a hand-built stats dict instead of one the
chunker produced. Each test below fails against the old code.

1. `_compute_stats` counted failures as `status == "failure"`. The canonical
   vocabulary from src.shared.normalize is "success" / "fail", so failure_rate
   was 0.0 for every chunk ever produced, and the T1110 brute-force rule was
   unreachable.
2. `protocol` was never aggregated, so the ntlm_lateral_movement rule that
   already existed in the table could never fire -- on a dataset where 100% of
   red-team logins are NTLM.
3. `prioritizer._actor_match` imported a function that does not exist, inside a
   bare `except Exception: pass`. It returned 0.0 always; 20% of the risk score
   was dead.
4. Chain `technique_ids` was not deduplicated, so a chain of one technique
   repeated 49 times reported as "49 techniques".

Together these made the agent lane call the LANL campaign `medium` against the
workflow's `critical` -- a two-band contradiction that ADR 0007 says means one
lane is wrong, not that we report the conflict.
"""
from __future__ import annotations

import pandas as pd
import pytest

from src.agents.chunker import _compute_stats
from src.agents.prioritizer import _actor_match, _band, _tech_to_groups


# --------------------------------------------------------------------------- #
# 1. failure counting                                                          #
# --------------------------------------------------------------------------- #
def test_failures_are_counted_from_the_canonical_status_vocabulary():
    df = pd.DataFrame({"status": ["success", "fail", "fail", "success"]})
    s = _compute_stats(df)
    assert s["n_failures"] == 2, "'fail' is what normalize emits, not 'failure'"
    assert s["failure_rate"] == 0.5
    assert s["n_successes"] == 2


def test_a_brute_force_chunk_reaches_the_t1110_rule():
    from src.agents.intelligence import _rule_based_map
    df = pd.DataFrame({"status": ["fail"] * 9 + ["success"],
                       "destination_host": ["H1"] * 10})
    m = _rule_based_map({"stats": _compute_stats(df), "anomaly_score": 80})
    assert m and m["technique_id"] == "T1110", m


# --------------------------------------------------------------------------- #
# 2. NTLM                                                                      #
# --------------------------------------------------------------------------- #
def test_protocol_is_aggregated():
    df = pd.DataFrame({"protocol": ["NTLM", "NTLM", "Kerberos", "NTLM"]})
    s = _compute_stats(df)
    assert s["ntlm_rate"] == 0.75
    assert s["protocol_top"]["NTLM"] == 3


def test_ntlm_fan_out_maps_to_pass_the_hash():
    from src.agents.intelligence import _rule_based_map
    df = pd.DataFrame({"protocol": ["NTLM"] * 8,
                       "status": ["success"] * 8,
                       "destination_host": [f"WARD-PC-{i:03d}" for i in range(8)]})
    m = _rule_based_map({"stats": _compute_stats(df), "anomaly_score": 90})
    assert m and m["technique_id"] == "T1550.002", m
    assert m["claim_status"] == "inferred", "NTLM fan-out infers pass-the-hash, never observes it"


def test_ntlm_alone_is_not_pass_the_hash():
    """30% of benign LANL logins use NTLM. Asserting T1550.002 on the protocol
    alone would be the over-assertion we already made once with T1078."""
    from src.agents.intelligence import _rule_based_map
    df = pd.DataFrame({"protocol": ["NTLM"] * 6,
                       "status": ["success"] * 6,
                       "destination_host": ["ONE-HOST"] * 6})
    m = _rule_based_map({"stats": _compute_stats(df), "anomaly_score": 90})
    assert m is None or m["technique_id"] != "T1550.002", m


# --------------------------------------------------------------------------- #
# 3. actor match                                                               #
# --------------------------------------------------------------------------- #
def test_the_group_lookup_loads_real_attack_data():
    t2g = _tech_to_groups()
    assert len(t2g) > 400, f"only {len(t2g)} techniques have groups; lookup is broken"
    assert "APT29" in t2g.get("T1078", []), t2g.get("T1078", [])[:5]


def test_actor_match_is_not_silently_always_zero():
    assert _actor_match(["T1550.002"]) == 1.0
    assert _actor_match(["T9999"]) == 0.0
    assert _actor_match([]) == 0.0


def test_the_group_lookup_raises_rather_than_swallowing_a_broken_import(monkeypatch):
    """The original bug survived because a bare except hid an ImportError. If the
    lookup ever breaks again this must be loud, not a silent 0.0."""
    import src.agents.prioritizer as pz
    monkeypatch.setattr(pz, "_TECH_TO_GROUPS", None)
    monkeypatch.setattr("src.shared.attack_mapper._lookups",
                        lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    with pytest.raises(RuntimeError):
        pz._tech_to_groups()


# --------------------------------------------------------------------------- #
# 4. bands and dedup                                                           #
# --------------------------------------------------------------------------- #
def test_band_is_read_from_the_number_that_gets_printed():
    """0.54999 printed as risk=0.55 next to the band 'medium'."""
    assert _band(round(0.54999, 4)) == "high"
    assert _band(0.5499) == "medium"


def test_chain_techniques_are_distinct_and_in_first_seen_order():
    from src.agents import AgentResult, AgentStatus
    from src.agents.validator import run as validate
    mapped = [{"entity": "U66@DOM1", "technique_id": t, "anomaly_score": 90,
               "point_a_text": "", "tactic": ""}
              for t in ["T1078", "T1550.002", "T1078", "T1550.002", "T1021"]]
    intel = AgentResult(agent="intelligence", status=AgentStatus.OK,
                        output={"mapped": mapped})
    kb = AgentResult(agent="kb_connector", status=AgentStatus.OK, output={})
    res = validate(kb, intel)
    chain = res.output["chains"][0]
    assert chain["technique_ids"] == ["T1078", "T1550.002", "T1021"]
    assert chain["n_technique_events"] == 5


# --------------------------------------------------------------------------- #
# the outcome all four were breaking                                           #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("scenario,source", [
    ("lanl_campaign_all", "lanl"),
    ("lanl_redteam_u66", "lanl"),
])
def test_the_two_lanes_no_longer_contradict_on_lanl(scenario, source):
    """ADR 0007: adjacent severity is tolerable and informative. A two-band gap
    means one lane is wrong and the answer is to fix it, not to report it."""
    from pathlib import Path

    from src.agents.orchestrator import run_pipeline
    from src.shared.normalize import normalize
    df = pd.read_csv(Path("data/demo/scenarios") / f"{scenario}.csv")
    result = run_pipeline(normalize(df, source=source), scenario=scenario,
                          use_llm=False).as_dict()
    rank = ["low", "medium", "high", "critical"]
    assert rank.index(result["severity"]) >= rank.index("high"), (
        f"{scenario} is a real red-team campaign; the agent lane called it "
        f"{result['severity']}")


def test_the_lane_maps_more_than_one_technique_on_a_multi_stage_campaign():
    """It mapped 60 of 229 flagged chunks and every one to T1021, so the entity
    graph held a single technique node and the predictor saw a chain of one."""
    from pathlib import Path

    from src.agents.orchestrator import run_pipeline
    from src.shared.normalize import normalize
    df = pd.read_csv(Path("data/demo/scenarios/lanl_campaign_all.csv"))
    result = run_pipeline(normalize(df, source="lanl"),
                          scenario="lanl_campaign_all", use_llm=False).as_dict()
    found = {t for c in result["ranked_chains"] for t in c["technique_ids"]}
    assert len(found) >= 3, found
    assert "T1550.002" in found, "the NTLM pass-the-hash signal must be visible"
