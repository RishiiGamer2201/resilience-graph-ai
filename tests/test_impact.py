"""Impact layer: the digital twin and vulnerability prioritisation.

Both produce numbers a responder acts on, so the tests are about the properties
that make those numbers trustworthy — monotonicity, non-mutation, determinism and
honest handling of what we do not know — not about specific values that would
change the next time CISA updates the KEV catalogue.
"""
from __future__ import annotations

from datetime import date

import pytest

from src.shared import twin
from src.shared import vuln

VIEW = {
    "nodes": [{"id": "PC", "critical": False}, {"id": "JUMP", "critical": False},
              {"id": "DB", "critical": True}, {"id": "SPARE", "critical": False}],
    "edges": [{"from": "PC", "to": "JUMP", "users": ["a@x"], "event_count": 3},
              {"from": "JUMP", "to": "DB", "users": ["a@x"], "event_count": 2},
              {"from": "JUMP", "to": "SPARE", "users": ["b@x"], "event_count": 1}],
    "critical_assets_at_risk": ["DB"],
}


# --------------------------------------------------------------------------- #
# digital twin                                                                 #
# --------------------------------------------------------------------------- #
def test_isolating_the_pivot_protects_the_crown_jewel():
    s = twin.simulate(VIEW, isolate_host="JUMP")
    assert s["before"]["crown_jewels_reachable"] == ["DB"]
    assert s["after"]["crown_jewels_reachable"] == []
    assert s["delta"]["crown_jewels_protected"] == ["DB"]
    assert s["delta"]["hosts_no_longer_reachable"] == 3


def test_the_incident_graph_is_never_mutated():
    before = str(VIEW)
    twin.simulate(VIEW, isolate_host="JUMP")
    twin.simulate(VIEW, cut_edge=["JUMP", "DB"])
    twin.rank_candidates(VIEW)
    assert str(VIEW) == before, "the twin mutated the incident graph"


def test_cutting_one_edge_is_cheaper_than_isolating_the_host():
    host = twin.simulate(VIEW, isolate_host="JUMP")
    edge = twin.simulate(VIEW, cut_edge=["JUMP", "DB"])
    assert edge["delta"]["crown_jewels_protected"] == ["DB"]
    assert edge["operational_cost"]["hosts_taken_offline"] == 0
    assert (edge["operational_cost"]["sessions_severed"]
            < host["operational_cost"]["sessions_severed"])


def test_a_useless_containment_says_so():
    s = twin.simulate(VIEW, isolate_host="SPARE")
    assert s["delta"]["crown_jewels_protected"] == []
    assert "do not take the outage" in s["verdict"] or "protects no crown" in s["verdict"]


def test_candidates_rank_benefit_first_then_lowest_cost():
    ranked = twin.rank_candidates(VIEW)
    assert ranked[0]["host"] == "JUMP"
    # every candidate that protects a jewel must sort above every one that does not
    protecting = [i for i, c in enumerate(ranked) if c["crown_jewels_protected"]]
    idle = [i for i, c in enumerate(ranked) if not c["crown_jewels_protected"]]
    assert not protecting or not idle or max(protecting) < min(idle)


def test_simulation_is_deterministic():
    a = twin.simulate(VIEW, isolate_host="JUMP")
    b = twin.simulate(VIEW, isolate_host="JUMP")
    assert a == b


def test_a_host_outside_the_graph_is_rejected():
    with pytest.raises(ValueError):
        twin.simulate(VIEW, isolate_host="NOT-A-HOST")
    with pytest.raises(ValueError):
        twin.simulate(VIEW)


def test_every_result_declares_itself_simulated():
    s = twin.simulate(VIEW, isolate_host="JUMP")
    assert s["simulated"] is True
    assert "SIMULATION ONLY" in s["note"]


# --------------------------------------------------------------------------- #
# vulnerability prioritisation                                                 #
# --------------------------------------------------------------------------- #
def test_config_is_validated_not_trusted(tmp_path):
    import json
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({
        "version": "x", "weights": {"a": 0.9},        # does not sum to 1
        "asset_criticality_scale": {"medium": 0.4},
        "reachability_scale": {}, "freshness": {}, "severity": {},
        "bands": {"act_now": 80, "urgent": 60, "scheduled": 40}}))
    with pytest.raises(AssertionError):
        vuln.load_config(bad)
    vuln.load_config()                                 # restore the real one


def test_config_hash_travels_with_the_result():
    cfg = vuln.load_config()
    assert len(cfg["sha256"]) == 64
    assert abs(sum(cfg["weights"].values()) - 1.0) < 1e-9


@pytest.mark.skipif(not __import__("src.shared.evidence", fromlist=["x"]).available(),
                    reason="evidence index not built")
class TestPrioritisation:
    @staticmethod
    @pytest.fixture(scope="class")
    def kev_hit():
        k = vuln.kev_facts()[0]
        return {**k, "matched_software": {"vendor": k["vendor"], "product": k["product"]}}

    @staticmethod
    @pytest.fixture(scope="class")
    def graph():
        return {"edges": [{"to": "SRV-A"}], "nodes": [{"id": "SRV-A"}, {"id": "SRV-B"}],
                "critical_assets_at_risk": ["SRV-A"],
                "paths_to_critical": {"SRV-A": ["PIVOT", "SRV-A"]}}

    def _score(self, host, crit, kev_hit, graph):
        return vuln.score_finding({"host": host, "criticality": crit}, kev_hit, graph,
                                  [], vuln.load_config(), date(2026, 8, 18))

    def test_criticality_is_monotone(self, kev_hit, graph):
        scores = [self._score("SRV-A", c, kev_hit, graph)["priority_score"]
                  for c in ("low", "medium", "high", "critical")]
        assert scores == sorted(scores), scores

    def test_reachability_raises_priority(self, kev_hit, graph):
        reached = self._score("SRV-A", "critical", kev_hit, graph)["priority_score"]
        unreached = self._score("SRV-Z", "critical", kev_hit, graph)["priority_score"]
        assert reached > unreached

    def test_the_headline_ordering_holds(self, kev_hit, graph):
        """A known-exploited CVE on a critical, reachable asset must outrank the
        same CVE on a low-criticality, unreachable one. This is the whole claim."""
        hi = self._score("SRV-A", "critical", kev_hit, graph)
        lo = self._score("SRV-Z", "low", kev_hit, graph)
        assert hi["priority_score"] > lo["priority_score"]
        assert hi["band"] in ("act now", "urgent")

    def test_unknown_severity_is_reported_not_zeroed(self, kev_hit, graph):
        f = self._score("SRV-A", "critical", kev_hit, graph)
        assert "severity" in f["unknown_factors"]
        assert f["factors"]["severity"]["value"] is None
        assert 0 < f["confidence"] < 1.0
        # dropping the factor must not drag the score toward zero
        assert f["priority_score"] > 70

    def test_every_finding_carries_a_resolvable_citation(self, graph):
        inv = vuln.load_inventory("aiims_ransomware")
        out = vuln.prioritize(inv, graph, [], limit=5)
        assert out["findings"]
        for f in out["findings"]:
            assert f["citation"]["url"].startswith("https://")
            assert f["citation"]["publisher"] == "CISA"
            assert f["cve"].startswith("CVE-")

    def test_no_inventory_means_no_findings_not_invented_ones(self, graph):
        inv = vuln.load_inventory("lanl_campaign_all")
        assert inv["provenance"] == "NOT_AVAILABLE"
        out = vuln.prioritize(inv, graph, [], limit=5)
        assert out["findings"] == []
        assert "anonymised" in out["inventory_note"]

    def test_an_unknown_scenario_explains_itself(self):
        inv = vuln.load_inventory("someone-elses-upload")
        assert inv["provenance"] == "NOT_PROVIDED"
        assert "do not guess" in inv["note"]
