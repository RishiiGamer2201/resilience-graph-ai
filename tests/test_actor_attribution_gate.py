"""An ATT&CK profile ranking must not silently become actor attribution."""
from __future__ import annotations

import numpy as np
import pytest

from src.engine2.attribution import (
    AttributionCalibration,
    build_profiles,
    decide_actor_attribution,
    rank_actors,
)


def _rank(observed: list[str], groups: dict[str, list[str]], vectors: dict[str, list[float]]):
    embeddings = {key: np.asarray(value, dtype="float32")
                  for key, value in vectors.items()}
    profiles = build_profiles(groups, embeddings)
    return rank_actors(observed, profiles, embeddings)


def test_zero_exact_overlap_always_abstains_even_with_semantic_similarity():
    ranked = _rank(
        ["T0800"],
        {"Equation": ["T-A"], "Other": ["T-B"]},
        {"T0800": [1.0, 0.0], "T-A": [1.0, 0.0], "T-B": [0.0, 1.0]},
    )

    assert ranked[0]["actor"] == "Equation"
    assert ranked[0]["score"] > 0
    assert ranked[0]["observed_matches"] == []

    decision = decide_actor_attribution(ranked)
    assert decision["status"] == "unattributed"
    assert decision["attributed_actor"] is None
    assert decision["exact_match_count"] == 0
    assert decision["negative_evidence"]["zero_exact_overlap"] is True
    assert "semantic similarity alone" in decision["abstention_reason"]


def test_one_common_technique_cannot_name_an_actor():
    ranked = _rank(
        ["T-COMMON"],
        {"Group A": ["T-COMMON", "T-A"], "Group B": ["T-COMMON", "T-B"]},
        {
            "T-COMMON": [1.0, 0.0],
            "T-A": [1.0, 0.2],
            "T-B": [0.8, 0.2],
        },
    )

    decision = decide_actor_attribution(ranked)
    assert decision["attributed_actor"] is None
    assert decision["evidence_count"] == 1
    assert decision["exact_match_count"] == 1
    assert decision["negative_evidence"]["single_technique_only"] is True
    assert "single common technique" in decision["abstention_reason"]


def test_strong_profile_overlap_still_abstains_without_independent_calibration():
    ranked = _rank(
        ["T-A", "T-B"],
        {"Group A": ["T-A", "T-B"], "Group B": ["T-A", "T-C"]},
        {"T-A": [1.0, 0.0], "T-B": [0.9, 0.1], "T-C": [0.0, 1.0]},
    )

    decision = decide_actor_attribution(ranked)
    assert decision["attributed_actor"] is None
    assert decision["score"] is not None
    assert decision["margin"] is not None
    assert decision["alternatives"]
    assert decision["gate"]["calibrated"] is False
    assert decision["gate"]["calibrated_thresholds"] is None
    assert "not been calibrated" in decision["abstention_reason"]


def test_independently_calibrated_thresholds_can_open_the_gate():
    ranked = _rank(
        ["T-A", "T-B"],
        {"Group A": ["T-A", "T-B"], "Group B": ["T-C", "T-D"]},
        {
            "T-A": [1.0, 0.0], "T-B": [0.9, 0.1],
            "T-C": [0.0, 1.0], "T-D": [0.1, 0.9],
        },
    )
    calibration = AttributionCalibration(
        source="independent-labelled-incident-fixture",
        independent_incidents=100,
        minimum_observed_techniques=2,
        minimum_exact_matches=2,
        minimum_score=0.70,
        minimum_margin=0.10,
    )

    decision = decide_actor_attribution(ranked, calibration=calibration)
    assert decision["status"] == "attributed"
    assert decision["attributed_actor"]["actor"] == "Group A"
    assert decision["abstention_reason"] is None
    assert decision["gate"]["calibrated"] is True
    assert decision["gate"]["independent_incident_count"] == 100


@pytest.mark.parametrize(
    "kwargs",
    [
        {"source": "", "independent_incidents": 1},
        {"source": "fixture", "independent_incidents": 0},
        {"source": "fixture", "independent_incidents": 1,
         "minimum_observed_techniques": 1},
        {"source": "fixture", "independent_incidents": 1,
         "minimum_exact_matches": 1},
        {"source": "fixture", "independent_incidents": 1,
         "minimum_score": 1.1},
        {"source": "fixture", "independent_incidents": 1,
         "minimum_margin": -0.1},
    ],
)
def test_calibration_cannot_weaken_safety_or_omit_provenance(kwargs):
    defaults = {
        "source": "fixture",
        "independent_incidents": 1,
        "minimum_observed_techniques": 2,
        "minimum_exact_matches": 2,
        "minimum_score": 0.5,
        "minimum_margin": 0.1,
    }
    defaults.update(kwargs)
    with pytest.raises(ValueError):
        AttributionCalibration(**defaults)


def test_cached_api_separates_similar_profiles_from_attribution_decision():
    from fastapi.testclient import TestClient

    from api.main import app

    client = TestClient(app)
    intel_response = client.get("/api/threat-intel")
    report_response = client.get("/api/report")

    assert intel_response.status_code == 200
    intel = intel_response.json()
    assert intel["ranked_similar_profiles"]
    assert "attribution" not in intel
    decision = intel["attribution_assessment"]
    for key in ("evidence_count", "exact_match_count", "score", "margin",
                "alternatives", "abstention_reason", "negative_evidence", "gate"):
        assert key in decision
    assert decision["status"] == "unattributed"
    assert decision["attributed_actor"] is None

    assert report_response.status_code == 200
    report = report_response.json()
    assert report["attributed_actor"] is None
    assert report["attribution_assessment"]["abstention_reason"]
