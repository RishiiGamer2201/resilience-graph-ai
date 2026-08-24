from __future__ import annotations

import json
import pickle

from scripts.refresh_association_cache import CACHE
from src.shared import predictor


def test_artifact_records_profile_data_and_fails_closed():
    with predictor.MARKOV_PATH.open("rb") as handle:
        artifact = pickle.load(handle)

    assert artifact["version"] == 3
    assert artifact["task"] == "attack-technique-association-ranking"
    gate = artifact["temporal_validation"]
    assert gate["enabled"] is False
    assert gate["data_basis"]["observed_timeline"] is False
    assert gate["benchmark"]["independent_of_training"] is True
    lo, hi = gate["benchmark"]["gain_sequence_bootstrap_95"]
    assert lo <= 0 <= hi


def test_cached_ui_payload_contains_no_stale_chronological_claim():
    overview = json.loads((CACHE / "overview.json").read_text(encoding="utf-8"))
    text = json.dumps(overview)

    assert "205 real ATT&CK campaigns" not in text
    assert "the next moves are" not in text
    forecast = overview["analysis"]["progression_forecast"]
    assert forecast["available"] is False
    assert forecast["mode"] == "association-only"
    assert forecast["associations"]
    assert "steps" not in forecast


def test_legacy_rank_next_name_cannot_reenable_chronology():
    ranked, source = predictor.rank_next(["T1078"], 3)

    assert ranked
    assert source.startswith("profile-association-")
    assert predictor.temporal_prediction_status()["enabled"] is False
