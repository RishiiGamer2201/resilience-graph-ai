from __future__ import annotations

import copy
import gzip
import json

import pytest

from scripts.validate_cert_in_sequences import (
    ROOT,
    SEQUENCES,
    extract_official_advisory,
    source_sha256,
    validate,
)


@pytest.fixture()
def entries() -> list[dict]:
    return json.loads(SEQUENCES.read_text(encoding="utf-8"))


def test_verified_cert_in_sources_have_unique_matching_ids(entries):
    checked = validate(entries)

    assert len(checked) == 4
    assert len({row["advisory_id"] for row in checked}) == 4
    fortibleed = next(
        row for row in entries if "FortiBleed" in row["source_title"])
    assert fortibleed["advisory_id"] == "CICA-2026-3531"
    assert "CACODE=CICA-2026-3531" in fortibleed["source_url"]


def test_conflicting_duplicate_advisory_ids_fail_offline_validation(entries):
    duplicate = copy.deepcopy(entries[0])
    duplicate["source_title"] = "A conflicting title"
    entries.append(duplicate)

    with pytest.raises(ValueError, match="duplicate advisory_id.*conflicting titles"):
        validate(entries)


def test_url_id_must_match_the_declared_advisory(entries):
    entries[0]["source_url"] = entries[0]["source_url"].replace("3534", "3531")

    with pytest.raises(ValueError, match="source_url CACODE does not match"):
        validate(entries)


def test_online_validation_checks_official_title_and_body_hash(entries):
    entry = copy.deepcopy(entries[0])
    title = entry["source_title"]
    page = f"""
      <html><body><h2>CURRENT ACTIVITIES</h2><div>{title}</div>
      <p>Original Issue Date:June 25, 2026 Stable advisory content.</p>
      <h3>Disclaimer</h3><p>dynamic footer</p></body></html>
    """.encode()
    official_title, body = extract_official_advisory(page)
    entry["source_sha256"] = source_sha256(official_title, body)

    checked = validate([entry], online=True, fetcher=lambda _: page)

    assert checked[0]["official_title"] == title
    assert checked[0]["source_sha256"] == entry["source_sha256"]


def test_fortibleed_mappings_are_all_backed_by_reviewed_evidence(entries):
    fortibleed = next(
        row for row in entries if row["advisory_id"] == "CICA-2026-3531")
    mapped = set(fortibleed["ordered_technique_ids"])
    evidenced = {row["technique_id"] for row in fortibleed["technique_evidence"]}

    assert mapped == {"T1110.001", "T1589.001"}
    assert evidenced == mapped
    assert all(row["status"] == "reported" for row in fortibleed["technique_evidence"])


def test_committed_evidence_index_carries_official_source_hashes(entries):
    index_path = ROOT / "data" / "processed" / "evidence" / "index.json.gz"
    with gzip.open(index_path, "rt", encoding="utf-8") as handle:
        index = json.load(handle)
    certin = {chunk["url"]: chunk for chunk in index["chunks"]
              if chunk["source_id"] == "cert-in-advisories"}

    assert len(certin) == len(entries)
    for entry in entries:
        chunk = certin[entry["source_url"]]
        assert chunk["title"] == entry["source_title"]
        assert chunk["source_sha256"] == entry["source_sha256"]


def test_rebuilt_reports_no_longer_contain_the_stale_fortibleed_source():
    prediction = (ROOT / "reports" / "prediction_eval.md").read_text(encoding="utf-8")
    retrieval = (ROOT / "reports" / "retrieval_eval.md").read_text(encoding="utf-8")
    metrics = json.loads((ROOT / "reports" / "metrics.json").read_text(encoding="utf-8"))

    assert "27 prediction points" in prediction
    assert metrics["engine2"]["manual_cert_in_top3"] == 0.111
    assert "CICA-2026-3534 — potential exposure" not in retrieval
    assert "Potential Exposure of FortiGate Administrative" in retrieval
