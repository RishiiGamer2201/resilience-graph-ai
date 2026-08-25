"""The PCAP-to-world-model path, tested against the artifact that actually ships.

Issue #41. `tests/test_packets.py::test_packet_windows_feed_the_netstate_model`
already fed packet windows to a netstate model and passed -- but it called
`fit()` first, so the model it fed was a fresh 60-dimensional one trained on
those same windows. That proves packets can train *a* model. It says nothing
about `models/netstate_cicids.npz`, which is the one the API loads, and which
encodes 48 dimensions. So the documented "hand a capture to the same model
unchanged" path was never exercised, and it does not work.

These tests load the committed artifact.
"""
from __future__ import annotations

import numpy as np
import pytest

from src.engine3.netstate import (FLOW_FEATURES, STATE_DIM as FLOW_STATE_DIM,
                                  FeatureContractError, MODEL, NetStateModel)
from src.engine3.packets import (PACKET_FEATURES, STATE_DIM as PACKET_STATE_DIM,
                                 packet_windows, read_packets, write_pcap)

SYN, ACK, PSH = 0x02, 0x10, 0x08

pytestmark = pytest.mark.skipif(
    not MODEL.exists(),
    reason="world model artifact not built (python -m scripts.eval_netstate)")


def _capture(tmp_path, n=768):
    """A capture with a scan phase and a bulk-transfer phase, so the windows
    differ from each other rather than being 768 copies of one packet."""
    pkts = []
    for i in range(n):
        scan = (i // 128) % 2 == 0
        pkts.append({"dst": "10.0.0.9" if scan else "10.0.0.20",
                     "dport": (1000 + i) if scan else 443,
                     "flags": SYN if scan else (PSH | ACK),
                     "payload_len": 0 if scan else 1200,
                     "ttl": 64 if scan else 52 + i % 5,
                     "ts": i * 0.001})
    return write_pcap(tmp_path / "contract.pcap", pkts)


# --------------------------------------------------------------------------- #
# the two contracts, stated                                                    #
# --------------------------------------------------------------------------- #
def test_the_two_feature_sets_are_different_sizes():
    """The whole issue in three lines. If these ever match, the rest of this
    file is measuring nothing and should be revisited rather than deleted."""
    assert len(FLOW_FEATURES) == 24 and FLOW_STATE_DIM == 48
    assert len(PACKET_FEATURES) == 30 and PACKET_STATE_DIM == 60
    assert not set(FLOW_FEATURES) & set(PACKET_FEATURES), (
        "the two feature sets now overlap; the incompatibility story in "
        "src/engine3/packets.py and reports/packet_features.md needs rewriting")


def test_the_committed_artifact_encodes_flow_windows():
    """The positive half: the shipped artifact does work, on what it was
    trained on. Without this, the test below could pass on a broken artifact."""
    model = NetStateModel.load()
    assert model.mean.shape[-1] == FLOW_STATE_DIM
    latents = model.encode(np.zeros((3, FLOW_STATE_DIM)))
    assert latents.shape == (3,)
    forecast = model.forecast(np.zeros((3, FLOW_STATE_DIM)), horizon=3)
    cumulative = [s["cumulative_probability"] for s in forecast["steps"]]
    assert cumulative == sorted(cumulative)


# --------------------------------------------------------------------------- #
# the path the documentation used to claim                                     #
# --------------------------------------------------------------------------- #
def test_pcap_windows_are_refused_by_the_shipped_artifact_by_name(tmp_path):
    """The integration test #41 asks for: generated PCAP, committed artifact.

    The outcome is a refusal, and that is the honest result -- the point is
    that it is a refusal that says why, rather than
    `operands could not be broadcast together with shapes (6,60) (48,)`.
    """
    states, _ = packet_windows(read_packets(_capture(tmp_path))[0], window=128)
    assert states.shape[1] == PACKET_STATE_DIM

    model = NetStateModel.load()
    with pytest.raises(FeatureContractError) as excinfo:
        model.encode(states)

    message = str(excinfo.value)
    assert "48" in message and "60" in message, message
    assert "packet" in message.lower() and "flow" in message.lower(), message


def test_forecasting_from_a_capture_fails_the_same_way(tmp_path):
    """forecast() encodes internally, so the guard has to hold there too --
    that is the call the API makes."""
    states, _ = packet_windows(read_packets(_capture(tmp_path))[0], window=128)
    with pytest.raises(FeatureContractError):
        NetStateModel.load().forecast(states, horizon=3)


def test_the_error_is_a_valueerror_so_existing_handlers_still_catch_it():
    """It is raised into paths that already expect ValueError. Narrowing the
    type must not widen what escapes."""
    assert issubclass(FeatureContractError, ValueError)


# --------------------------------------------------------------------------- #
# the claim that started it                                                    #
# --------------------------------------------------------------------------- #
def test_no_source_claims_the_two_are_interchangeable():
    """`packets.py` said a capture could go to the same model "unchanged", and
    reports/packet_features.md said the same thing one line above a number
    fitted on 60-dimensional windows. Both are corrected; this keeps them so."""
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    # Asserted positively. Both files now quote the old wording in order to
    # correct it, so grepping for its absence flags the correction itself --
    # which is how the first version of this test failed.
    for rel in ("src/engine3/packets.py", "reports/packet_features.md"):
        # whitespace-normalised: both files wrap prose, and the phrase lands
        # across a line break in one of them
        text = " ".join((root / rel).read_text().lower().split())
        assert "not interchangeable" in text, (
            f"{rel} must state that packet and flow vectors are not "
            f"interchangeable; it is the claim that made #41 possible")


def test_packet_features_still_make_no_measured_detection_claim():
    """#41 also asks that packet performance be measured before any detection
    claim is made. None is made, and this is what keeps it that way."""
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    text = (root / "src" / "engine3" / "packets.py").read_text().lower()
    assert "not measured" in text
