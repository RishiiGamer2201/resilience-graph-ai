"""Packet-level features and PCAP ingestion: correctness, not performance.

SIH 2026 requirements 7 and 8. There is no labelled capture in this repository,
so there is no accuracy claim to test. What these tests establish instead is
that the extractor computes what it says it computes, against frames whose
properties are known because the test wrote them. A capture built with TTLs of
exactly 64 and 63 must report that variance; twelve bare SYNs to twelve ports
must register as a scan; one repeated sequence number must count as exactly one
retransmission.

The strongest test here is the last section: the stdlib reader and the scapy
reader must produce identical features from the same file. That cross-check
already found a real bug, where the stdlib path parsed the leading bytes of a
non-first IP fragment as a TCP header and manufactured ports, sequence numbers
and retransmissions out of payload continuation.
"""
from __future__ import annotations

import struct

import numpy as np
import pytest

from src.engine3.packets import (
    ACK,
    FIN,
    PACKET_FEATURES,
    PROTO_UDP,
    PSH,
    RST,
    STATE_DIM,
    SYN,
    URG,
    Packet,
    describe,
    packet_windows,
    read_packets,
    read_pcap_scapy,
    read_pcap_stdlib,
    scapy_available,
    state_names,
    window_features,
    write_pcap,
)

needs_scapy = pytest.mark.skipif(not scapy_available(), reason="scapy not installed")


def cap(tmp_path, packets, name="t.pcap"):
    return write_pcap(tmp_path / name, packets)


# --------------------------------------------------------------------------- #
# the reader                                                                   #
# --------------------------------------------------------------------------- #
def test_a_written_capture_reads_back_intact(tmp_path):
    p = cap(tmp_path, [{"src": "192.168.1.10", "dst": "10.0.0.7", "sport": 4444,
                        "dport": 8080, "ttl": 57, "flags": SYN | ACK,
                        "window": 29200, "payload_len": 120, "seq": 77}])
    pkts, _ = read_packets(p)
    assert len(pkts) == 1
    q = pkts[0]
    assert (q.src, q.dst) == ("192.168.1.10", "10.0.0.7")
    assert (q.sport, q.dport) == (4444, 8080)
    assert q.ttl == 57 and q.window == 29200 and q.seq == 77
    assert q.payload_len == 120
    assert q.flags & SYN and q.flags & ACK


def test_udp_is_parsed(tmp_path):
    p = cap(tmp_path, [{"proto": PROTO_UDP, "sport": 5353, "dport": 53,
                        "payload_len": 64}])
    pkts, _ = read_packets(p)
    assert pkts[0].sport == 5353 and pkts[0].dport == 53
    assert pkts[0].payload_len == 64


def test_a_non_pcap_file_is_refused(tmp_path):
    bad = tmp_path / "not.pcap"
    bad.write_bytes(b"this is not a capture file at all")
    with pytest.raises(ValueError, match="not a pcap"):
        read_pcap_stdlib(bad)


def test_a_truncated_record_does_not_crash_the_reader(tmp_path):
    p = cap(tmp_path, [{"dport": 80}, {"dport": 81}])
    raw = p.read_bytes()
    (tmp_path / "cut.pcap").write_bytes(raw[:-12])       # chop the last frame
    pkts = read_pcap_stdlib(tmp_path / "cut.pcap")
    assert len(pkts) == 1, "the intact record survives, the torn one is dropped"


def test_the_packet_limit_is_honoured(tmp_path):
    p = cap(tmp_path, [{"dport": 1000 + i} for i in range(50)])
    assert len(read_pcap_stdlib(p, limit=10)) == 10


def test_pcapng_is_refused_rather_than_misread(tmp_path):
    """A half-parsed block file would give confident wrong numbers."""
    ng = tmp_path / "x.pcapng"
    ng.write_bytes(struct.pack(">I", 0x0A0D0D0A) + b"\x00" * 60)
    with pytest.raises(ValueError, match="pcapng"):
        read_pcap_stdlib(ng)


def test_a_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        read_packets(tmp_path / "nope.pcap")


# --------------------------------------------------------------------------- #
# requirement 7, feature by feature                                            #
# --------------------------------------------------------------------------- #
def test_ttl_variance_is_the_variance_of_the_ttls(tmp_path):
    p = cap(tmp_path, [{"ttl": t} for t in (64, 63, 128)])
    f = window_features(read_packets(p)[0])
    assert f["ttl_mean"] == pytest.approx(np.mean([64, 63, 128]))
    assert f["ttl_var"] == pytest.approx(np.var([64, 63, 128]))
    assert f["ttl_unique"] == 3.0


def test_a_constant_ttl_has_zero_variance(tmp_path):
    p = cap(tmp_path, [{"ttl": 64} for _ in range(20)])
    f = window_features(read_packets(p)[0])
    assert f["ttl_var"] == 0.0 and f["ttl_unique"] == 1.0


def test_tcp_window_size_is_reported(tmp_path):
    p = cap(tmp_path, [{"window": w} for w in (0, 512, 65535)])
    f = window_features(read_packets(p)[0])
    assert f["tcp_window_mean"] == pytest.approx(np.mean([0, 512, 65535]))
    assert f["tcp_window_zero_rate"] == pytest.approx(1 / 3)


def test_fragment_flags_are_reported(tmp_path):
    p = cap(tmp_path, [
        {"dont_fragment": True},
        {"more_fragments": True},
        {"frag_offset": 1480},
        {},
    ])
    f = window_features(read_packets(p)[0])
    assert f["dont_fragment_rate"] == 0.25
    assert f["more_fragments_rate"] == 0.25
    assert f["frag_rate"] == 0.5, "a set MF bit or a non-zero offset both count"


def test_payload_distribution(tmp_path):
    p = cap(tmp_path, [{"payload_len": n} for n in (0, 0, 100, 1400)])
    f = window_features(read_packets(p)[0])
    assert f["payload_zero_rate"] == 0.5
    assert f["payload_mean"] == pytest.approx(375.0)
    assert f["payload_entropy"] > 0


def test_identical_payloads_have_zero_entropy(tmp_path):
    p = cap(tmp_path, [{"payload_len": 512} for _ in range(16)])
    assert window_features(read_packets(p)[0])["payload_entropy"] == 0.0


def test_flag_rates(tmp_path):
    p = cap(tmp_path, [{"flags": SYN}, {"flags": ACK}, {"flags": FIN | ACK},
                       {"flags": RST}, {"flags": URG | PSH}])
    f = window_features(read_packets(p)[0])
    assert f["syn_rate"] == 0.2 and f["rst_rate"] == 0.2
    assert f["ack_rate"] == 0.4 and f["fin_rate"] == 0.2
    assert f["urg_rate"] == 0.2 and f["psh_rate"] == 0.2


# --------------------------------------------------------------------------- #
# port-scan signature                                                          #
# --------------------------------------------------------------------------- #
def test_a_port_scan_scores_high(tmp_path):
    p = cap(tmp_path, [{"dst": "10.0.0.9", "dport": 1000 + i, "flags": SYN,
                        "payload_len": 0} for i in range(64)])
    f = window_features(read_packets(p)[0])
    assert f["unique_dst_ports"] == 64
    assert f["unique_dst_hosts"] == 1
    assert f["syn_without_ack_rate"] == 1.0
    assert f["portscan_score"] > 0.9


def test_a_busy_client_on_one_port_is_not_a_scan(tmp_path):
    """The signature has to separate a scan from ordinary traffic, or it is a
    false-positive generator rather than a feature."""
    p = cap(tmp_path, [{"dst": "10.0.0.20", "dport": 443, "sport": 40000 + i,
                        "flags": PSH | ACK, "payload_len": 800}
                       for i in range(64)])
    f = window_features(read_packets(p)[0])
    assert f["portscan_score"] < 0.05
    assert f["syn_without_ack_rate"] == 0.0


def test_a_completed_handshake_is_not_a_scan(tmp_path):
    p = cap(tmp_path, [{"dport": 443, "flags": SYN | ACK} for _ in range(32)])
    assert window_features(read_packets(p)[0])["syn_without_ack_rate"] == 0.0


# --------------------------------------------------------------------------- #
# retransmissions                                                              #
# --------------------------------------------------------------------------- #
def test_a_repeated_sequence_number_is_one_retransmission(tmp_path):
    p = cap(tmp_path, [{"seq": 100, "payload_len": 500, "flags": PSH | ACK},
                       {"seq": 100, "payload_len": 500, "flags": PSH | ACK},
                       {"seq": 600, "payload_len": 500, "flags": PSH | ACK},
                       {"seq": 1100, "payload_len": 500, "flags": PSH | ACK}])
    assert window_features(read_packets(p)[0])["retransmission_rate"] == 0.25


def test_three_sends_of_one_segment_are_two_retransmissions(tmp_path):
    p = cap(tmp_path, [{"seq": 1, "payload_len": 100, "flags": PSH | ACK}] * 3
                      + [{"seq": 2, "payload_len": 100, "flags": PSH | ACK}])
    assert window_features(read_packets(p)[0])["retransmission_rate"] == 0.5


def test_pure_acks_are_not_retransmissions(tmp_path):
    """Zero-payload segments legitimately repeat a sequence number."""
    p = cap(tmp_path, [{"seq": 5, "payload_len": 0, "flags": ACK}
                       for _ in range(10)])
    assert window_features(read_packets(p)[0])["retransmission_rate"] == 0.0


def test_the_same_sequence_on_a_different_flow_is_not_a_retransmission(tmp_path):
    p = cap(tmp_path, [{"seq": 9, "payload_len": 50, "dst": "10.0.0.1",
                        "flags": PSH | ACK},
                       {"seq": 9, "payload_len": 50, "dst": "10.0.0.2",
                        "flags": PSH | ACK}])
    assert window_features(read_packets(p)[0])["retransmission_rate"] == 0.0


# --------------------------------------------------------------------------- #
# window vectors feed the world model                                          #
# --------------------------------------------------------------------------- #
def test_the_window_vector_has_the_declared_shape(tmp_path):
    p = cap(tmp_path, [{"dport": 1000 + i} for i in range(256)])
    states, dicts = packet_windows(read_packets(p)[0], window=128)
    assert states.shape == (2, STATE_DIM)
    assert len(state_names()) == STATE_DIM == len(PACKET_FEATURES) * 2
    assert len(dicts) == 2 and np.isfinite(states).all()


def test_too_few_packets_yields_no_window_rather_than_a_ragged_one(tmp_path):
    p = cap(tmp_path, [{"dport": 80} for _ in range(10)])
    states, dicts = packet_windows(read_packets(p)[0], window=128)
    assert len(states) == 0 and dicts == []


def test_an_empty_window_returns_zeros_not_a_crash():
    f = window_features([])
    assert set(f) == set(PACKET_FEATURES)
    assert all(v == 0.0 for v in f.values())


def test_packet_windows_feed_a_netstate_model_TRAINED_ON_PACKETS(tmp_path):
    """Packet windows can train and drive a netstate model of their own.

    Note what this does NOT show, and used to claim it did: it calls `fit()`
    first, so the model here is a fresh 60-dimensional one built from these very
    windows. It says nothing about `models/netstate_cicids.npz`, the artifact
    the API loads, which encodes 48 dimensions and rejects these vectors --
    see tests/test_packet_flow_contract.py. The old docstring said "packets and
    flows are the same state space", which is how issue #41 survived a green
    suite.
    """
    from src.engine3.netstate import fit
    pkts = []
    for i in range(768):
        scan = (i // 128) % 2 == 0
        pkts.append({"dst": "10.0.0.9" if scan else "10.0.0.20",
                     "dport": (1000 + i) if scan else 443,
                     "flags": SYN if scan else (PSH | ACK),
                     "payload_len": 0 if scan else 1200,
                     "ttl": 64 if scan else 52 + i % 5,
                     "ts": i * 0.001})
    states, _ = packet_windows(read_packets(cap(tmp_path, pkts))[0], window=128)
    assert len(states) == 6

    half = len(states) // 2
    m = fit([("a", states[:half], np.zeros(half)),
             ("b", states[half:], np.zeros(len(states) - half))],
            n_states=3, window=128)
    assert m.centroids.shape[1] == STATE_DIM
    assert np.allclose(m.transition_matrix().sum(axis=1), 1.0)
    f = m.forecast(states, horizon=3)
    cum = [s["cumulative_probability"] for s in f["steps"]]
    assert cum == sorted(cum), cum


def test_describe_reports_that_performance_is_not_measured(tmp_path):
    """The honesty rule, enforced. There is no labelled capture here, so no
    accuracy claim may ride along with the features."""
    p = cap(tmp_path, [{"dport": 80 + i} for i in range(256)])
    d = describe(p, window=128)
    assert d["n_packets"] == 256 and d["n_windows"] == 2
    assert "NOT measured" in d["note"]


# --------------------------------------------------------------------------- #
# the two readers must agree                                                   #
# --------------------------------------------------------------------------- #
@needs_scapy
def test_both_readers_produce_identical_features(tmp_path):
    """The cross-check that found the fragment bug.

    The stdlib reader was parsing the leading bytes of a non-first IP fragment
    as a TCP header, inventing ports and sequence numbers from payload
    continuation and manufacturing retransmissions out of them. Any future
    divergence between a sixty-line struct parser and a real dissector should
    fail loudly here.
    """
    pkts = [{"dst": f"10.0.0.{i % 7}", "dport": 1000 + i,
             "flags": SYN if i % 3 else (PSH | ACK),
             "ttl": 64 - (i % 5), "payload_len": (i * 13) % 900,
             "seq": 500 + i // 2, "window": 8192 + i,
             "dont_fragment": bool(i % 2),
             "more_fragments": i % 17 == 0,
             "frag_offset": 8 if i % 17 == 0 else 0,
             "ts": i * 0.003} for i in range(300)]
    p = cap(tmp_path, pkts)
    a, b = window_features(read_pcap_stdlib(p)), window_features(read_pcap_scapy(p))
    for k in PACKET_FEATURES:
        assert a[k] == pytest.approx(b[k], abs=1e-9), f"{k}: stdlib {a[k]} vs scapy {b[k]}"


@needs_scapy
def test_a_non_first_fragment_contributes_no_ports_or_sequence(tmp_path):
    """The bug itself, pinned. A continuation fragment carries no L4 header."""
    p = cap(tmp_path, [{"frag_offset": 1480, "payload_len": 600,
                        "dport": 0, "seq": 0}])
    for reader in (read_pcap_stdlib, read_pcap_scapy):
        q = reader(p)[0]
        assert q.sport == 0 and q.dport == 0 and q.seq == 0, reader.__name__
        assert q.payload_len > 0


def test_the_stdlib_reader_works_without_scapy(tmp_path, monkeypatch):
    """The zero-dependency path must stay zero-dependency: the slim deployed
    image does not install scapy."""
    import src.engine3.packets as mod
    monkeypatch.setattr(mod, "scapy_available", lambda: False)
    p = cap(tmp_path, [{"dport": 443, "ttl": 60} for _ in range(8)])
    pkts, reader = mod.read_packets(p)
    assert reader == "stdlib" and len(pkts) == 8
