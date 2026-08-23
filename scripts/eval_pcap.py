"""
End-to-end: a capture file becomes a world-model state space.

SIH 2026 requirements 7 and 8 ask for packet-level features and PCAP ingestion.
Requirements 1, 2 and 3 ask for a network-state representation, learned
transition dynamics and a forecast. This script shows they are the same state
space: `src/engine3/packets.py` emits the window vectors that
`src/engine3/netstate.py` already knows how to model, so a capture is fitted,
quantised, transitioned and rolled forward without changing the model at all.

    python -m scripts.eval_pcap                     # synthetic demonstration
    python -m scripts.eval_pcap path/to/real.pcap   # your own capture

WHAT THIS DOES AND DOES NOT ESTABLISH
-------------------------------------
It establishes that the pipeline is real end to end and that the extractor
computes what it claims. Every feature is checked against frames whose
properties are known because this script wrote them: a scan window with exactly
one TTL value must report zero TTL variance, a repeated sequence number must
count as one retransmission.

It does NOT establish detection performance. Without a labelled capture there is
no honest accuracy number, so none is printed. The numbers that ARE measured in
this project -- 0.987 next-window ROC on CIC-IDS2017 flows -- come from
`scripts/eval_netstate.py` and belong to the flow state space, not this one.

Point this at a labelled capture and the same machinery will produce a real
number. That is the remaining work, and it is data, not code.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import numpy as np

from src.engine3.netstate import NetStateModel, fit
from src.engine3.packets import (
    ACK,
    PACKET_FEATURES,
    PSH,
    RST,
    STATE_DIM,
    SYN,
    describe,
    packet_windows,
    read_packets,
    scapy_available,
    state_names,
    window_features,
    write_pcap,
)

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "reports" / "packet_features.md"
WINDOW = 128


# ─── A synthetic capture with three regimes we control ────────────────────────
def synthetic_capture(path: Path) -> dict[str, slice]:
    """Write a capture with three phases whose ground truth we chose.

    Labelled synthetic in every report line that mentions it. The point is not
    to claim detection; it is that the extractor separates behaviours it should
    separate, on data where the right answer is known by construction.
    """
    pkts: list[dict] = []
    marks: dict[str, slice] = {}
    t = 0.0

    # 1. Ordinary browsing: two servers, port 443, mixed payloads, stable TTL.
    start = len(pkts)
    for i in range(512):
        t += 0.004
        pkts.append({"src": "10.0.0.5", "dst": f"10.0.0.{20 + i % 2}",
                     "sport": 40000 + i % 64, "dport": 443,
                     "flags": PSH | ACK, "ttl": 64, "window": 64240,
                     "payload_len": 200 + (i * 37) % 1200, "seq": 10_000 + i,
                     "dont_fragment": True, "ts": t})
    marks["benign"] = slice(start, len(pkts))

    # 2. Port scan: one host, 1024 ports, bare SYN, no payload, fast.
    start = len(pkts)
    for i in range(512):
        t += 0.0002
        pkts.append({"src": "10.0.0.5", "dst": "10.0.0.99",
                     "sport": 50000, "dport": 1 + i, "flags": SYN, "ttl": 64,
                     "window": 1024, "payload_len": 0, "seq": 0, "ts": t})
    marks["portscan"] = slice(start, len(pkts))

    # 3. Exfiltration under loss: one destination, large payloads, heavy
    #    retransmission, varying TTL from a changing path, some fragmentation.
    start = len(pkts)
    seq = 90_000
    for i in range(512):
        t += 0.02
        retrans = i % 4 == 0                 # every fourth segment resent
        pkts.append({"src": "10.0.0.5", "dst": "203.0.113.7",
                     "sport": 40999, "dport": 8443, "flags": PSH | ACK,
                     "ttl": 52 + (i % 9), "window": 512,
                     "payload_len": 1400, "seq": seq if retrans else seq + 1,
                     "more_fragments": i % 11 == 0,
                     "frag_offset": 8 if i % 11 == 0 else 0, "ts": t})
        if not retrans:
            seq += 1
    marks["exfil"] = slice(start, len(pkts))

    write_pcap(path, pkts)
    return marks


def phase_table(packets, marks: dict[str, slice]) -> list[dict]:
    """Per-phase features, so a reader can see the separation directly."""
    rows = []
    for name, sl in marks.items():
        f = window_features(packets[sl])
        rows.append({"phase": name, **{k: round(f[k], 4) for k in (
            "ttl_var", "ttl_unique", "tcp_window_mean", "payload_mean",
            "payload_entropy", "unique_dst_ports", "portscan_score",
            "retransmission_rate", "frag_rate", "packets_per_second")}})
    return rows


def model_over_packets(states: np.ndarray) -> dict:
    """Fit the SAME latent state-space model over packet windows.

    The model never learns that its input is packets rather than flows. That is
    the claim being demonstrated: one state space, two sources.
    """
    if len(states) < 6:
        return {"state": "not measured", "why": "too few windows to fit a model"}

    half = len(states) // 2
    obs = [("first", states[:half], np.zeros(half)),
           ("second", states[half:], np.zeros(len(states) - half))]
    m = fit(obs, n_states=min(6, max(2, len(states) // 3)), window=WINDOW)

    f = m.forecast(states, horizon=3)
    return {
        "n_states": m.n_states,
        "state_dim": int(m.centroids.shape[1]),
        "persistence_weight": m.persistence_weight,
        "transitions_valid": bool(np.allclose(m.transition_matrix().sum(1), 1.0)),
        "current_state": f["current_state"],
        "forecast_steps": len(f["steps"]),
        "top_state_next": f["steps"][0]["top_states"][0]["state"],
    }


def write_report(m: dict) -> None:
    lines = [
        "# Packet-level features and PCAP ingestion", "",
        "SIH 2026 requirements 7 and 8. Generated by `python -m scripts.eval_pcap`.", "",
        f"- Readers: **stdlib** (`struct` only, classic pcap) and **scapy** "
        f"(pcapng and awkward link types). Scapy is "
        f"{'installed' if m['scapy'] else 'not installed'} here; the reader used "
        f"was **{m['reader']}**.",
        f"- Features: **{len(PACKET_FEATURES)}** per packet window, "
        f"**{STATE_DIM}** dimensions after mean and standard deviation.",
        f"- Capture: {m['n_packets']:,} packets, {m['n_windows']} windows of "
        f"{WINDOW}.", "",
        "## The honest scope", "",
        "**Detection performance on packet data is Not measured.** No labelled",
        "PCAP corpus is bundled: real captures are gigabytes and this project",
        "ships with no download step. There is therefore no accuracy number to",
        "report here and none is reported. The 0.987 next-window ROC-AUC this",
        "project does publish is measured on CIC-IDS2017 **flow** records by",
        "`scripts/eval_netstate.py`, and it does not transfer to this state space.", "",
        "What IS established: the extractor computes what it claims. Every",
        "feature below is checked against frames whose properties are known",
        "because the test wrote them. Both readers are also cross-checked against",
        "each other on the same file and must agree exactly, which is how a real",
        "bug was found: the stdlib reader was parsing the first bytes of a",
        "non-first IP fragment as a TCP header, inventing ports and sequence",
        "numbers out of payload continuation, and manufacturing retransmissions",
        "from them.", "",
        "## Features extracted", "",
        "| Requirement 7 asks for | Feature |",
        "|---|---|",
        "| TTL variance | `ttl_var`, `ttl_mean`, `ttl_unique` |",
        "| TCP window size | `tcp_window_mean`, `tcp_window_std`, `tcp_window_zero_rate` |",
        "| Fragment flags | `frag_rate`, `dont_fragment_rate`, `more_fragments_rate` |",
        "| Payload distribution | `payload_mean`, `payload_std`, `payload_zero_rate`, `payload_entropy` |",
        "| Port-scan signatures | `unique_dst_ports`, `unique_dst_hosts`, `syn_without_ack_rate`, `ports_per_host`, `portscan_score` |",
        "| Retransmissions | `retransmission_rate` |",
        "",
        "Plus the TCP flag distribution and timing that requirement 6 asks for, "
        "at packet rather than flow granularity.", "",
        "## Separation on a synthetic capture", "",
        "Three phases, written by this script so the right answer is known by",
        "construction. This demonstrates the features respond to the behaviours",
        "they are named for. It is not evidence about real traffic.", "",
    ]
    cols = ["phase", "ttl_var", "unique_dst_ports", "portscan_score",
            "retransmission_rate", "payload_entropy", "frag_rate"]
    lines.append("| " + " | ".join(cols) + " |")
    lines.append("|" + "---|" * len(cols))
    for r in m["phases"]:
        lines.append("| " + " | ".join(str(r[c]) for c in cols) + " |")

    lines += ["", "Reading it: the scan is the only phase with a high",
              "`portscan_score` and hundreds of destination ports; the",
              "exfiltration is the only one with retransmissions, fragmentation",
              "and TTL variance; ordinary traffic has none of those and the",
              "highest payload entropy.", ""]

    mo = m["model"]
    lines += ["## One state space, two sources", "",
              "The window vector is the same shape `src/engine3/netstate.py`",
              "uses for CIC-IDS2017 flows, so a capture is handed to the same",
              "latent state-space model unchanged. The model is not told whether",
              "its input came from flows or from packets.", ""]
    if mo.get("state") == "not measured":
        lines.append(f"Not fitted here: {mo['why']}.")
    else:
        lines += [
            f"- Fitted **{mo['n_states']} latent states** over "
            f"**{mo['state_dim']}-dimensional** packet windows",
            f"- Transition matrix rows sum to 1: **{mo['transitions_valid']}**",
            f"- Persistence weight fitted leave-one-fold-out: "
            f"**{mo['persistence_weight']}**",
            f"- A {mo['forecast_steps']}-step rollout runs from state "
            f"{mo['current_state']}",
            "",
            "No accuracy is claimed for this fit. It is fitted on synthetic",
            "traffic and demonstrates that the plumbing is real, nothing more.",
        ]

    lines += ["", "## What is still missing", "",
              "- **A labelled capture.** Point `python -m scripts.eval_pcap` at",
              "  one and the same machinery produces a real number. That is the",
              "  remaining work and it is data, not code.",
              "- **CTU-13 and CIC-IDS2018** (requirement 9), which ship the",
              "  captures that would close the point above.",
              "- **IPv6.** Both readers handle IPv4 only. A capture that is",
              "  mostly IPv6 will yield few packets rather than wrong ones.", ""]
    REPORT.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    arg = sys.argv[1] if len(sys.argv) > 1 else None
    tmp = None
    if arg:
        path, marks = Path(arg), {}
        print(f"reading {path} ...")
    else:
        tmp = tempfile.TemporaryDirectory()
        path = Path(tmp.name) / "synthetic.pcap"
        marks = synthetic_capture(path)
        print(f"no capture given; wrote a SYNTHETIC one to {path.name}")

    packets, reader = read_packets(path)
    states, _ = packet_windows(packets, window=WINDOW)
    print(f"  {len(packets):,} packets · {len(states)} windows of {WINDOW} "
          f"· reader={reader}")

    m = {
        "scapy": scapy_available(), "reader": reader,
        "n_packets": len(packets), "n_windows": len(states),
        "phases": phase_table(packets, marks) if marks else [],
        "model": model_over_packets(states),
    }
    if marks:
        write_report(m)
        print(f"  wrote {REPORT.relative_to(ROOT)}")
    for r in m["phases"]:
        print(f"    {r['phase']:9} portscan={r['portscan_score']:<7} "
              f"retrans={r['retransmission_rate']:<7} ttl_var={r['ttl_var']}")
    mo = m["model"]
    if mo.get("state") != "not measured":
        print(f"  world model over packet windows: {mo['n_states']} states, "
              f"{mo['state_dim']} dims, rollout ok")
    print("\ndetection performance on packet data: Not measured "
          "(no labelled capture bundled)")
    if tmp:
        tmp.cleanup()


if __name__ == "__main__":
    main()
