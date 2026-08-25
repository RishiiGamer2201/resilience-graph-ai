"""
src/engine3/packets.py — packet-level features and PCAP ingestion.

SIH 2026 requirements 7 and 8: TTL variance, TCP window size, fragment flags,
payload-length distribution, port-scan signatures and retransmission counts,
read from a real capture file.

Two readers, and the plain one is the default
---------------------------------------------
Classic pcap is a simple format: a 24-byte file header, then a 16-byte record
header before each frame. Parsing it needs `struct` and nothing else, so the
zero-dependency path stays zero-dependency and the slim deployed image does not
grow. Scapy is used when it is installed, because it handles pcapng, unusual
link types and malformed frames far better than sixty lines of `struct` ever
will, and because the problem statement names it.

    read_packets(path)            picks the best reader available
    packet_features(packets)      per-window feature vectors
    describe(path)                one call, file to feature matrix

What this does NOT claim
------------------------
**Detection performance on packet data is Not measured.** No labelled PCAP
corpus is bundled -- real captures are gigabytes and this project ships without
a download step -- so there is no honest accuracy number to report here, and
none is reported.

What IS verified is that the extractor computes what it says it computes. Every
feature is tested against frames whose properties are known because the test
builds them: a capture with TTLs of exactly 64, 63 and 128 must report that
variance, a SYN fan-out across twelve ports must register as a port scan, and a
repeated TCP sequence number must count as one retransmission. That is a real
correctness guarantee and it is a different claim from "it detects attacks".

The window vector follows the same shape CONVENTION as the one in
`src/engine3/netstate.py` -- mean and standard deviation per feature over a
window -- but NOT the same feature set, and the two are not interchangeable.

This paragraph used to end "a capture can therefore be fed to the same latent
state-space model without changing the model". It cannot, and saying so here
while `packet_windows` said the opposite left the file arguing with itself.
These are the 30 features of PACKET_FEATURES, 60 dimensions; the shipped
artifact was trained on 24 CIC-IDS2017 flow features, 48 dimensions. Using
these vectors means training an artifact on them. See `packet_windows` and
`NetStateModel.encode`, which refuses the mismatch by name.
"""
from __future__ import annotations

import math
import struct
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import numpy as np

# ─── Link-layer and protocol constants ────────────────────────────────────────
PCAP_MAGIC_LE = 0xA1B2C3D4         # microsecond timestamps, little-endian
PCAP_MAGIC_BE = 0xD4C3B2A1
PCAP_MAGIC_NS_LE = 0xA1B23C4D      # nanosecond timestamps
PCAP_MAGIC_NS_BE = 0x4D3CB2A1
PCAPNG_MAGIC = 0x0A0D0D0A

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_NULL = 0

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_VLAN = 0x8100

PROTO_TCP, PROTO_UDP, PROTO_ICMP = 6, 17, 1

# TCP flag bits, in the order they sit in the header byte.
FIN, SYN, RST, PSH, ACK, URG, ECE, CWR = (1, 2, 4, 8, 16, 32, 64, 128)

MAX_PACKETS = 2_000_000            # a cap, so a hostile capture cannot exhaust memory
WINDOW = 256                       # packets per state observation


@dataclass
class Packet:
    """The fields the features need. Deliberately flat and cheap."""

    ts: float
    length: int
    ttl: int = 0
    proto: int = 0
    src: str = ""
    dst: str = ""
    sport: int = 0
    dport: int = 0
    flags: int = 0
    window: int = 0
    seq: int = 0
    payload_len: int = 0
    frag_offset: int = 0
    dont_fragment: bool = False
    more_fragments: bool = False


# ─── Feature vector ───────────────────────────────────────────────────────────
# Every category the problem statement names, restricted to what a capture
# actually contains.
PACKET_FEATURES: list[str] = [
    # TTL: the PS names its variance specifically. A path change or a spoofed
    # source shows up here before it shows up anywhere else.
    "ttl_mean", "ttl_var", "ttl_unique",
    # TCP window: congestion behaviour, and a fingerprint of the sending stack.
    "tcp_window_mean", "tcp_window_std", "tcp_window_zero_rate",
    # Fragmentation.
    "frag_rate", "dont_fragment_rate", "more_fragments_rate",
    # Payload-length distribution.
    "payload_mean", "payload_std", "payload_zero_rate", "payload_entropy",
    # TCP flag distribution.
    "syn_rate", "ack_rate", "fin_rate", "rst_rate", "psh_rate", "urg_rate",
    # Port-scan signature: many destinations, many ports, SYN without ACK.
    "unique_dst_ports", "unique_dst_hosts", "syn_without_ack_rate",
    "ports_per_host", "portscan_score",
    # Retransmissions: a repeated (flow, seq) pair carrying payload.
    "retransmission_rate",
    # Timing and volume.
    "iat_mean", "iat_std", "packets_per_second", "bytes_per_second",
    "mean_packet_size",
]

STATE_DIM = len(PACKET_FEATURES) * 2      # mean and std of each, per window


def state_names() -> list[str]:
    return ([f"{c} (mean)" for c in PACKET_FEATURES]
            + [f"{c} (std)" for c in PACKET_FEATURES])


# ─── Readers ──────────────────────────────────────────────────────────────────
def scapy_available() -> bool:
    """Is scapy importable? Checked WITHOUT importing it.

    `import scapy.all` prints "No libpcap provider available" on a machine with
    no capture driver, which is every CI runner and this developer box. We only
    ever read files, so that warning is noise -- and noise in a verification log
    trains a reader to skim it.
    """
    from importlib.util import find_spec
    try:
        return find_spec("scapy") is not None
    except Exception:
        return False


def _ipv4(buf: bytes, ts: float, wire_len: int) -> Packet | None:
    """Parse one IPv4 datagram. Returns None for anything that is not IPv4."""
    if len(buf) < 20 or (buf[0] >> 4) != 4:
        return None
    ihl = (buf[0] & 0x0F) * 4
    if ihl < 20 or len(buf) < ihl:
        return None

    total_len, _ident, flags_frag, ttl, proto = struct.unpack("!H H H B B", buf[2:10])
    src = ".".join(str(b) for b in buf[12:16])
    dst = ".".join(str(b) for b in buf[16:20])

    p = Packet(ts=ts, length=wire_len, ttl=ttl, proto=proto, src=src, dst=dst,
               frag_offset=(flags_frag & 0x1FFF) * 8,
               dont_fragment=bool(flags_frag & 0x4000),
               more_fragments=bool(flags_frag & 0x2000))

    rest = buf[ihl:]
    if p.frag_offset > 0:
        # A non-first fragment carries no L4 header: those bytes are payload
        # continuation. Reading them as TCP invents a source port, a sequence
        # number and a window size out of file contents. Cross-checking the two
        # readers caught exactly this -- the stdlib path reported 300 unique
        # destination ports where scapy reported 282, the difference being the
        # 18 fragments, and it manufactured retransmissions from the fake
        # sequence numbers.
        p.payload_len = len(rest)
    elif proto == PROTO_TCP and len(rest) >= 20:
        sport, dport, seq, _ack = struct.unpack("!HHII", rest[:12])
        offset = (rest[12] >> 4) * 4
        p.sport, p.dport, p.seq = sport, dport, seq
        p.flags = rest[13]
        p.window = struct.unpack("!H", rest[14:16])[0]
        p.payload_len = max(0, min(total_len, len(buf)) - ihl - offset)
    elif proto == PROTO_UDP and len(rest) >= 8:
        p.sport, p.dport, udp_len, _ck = struct.unpack("!HHHH", rest[:8])
        p.payload_len = max(0, udp_len - 8)
    else:
        p.payload_len = max(0, min(total_len, len(buf)) - ihl)
    return p


def _strip_link(frame: bytes, linktype: int) -> bytes | None:
    """Return the IP datagram inside a link-layer frame."""
    if linktype == LINKTYPE_RAW:
        return frame
    if linktype == LINKTYPE_NULL:
        return frame[4:] if len(frame) > 4 else None
    if linktype == LINKTYPE_LINUX_SLL:
        if len(frame) < 16 or struct.unpack("!H", frame[14:16])[0] != ETHERTYPE_IPV4:
            return None
        return frame[16:]
    if linktype == LINKTYPE_ETHERNET:
        if len(frame) < 14:
            return None
        etype = struct.unpack("!H", frame[12:14])[0]
        off = 14
        if etype == ETHERTYPE_VLAN:                 # one VLAN tag is common enough
            if len(frame) < 18:
                return None
            etype = struct.unpack("!H", frame[16:18])[0]
            off = 18
        return frame[off:] if etype == ETHERTYPE_IPV4 else None
    return None


def read_pcap_stdlib(path: Path, *, limit: int = MAX_PACKETS) -> list[Packet]:
    """Classic pcap, with `struct` and nothing else.

    Keeps the zero-dependency path zero-dependency. Raises on pcapng, which this
    reader deliberately does not attempt -- a wrong answer from a half-parsed
    block file would be worse than an honest refusal.
    """
    raw = Path(path).read_bytes()
    if len(raw) < 24:
        raise ValueError("file is too short to be a pcap")

    magic = struct.unpack("<I", raw[:4])[0]
    if magic == PCAPNG_MAGIC or struct.unpack(">I", raw[:4])[0] == PCAPNG_MAGIC:
        raise ValueError("this is pcapng; install scapy to read it "
                         "(pip install scapy) or convert with editcap")
    if magic in (PCAP_MAGIC_LE, PCAP_MAGIC_NS_LE):
        endian, nano = "<", magic == PCAP_MAGIC_NS_LE
    elif magic in (PCAP_MAGIC_BE, PCAP_MAGIC_NS_BE):
        endian, nano = ">", magic == PCAP_MAGIC_NS_BE
    else:
        raise ValueError(f"not a pcap file: magic 0x{magic:08x}")

    linktype = struct.unpack(endian + "I", raw[20:24])[0]
    out: list[Packet] = []
    off, n = 24, len(raw)
    rec = struct.Struct(endian + "IIII")

    while off + 16 <= n and len(out) < limit:
        sec, frac, caplen, wirelen = rec.unpack_from(raw, off)
        off += 16
        if caplen > n - off:                      # truncated final record
            break
        frame = raw[off:off + caplen]
        off += caplen
        ip = _strip_link(frame, linktype)
        if ip:
            p = _ipv4(ip, sec + frac / (1e9 if nano else 1e6), wirelen)
            if p:
                out.append(p)
    return out


def read_pcap_scapy(path: Path, *, limit: int = MAX_PACKETS) -> list[Packet]:
    """Scapy path: handles pcapng, odd link types and malformed frames."""
    import logging
    # Live capture needs libpcap; reading a file does not. Silence the startup
    # warning rather than let it surface as if something were wrong.
    for name in ("scapy", "scapy.runtime", "scapy.loading"):
        logging.getLogger(name).setLevel(logging.ERROR)
    from scapy.all import IP, TCP, UDP, PcapReader

    out: list[Packet] = []
    with PcapReader(str(path)) as reader:
        for pkt in reader:
            if len(out) >= limit:
                break
            if IP not in pkt:
                continue
            ip = pkt[IP]
            p = Packet(ts=float(pkt.time), length=len(pkt), ttl=int(ip.ttl),
                       proto=int(ip.proto), src=str(ip.src), dst=str(ip.dst),
                       frag_offset=int(ip.frag) * 8,
                       dont_fragment=bool(int(ip.flags) & 0x02),
                       more_fragments=bool(int(ip.flags) & 0x01))
            if TCP in pkt:
                t = pkt[TCP]
                p.sport, p.dport = int(t.sport), int(t.dport)
                p.flags, p.window, p.seq = int(t.flags), int(t.window), int(t.seq)
                p.payload_len = len(bytes(t.payload))
            elif UDP in pkt:
                u = pkt[UDP]
                p.sport, p.dport = int(u.sport), int(u.dport)
                p.payload_len = len(bytes(u.payload))
            else:
                p.payload_len = len(bytes(ip.payload))
            out.append(p)
    return out


def read_packets(path: str | Path, *, limit: int = MAX_PACKETS,
                 prefer_scapy: bool = True) -> tuple[list[Packet], str]:
    """Read a capture with the best reader available. Returns (packets, reader)."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(path)
    if prefer_scapy and scapy_available():
        return read_pcap_scapy(path, limit=limit), "scapy"
    try:
        return read_pcap_stdlib(path, limit=limit), "stdlib"
    except ValueError:
        if not prefer_scapy and scapy_available():
            return read_pcap_scapy(path, limit=limit), "scapy"
        raise


# ─── Features ─────────────────────────────────────────────────────────────────
def _entropy(values: list[int], bins: int = 16) -> float:
    """Shannon entropy of the payload-length distribution, in bits.

    A window where every payload is the same size scores 0; a scan or a beacon
    looks very different from a file transfer here, and neither the mean nor the
    standard deviation separates them reliably.
    """
    if not values:
        return 0.0
    counts = Counter(min(bins - 1, int(math.log2(v + 1))) for v in values)
    total = sum(counts.values())
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def window_features(packets: list[Packet]) -> dict[str, float]:
    """The packet-level features the problem statement names, for one window."""
    n = len(packets)
    if n == 0:
        return dict.fromkeys(PACKET_FEATURES, 0.0)

    ttl = np.array([p.ttl for p in packets], dtype=float)
    lens = np.array([p.length for p in packets], dtype=float)
    payloads = [p.payload_len for p in packets]
    pay = np.array(payloads, dtype=float)

    tcp = [p for p in packets if p.proto == PROTO_TCP]
    win = np.array([p.window for p in tcp], dtype=float) if tcp else np.zeros(1)

    def rate(pred) -> float:
        return sum(1 for p in packets if pred(p)) / n

    # Port-scan signature. A scanner sends SYN with no ACK to many ports and
    # gets few completed handshakes; ports_per_host separates a scan from a
    # busy client talking to one server on many ephemeral ports.
    dst_ports = {p.dport for p in packets if p.dport}
    dst_hosts = {p.dst for p in packets if p.dst}
    syn_no_ack = sum(1 for p in tcp if (p.flags & SYN) and not (p.flags & ACK))
    ports_per_host = len(dst_ports) / max(len(dst_hosts), 1)
    portscan = (syn_no_ack / n) * min(ports_per_host / 10.0, 1.0)

    # Retransmissions: the same (src, dst, sport, dport, seq) seen more than
    # once carrying payload. Counted as repeats, so three sends of one segment
    # are two retransmissions.
    seen: Counter = Counter()
    retrans = 0
    for p in tcp:
        if p.payload_len == 0:
            continue
        key = (p.src, p.dst, p.sport, p.dport, p.seq)
        seen[key] += 1
        if seen[key] > 1:
            retrans += 1

    ts = sorted(p.ts for p in packets)
    iats = np.diff(ts) if len(ts) > 1 else np.zeros(1)
    span = max(ts[-1] - ts[0], 1e-6)

    return {
        "ttl_mean": float(ttl.mean()),
        "ttl_var": float(ttl.var()),
        "ttl_unique": float(len(set(int(t) for t in ttl))),
        "tcp_window_mean": float(win.mean()),
        "tcp_window_std": float(win.std()),
        "tcp_window_zero_rate": float((win == 0).mean()) if tcp else 0.0,
        "frag_rate": rate(lambda p: p.frag_offset > 0 or p.more_fragments),
        "dont_fragment_rate": rate(lambda p: p.dont_fragment),
        "more_fragments_rate": rate(lambda p: p.more_fragments),
        "payload_mean": float(pay.mean()),
        "payload_std": float(pay.std()),
        "payload_zero_rate": float((pay == 0).mean()),
        "payload_entropy": _entropy(payloads),
        "syn_rate": rate(lambda p: bool(p.flags & SYN)),
        "ack_rate": rate(lambda p: bool(p.flags & ACK)),
        "fin_rate": rate(lambda p: bool(p.flags & FIN)),
        "rst_rate": rate(lambda p: bool(p.flags & RST)),
        "psh_rate": rate(lambda p: bool(p.flags & PSH)),
        "urg_rate": rate(lambda p: bool(p.flags & URG)),
        "unique_dst_ports": float(len(dst_ports)),
        "unique_dst_hosts": float(len(dst_hosts)),
        "syn_without_ack_rate": syn_no_ack / n,
        "ports_per_host": float(ports_per_host),
        "portscan_score": float(portscan),
        "retransmission_rate": retrans / n,
        "iat_mean": float(iats.mean()),
        "iat_std": float(iats.std()),
        "packets_per_second": n / span,
        "bytes_per_second": float(lens.sum()) / span,
        "mean_packet_size": float(lens.mean()),
    }


def packet_windows(packets: list[Packet], *, window: int = WINDOW
                   ) -> tuple[np.ndarray, list[dict]]:
    """Consecutive windows of packets -> (states, per-window feature dicts).

    `states` follows the same shape CONVENTION as src/engine3/netstate.py -- the
    mean and the standard deviation of each feature across the window -- but not
    the same feature set, and the two are not interchangeable.

    This used to say a capture "can be handed to the same latent state-space
    model unchanged". It cannot. These are the 30 features of PACKET_FEATURES,
    60 dimensions; the shipped artifact (models/netstate_cicids.npz) was trained
    on the 24 CIC-IDS2017 flow features, 48 dimensions. Nothing converts one
    into the other: TTL variance and retransmission rate are not recoverable
    from flow records, and Init_Win_bytes_backward is not recoverable from a
    packet window. Using these vectors means training an artifact on them --
    which is what tests do, and why those tests never caught the claim.
    NetStateModel.encode() now refuses the mismatch by name.
    """
    if len(packets) < window:
        return np.empty((0, STATE_DIM)), []

    rows, dicts = [], []
    for i in range(0, len(packets) - window + 1, window):
        chunk = packets[i:i + window]
        # Sub-window statistics, so the vector carries dispersion within the
        # window and not only its centre. One value per feature would hide a
        # burst that averages out.
        subs = [window_features(chunk[j:j + max(window // 8, 1)])
                for j in range(0, window, max(window // 8, 1))]
        m = np.array([[s[f] for f in PACKET_FEATURES] for s in subs], dtype=float)
        rows.append(np.concatenate([m.mean(axis=0), m.std(axis=0)]))
        dicts.append(window_features(chunk))
    return np.vstack(rows), dicts


def describe(path: str | Path, *, window: int = WINDOW) -> dict:
    """Read a capture and summarise it. One call, file to features."""
    packets, reader = read_packets(path)
    states, per_window = packet_windows(packets, window=window)
    return {
        "path": str(path),
        "reader": reader,
        "n_packets": len(packets),
        "n_windows": len(states),
        "window": window,
        "state_dim": STATE_DIM,
        "features": PACKET_FEATURES,
        "states": states,
        "windows": per_window,
        "note": ("Packet-level features extracted. Detection performance on "
                 "packet data is NOT measured: no labelled PCAP corpus is "
                 "bundled with this project."),
    }


# ─── Writing a capture, for tests and for the self-check ──────────────────────
def write_pcap(path: str | Path, packets: list[dict]) -> Path:
    """Write a classic pcap of synthetic Ethernet/IPv4 frames.

    Exists so the reader and the features can be exercised offline against
    frames whose properties are known exactly, because the caller chose them.
    A capture written here is synthetic and is never presented as real traffic.
    """
    def ip_frame(p: dict) -> bytes:
        proto = p.get("proto", PROTO_TCP)
        payload = b"\x00" * p.get("payload_len", 0)
        if proto == PROTO_TCP:
            l4 = struct.pack("!HHIIBBHHH", p.get("sport", 1234), p.get("dport", 80),
                             p.get("seq", 1), 0, 5 << 4, p.get("flags", SYN),
                             p.get("window", 8192), 0, 0) + payload
        elif proto == PROTO_UDP:
            l4 = struct.pack("!HHHH", p.get("sport", 1234), p.get("dport", 53),
                             8 + len(payload), 0) + payload
        else:
            l4 = payload

        flags_frag = ((0x4000 if p.get("dont_fragment") else 0)
                      | (0x2000 if p.get("more_fragments") else 0)
                      | (p.get("frag_offset", 0) // 8))
        total = 20 + len(l4)
        ip = struct.pack("!BBHHHBBH", 0x45, 0, total, p.get("ident", 1),
                         flags_frag, p.get("ttl", 64), proto, 0)
        ip += bytes(int(o) for o in p.get("src", "10.0.0.1").split("."))
        ip += bytes(int(o) for o in p.get("dst", "10.0.0.2").split("."))
        return ip + l4

    path = Path(path)
    with path.open("wb") as f:
        f.write(struct.pack("<IHHiIII", PCAP_MAGIC_LE, 2, 4, 0, 0, 65535,
                            LINKTYPE_ETHERNET))
        for i, p in enumerate(packets):
            frame = b"\xff" * 6 + b"\x00" * 6 + struct.pack("!H", ETHERTYPE_IPV4)
            frame += ip_frame(p)
            ts = p.get("ts", i * 0.001)
            f.write(struct.pack("<IIII", int(ts), int((ts % 1) * 1e6),
                                len(frame), len(frame)))
            f.write(frame)
    return path


# ─── Self-check ───────────────────────────────────────────────────────────────
def demo() -> None:
    """Asserts the extractor computes what it claims, against known frames."""
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        # A port scan: one source, one host, many ports, SYN with no ACK,
        # no payload, TTL fixed at 64.
        scan = [{"dst": "10.0.0.9", "dport": 1000 + i, "flags": SYN, "ttl": 64,
                 "ts": i * 0.0005} for i in range(256)]
        # A file transfer: two hosts, one port, PSH+ACK, large payloads,
        # varying TTL, and one segment sent twice.
        xfer = []
        for i in range(256):
            xfer.append({"dst": "10.0.0.20", "dport": 443, "flags": PSH | ACK,
                         "ttl": 64 if i % 2 else 63, "payload_len": 1400,
                         "seq": 1000 + (i - 1 if i == 200 else i),
                         "window": 64240, "dont_fragment": True,
                         "ts": 1.0 + i * 0.01})

        sp = write_pcap(Path(d) / "scan.pcap", scan)
        xp = write_pcap(Path(d) / "xfer.pcap", xfer)

        s, reader = read_packets(sp)
        x, _ = read_packets(xp)
        assert len(s) == 256 and len(x) == 256, (len(s), len(x))

        fs = window_features(s)
        fx = window_features(x)

        # TTL: the scan is a single constant, the transfer alternates 64/63.
        assert fs["ttl_var"] == 0.0 and fs["ttl_unique"] == 1.0, fs
        assert fx["ttl_unique"] == 2.0 and fx["ttl_var"] > 0.0, fx

        # Port-scan signature must separate the two, decisively.
        assert fs["unique_dst_ports"] == 256, fs
        assert fs["syn_without_ack_rate"] == 1.0, fs
        assert fs["portscan_score"] > 0.9, fs
        assert fx["portscan_score"] < 0.01, fx

        # Payload distribution.
        assert fs["payload_zero_rate"] == 1.0 and fs["payload_entropy"] == 0.0, fs
        assert fx["payload_mean"] == 1400.0, fx

        # Retransmission: exactly one duplicated (flow, seq) in the transfer.
        assert fx["retransmission_rate"] == 1 / 256, fx["retransmission_rate"]
        assert fs["retransmission_rate"] == 0.0, fs

        # TCP window and fragmentation flags survive the round trip.
        assert fx["tcp_window_mean"] == 64240.0, fx
        assert fx["dont_fragment_rate"] == 1.0 and fs["dont_fragment_rate"] == 0.0

        # Window vectors are the shape the world model expects.
        states, dicts = packet_windows(s, window=128)
        assert states.shape == (2, STATE_DIM), states.shape
        assert len(dicts) == 2 and np.isfinite(states).all()

    print(f"packets ok: {len(PACKET_FEATURES)} packet features, {STATE_DIM}-dim "
          f"windows · reader={reader} · scapy "
          f"{'available' if scapy_available() else 'not installed, stdlib reader used'} "
          f"· scan vs transfer separated on TTL, ports, payload and retransmits")


if __name__ == "__main__":
    demo()
