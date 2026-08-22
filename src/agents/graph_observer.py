"""
src/agents/graph_observer.py — Agent 4: Graph Observation (Skeleton Blueprint)

Sarthak's doc: "organizes them by attacker logic — not just 'event happened,'
but grouped by exposure type, identity, and asset into a structured blueprint:
nodes for hosts/users/assets, initial placement based on what kind of access
or exposure each represents."

Input:  AgentResult from Intelligence (mapped chunks with technique IDs)
Output: AgentResult with graph skeleton — nodes placed, no edges yet.

Node types:
  "user"            — identity node (source of action)
  "host"            — workstation or server involved in movement
  "critical_asset"  — asset_criticality == "high" or "critical"
  "external_ip"     — destination outside the internal estate
  "technique"       — ATT&CK technique observed

Usage:
    from src.agents.graph_observer import run
    result = run(intelligence_result)
"""
from __future__ import annotations

import re
import time
from collections import defaultdict

from src.agents import AgentResult, AgentStatus

# ─── Internal IP heuristic ─────────────────────────────────────────────────────
_INTERNAL_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                      "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                      "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                      "172.30.", "172.31.", "192.168.", "127.", "C", "AUTH")


def _is_internal(host: str) -> bool:
    return any(str(host).startswith(p) for p in _INTERNAL_PREFIXES)


_IPISH = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _node_type(entity: str, events_df=None, criticality: str = "") -> str:
    """Classify a node.

    The previous version asked only "does this start with an internal IP
    prefix?" and returned `external_ip` for everything else. Those prefixes are
    LANL-shaped ("C", "AUTH"), so on any other estate every hostname and every
    username was labelled an external IP: `WARD-PC-041`, `PATIENT-DB-01` and
    `lab.iyer@AIIMS` all came back `external_ip`, which is both wrong and
    alarming to read.

    Order matters: an identity is an identity regardless of what it looks like,
    and only something that actually parses as a non-private IP is external.
    """
    e = str(entity or "").strip()
    if not e:
        return "host"
    if criticality in ("high", "critical"):
        return "critical_asset"
    if "@" in e or "\\" in e:                 # user@domain, DOMAIN\user
        return "user"
    if _IPISH.match(e):
        return "host" if _is_internal(e) else "external_ip"
    if e.upper().startswith(("USER", "SVC", "ADMIN")):
        return "user"
    if _is_internal(e):                        # LANL-style C####/AUTH hosts
        return "host"
    return "host"                              # a hostname is a host


def run(intelligence_result: AgentResult) -> AgentResult:
    """Build the entity graph: hosts, identities and techniques, WITH edges.

    Nodes and edges are derived from each chunk's actual events rather than from
    its summary statistics. The previous version read a `destination_host_top`
    key the chunker never emits (it emits `destination_host_unique`, a count),
    so no destination host was ever added and the whole graph was two nodes; and
    it built no edges at all, which left the KB connector deriving a single one.

    Returns AgentResult with:
        output["nodes"]: node dicts (id, type, label, critical, metadata)
        output["edges"]: source -> destination movements with counts and scores
        output["node_count"], output["edge_count"]
    """
    t0 = time.perf_counter()

    mapped: list[dict] = intelligence_result.output.get("mapped", [])
    if not mapped:
        return AgentResult(
            agent="graph_observer",
            status=AgentStatus.DEGRADED,
            confidence=0.0,
            notes=["No mapped chunks from Intelligence."],
            ms=(time.perf_counter() - t0) * 1000,
        )

    # Deduplicated node registry: node_id -> node dict
    nodes: dict[str, dict] = {}

    def _add_node(nid: str, ntype: str, label: str = "", meta: dict | None = None):
        if nid and nid not in nodes:
            nodes[nid] = {
                "id": nid,
                "type": ntype,
                "label": label or nid,
                "critical": ntype == "critical_asset",
                "meta": meta or {},
            }

    # edge registry: (src, dst) -> edge dict
    edges: dict[tuple, dict] = {}

    def _add_edge(src: str, dst: str, **meta):
        if not src or not dst or src == dst:
            return
        key = (src, dst)
        e = edges.get(key)
        if e is None:
            edges[key] = {
                "source": src, "target": dst, "from": src, "to": dst,
                "event_count": 1,
                "score": meta.get("score", 0),
                "technique": meta.get("technique"),
                "tactic": meta.get("tactic", ""),
                "users": [u for u in [meta.get("user")] if u],
                "kind": meta.get("kind", "movement"),
            }
        else:
            e["event_count"] += 1
            e["score"] = max(e["score"], meta.get("score", 0))
            u = meta.get("user")
            if u and u not in e["users"]:
                e["users"].append(u)

    for chunk in mapped:
        entity = str(chunk.get("entity", ""))
        tid = chunk.get("technique_id")
        tactic = chunk.get("tactic", "")
        score = chunk.get("anomaly_score", 0)

        # Entity node (user or host depending on entity_col used in chunking)
        etype = _node_type(entity)
        _add_node(entity, etype, label=entity, meta={"max_score": score})

        # Hosts and movements come from the chunk's ACTUAL events. The chunk
        # carries them as a DataFrame; the summary stats only carry counts.
        # The scored/mapped record is a flat summary; the original EventChunk
        # travels with it as `_chunk_ref` and is the only thing holding the
        # actual events.
        events = chunk.get("events")
        ref = chunk.get("_chunk_ref")
        if events is None and ref is not None:
            events = getattr(ref, "events", None)
        rows = []
        if events is not None and hasattr(events, "to_dict"):
            rows = events.to_dict("records")
        elif isinstance(events, list):
            rows = events

        for row in rows:
            src = str(row.get("source_host") or "").strip()
            dst = str(row.get("destination_host") or "").strip()
            user = str(row.get("user") or "").strip()
            if src:
                _add_node(src, _node_type(src), label=src)
            if dst:
                _add_node(dst, _node_type(dst), label=dst)
            # the movement itself
            _add_edge(src, dst, score=score, technique=tid, tactic=tactic,
                      user=user, kind="movement")
            # who drove it, when the chunk is keyed by identity
            if user and dst and user != dst:
                _add_node(user, _node_type(user), label=user)
                _add_edge(user, dst, score=score, technique=tid, tactic=tactic,
                          user=user, kind="authenticated_to")

        # Technique node, linked to the entity it was observed on
        if tid:
            _add_node(
                tid, "technique",
                label=f"{tid} ({chunk.get('technique_name', '')})",
                meta={"tactic": tactic},
            )
            _add_edge(entity, tid, score=score, technique=tid, tactic=tactic,
                      kind="exhibits")

    node_types = defaultdict(int)
    for n in nodes.values():
        node_types[n["type"]] += 1

    return AgentResult(
        agent="graph_observer",
        status=AgentStatus.OK,
        confidence=1.0,
        output={
            "nodes": list(nodes.values()),
            "node_count": len(nodes),
            "node_type_counts": dict(node_types),
            "edges": list(edges.values()),
            "edge_count": len(edges),
            # Pass through the mapped chunks so KB Connector can build edges
            "_mapped_chunks": mapped,
        },
        notes=[f"Built entity graph: {len(nodes)} nodes {dict(node_types)}, "
               f"{len(edges)} edges."],
        ms=(time.perf_counter() - t0) * 1000,
    )
