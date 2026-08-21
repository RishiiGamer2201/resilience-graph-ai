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


def _node_type(entity: str, events_df=None, criticality: str = "") -> str:
    if criticality in ("high", "critical"):
        return "critical_asset"
    if not _is_internal(entity):
        return "external_ip"
    if entity.upper().startswith(("U", "USER", "SVC", "ADMIN")):
        return "user"
    return "host"


def run(intelligence_result: AgentResult) -> AgentResult:
    """Build a graph skeleton: nodes placed, no edges yet.

    Returns AgentResult with:
        output["nodes"]: list of node dicts (id, type, label, metadata)
        output["node_count"]: total nodes
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

    for chunk in mapped:
        entity = str(chunk.get("entity", ""))
        stats = chunk.get("stats", {})
        tid = chunk.get("technique_id")
        tactic = chunk.get("tactic", "")
        score = chunk.get("anomaly_score", 0)

        # Entity node (user or host depending on entity_col used in chunking)
        etype = _node_type(entity)
        _add_node(entity, etype, label=entity, meta={"max_score": score})

        # Destination hosts mentioned in this chunk
        for col in ("destination_host_top",):
            for host in (stats.get(col) or {}).keys():
                htype = _node_type(host)
                _add_node(host, htype, label=host)

        # Technique node
        if tid:
            _add_node(
                tid, "technique",
                label=f"{tid} ({chunk.get('technique_name', '')})",
                meta={"tactic": tactic},
            )

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
            # Pass through the mapped chunks so KB Connector can build edges
            "_mapped_chunks": mapped,
        },
        notes=[f"Built skeleton with {len(nodes)} nodes: {dict(node_types)}."],
        ms=(time.perf_counter() - t0) * 1000,
    )
