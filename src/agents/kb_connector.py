"""
src/agents/kb_connector.py — Agent 5: Knowledge Base Connection (Edge Building)

Sarthak's doc: "this is where edges actually get built — cross-references your
knowledge base (ATT&CK relationships, technique-to-technique transitions, past
incidents, group profiles) to decide which nodes should connect and why (same
session, lateral reachability, privilege chain, known technique sequence)."

Wraps:  src/shared/attack_graph.py  (NetworkX edge logic)
        src/shared/parse_attack.py  (ATT&CK STIX relationships)

Input:  AgentResult from Graph Observer (skeleton nodes + mapped chunks)
Output: AgentResult with a connected NetworkX DiGraph (JSON-serializable view).

Edge types:
  "auth"        — user authenticated to host
  "movement"    — host→host lateral move
  "used"        — entity used ATT&CK technique
  "follows"     — ATT&CK technique transition (from KB)
  "mitigated_by"— technique→mitigation edge

Usage:
    from src.agents.kb_connector import run
    result = run(graph_observer_result)
"""
from __future__ import annotations

import time

import networkx as nx

from src.agents import AgentResult, AgentStatus
from src.shared.attack_graph import analyze as _graph_analyze

# ─── ATT&CK STIX lookup (lazy) ────────────────────────────────────────────────
_attack_data: dict | None = None


def _get_attack():
    global _attack_data
    if _attack_data is None:
        try:
            from src.shared.parse_attack import load_attack
            _attack_data = load_attack()
        except Exception:
            _attack_data = {}
    return _attack_data


def _get_mitigations(tid: str) -> list[str]:
    attack = _get_attack()
    return attack.get("mitigations_by_technique", {}).get(tid, [])


def _get_technique_transitions(tid: str) -> list[str]:
    """Returns technique IDs that commonly follow `tid` based on the ATT&CK chain."""
    attack = _get_attack()
    # Use the pre-built tactic ordering to infer plausible next techniques
    tactic_order = attack.get("tactic_order", [])
    tech_to_tactic = attack.get("tech_to_tactic", {})
    my_tactic = tech_to_tactic.get(tid, "")

    if not my_tactic or my_tactic not in tactic_order:
        return []
    idx = tactic_order.index(my_tactic)
    if idx + 1 >= len(tactic_order):
        return []
    next_tactic = tactic_order[idx + 1]
    techs_in_next = [
        t for t, tac in tech_to_tactic.items() if tac == next_tactic
    ]
    return techs_in_next[:3]  # limit to 3 likely followers


def run(graph_observer_result: AgentResult) -> AgentResult:
    """Build a connected DiGraph by adding labeled edges between skeleton nodes.

    Returns AgentResult with:
        output["graph_view"]: JSON-serializable graph (nodes + edges)
        output["edge_count"]: total edges
        output["graph_analysis"]: blast-radius and choke-point analysis
    """
    t0 = time.perf_counter()

    nodes: list[dict] = graph_observer_result.output.get("nodes", [])
    mapped_chunks: list[dict] = graph_observer_result.output.get("_mapped_chunks", [])

    if not nodes:
        return AgentResult(
            agent="kb_connector",
            status=AgentStatus.DEGRADED,
            confidence=0.0,
            notes=["No nodes from Graph Observer."],
            ms=(time.perf_counter() - t0) * 1000,
        )

    # ── Build NetworkX DiGraph ──────────────────────────────────────────────
    G = nx.DiGraph()

    for node in nodes:
        G.add_node(node["id"], **{k: v for k, v in node.items() if k != "id"})

    evidence_refs: list[str] = []
    edges_added: list[dict] = []

    for chunk in mapped_chunks:
        entity = str(chunk.get("entity", ""))
        stats = chunk.get("stats", {})
        tid = chunk.get("technique_id")
        tactic = chunk.get("tactic", "")
        score = chunk.get("anomaly_score", 0)
        t_start = chunk.get("t_start", 0)

        # Edge: entity --[auth]--> destination hosts.
        # `destination_host_top` never existed; the chunker emits
        # `destination_host_unique`, a count. Host relationships now come from
        # the observer's event-derived edges, below.
        for dst_host in ():
            if entity and dst_host and entity != dst_host:
                if not G.has_node(entity):
                    G.add_node(entity, type="user", critical=False)
                if not G.has_node(dst_host):
                    G.add_node(dst_host, type="host", critical=False)
                G.add_edge(entity, dst_host,
                           relation="auth", technique=tid or "",
                           tactic=tactic, score=score, timestamp=t_start)
                edges_added.append({"from": entity, "to": dst_host, "relation": "auth"})

        # Edge: entity --[used]--> technique node
        if tid and G.has_node(tid):
            G.add_edge(entity, tid,
                       relation="used", tactic=tactic, score=score)
            evidence_refs.append(tid)
            edges_added.append({"from": entity, "to": tid, "relation": "used"})

        # Edge: technique --[follows]--> likely next techniques (from KB)
        if tid:
            for next_tid in _get_technique_transitions(tid):
                if G.has_node(next_tid):
                    G.add_edge(tid, next_tid, relation="follows", source="att&ck_kb")
                    edges_added.append({"from": tid, "to": next_tid, "relation": "follows"})

        # Edge: technique --[mitigated_by]--> mitigation IDs
        if tid:
            for mit in _get_mitigations(tid)[:2]:
                mit_id = f"MIT:{mit[:20]}"
                if not G.has_node(mit_id):
                    G.add_node(mit_id, type="mitigation", critical=False)
                G.add_edge(tid, mit_id, relation="mitigated_by")
                edges_added.append({"from": tid, "to": mit_id, "relation": "mitigated_by"})

    # ── Observed movements, from the graph observer ─────────────────────────
    # These are derived from the chunks' ACTUAL events (source_host ->
    # destination_host), not from summary statistics, so they are the real
    # topology rather than an inference about it.
    for edge in graph_observer_result.output.get("edges", []):
        src = str(edge.get("from") or edge.get("source") or "")
        dst = str(edge.get("to") or edge.get("target") or "")
        if not src or not dst or src == dst:
            continue
        if not G.has_node(src):
            G.add_node(src, type="host", critical=False)
        if not G.has_node(dst):
            G.add_node(dst, type="host", critical=False)
        if G.has_edge(src, dst):
            continue
        G.add_edge(src, dst,
                   relation=edge.get("kind", "movement"),
                   technique=edge.get("technique") or "",
                   tactic=edge.get("tactic", ""),
                   score=edge.get("score", 0),
                   users=edge.get("users", []),
                   event_count=edge.get("event_count", 1))
        edges_added.append({"from": src, "to": dst,
                            "relation": edge.get("kind", "movement")})

    # ── Serialize graph + run blast-radius analysis ─────────────────────────
    graph_view = {
        "nodes": [{"id": n, **G.nodes[n]} for n in G.nodes],
        "edges": [
            {"from": u, "to": v, **d}
            for u, v, d in G.edges(data=True)
        ],
    }

    try:
        graph_analysis = _graph_analyze(G)
    except Exception as e:
        graph_analysis = {"error": str(e)}

    return AgentResult(
        agent="kb_connector",
        status=AgentStatus.OK,
        confidence=0.85,
        output={
            "graph_view": graph_view,
            "edge_count": G.number_of_edges(),
            "node_count": G.number_of_nodes(),
            "graph_analysis": graph_analysis,
            "_graph": G,  # live object for Validator/Prioritizer
        },
        evidence_refs=list(set(evidence_refs)),
        notes=[
            f"Connected graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges.",
        ],
        ms=(time.perf_counter() - t0) * 1000,
    )
