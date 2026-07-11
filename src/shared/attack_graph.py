"""
Milestone 4 · S4 — Attack-path graph.

Builds a host/user/asset graph from a correlated incident and answers the
questions a responder actually asks:
  * How did the attacker move? (edges = authentications)
  * Which critical assets are reachable / at risk?  (shortest path to a crown jewel)
  * Which node should we isolate to cut the most paths? (betweenness choke point)
  * What's the blast radius from the entry host? (reachable set)

    from src.shared.attack_graph import build_graph, analyze
"""
from __future__ import annotations

import networkx as nx


def build_graph(incident: dict, critical_assets: set[str] | None = None) -> nx.DiGraph:
    """Directed graph: source_host -> destination_host, one edge per alert."""
    critical_assets = critical_assets or set()
    g = nx.DiGraph()
    for s in incident["alerts"]:
        src, dst = s["source_host"], s["destination_host"]
        if not src or not dst:
            continue
        g.add_node(src)
        g.add_node(dst, critical=dst in critical_assets)
        g.add_edge(src, dst, technique=s["technique_id"],
                   tactic=s["tactic"], score=s["anomaly_score"])
    for n in g.nodes:
        g.nodes[n].setdefault("critical", n in critical_assets)
    return g


def analyze(g: nx.DiGraph, entry_host: str | None = None,
            critical_assets: set[str] | None = None) -> dict:
    """Compute path-to-critical-asset, choke points, and blast radius."""
    critical_assets = critical_assets or {n for n, d in g.nodes(data=True) if d.get("critical")}
    entry_host = entry_host or _infer_entry(g)

    # shortest path from entry host to each reachable critical asset
    paths = {}
    for asset in critical_assets:
        if entry_host and asset in g and nx.has_path(g, entry_host, asset):
            paths[asset] = nx.shortest_path(g, entry_host, asset)

    # betweenness centrality -> choke points to isolate
    bc = nx.betweenness_centrality(g) if g.number_of_nodes() > 2 else {}
    choke_points = sorted(bc, key=bc.get, reverse=True)[:3]

    # blast radius = everything reachable from the entry host
    blast = sorted(nx.descendants(g, entry_host)) if entry_host in g else []

    return {
        "entry_host": entry_host,
        "n_nodes": g.number_of_nodes(),
        "n_edges": g.number_of_edges(),
        "critical_assets_at_risk": sorted(paths),
        "paths_to_critical": paths,
        "choke_points": choke_points,
        "blast_radius_size": len(blast),
        "blast_radius": blast[:20],           # cap for display
        "recommended_isolation": choke_points[0] if choke_points else entry_host,
    }


def _infer_entry(g: nx.DiGraph) -> str | None:
    """Entry host = highest out-degree source (the pivot point)."""
    if g.number_of_nodes() == 0:
        return None
    return max(g.nodes, key=lambda n: g.out_degree(n))
