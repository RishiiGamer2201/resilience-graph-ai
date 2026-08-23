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


def attacker_pivots(g: nx.DiGraph) -> list[str]:
    """Hosts that ORIGINATE flagged movement — i.e. attacker-controlled sources.

    A real campaign runs from several machines (the LANL red team used four), so a
    single-entry model silently under-reports: reachability computed from one host
    misses everything the other pivots touched.
    """
    return sorted((n for n in g.nodes if g.out_degree(n) > 0),
                  key=lambda n: (-g.out_degree(n), n))


def analyze(g: nx.DiGraph, entry_host: str | None = None,
            critical_assets: set[str] | None = None,
            choke_points: bool = True) -> dict:
    """Compute paths to critical assets, choke points, and blast radius.

    Reachability is computed from EVERY attacker pivot, not just the busiest one.
    """
    critical_assets = critical_assets or {n for n, d in g.nodes(data=True) if d.get("critical")}
    pivots = attacker_pivots(g)
    entry_host = entry_host or (pivots[0] if pivots else _infer_entry(g))

    # shortest path to each critical asset from ANY pivot (not only the primary)
    paths = {}
    for asset in critical_assets:
        if asset not in g:
            continue
        best = None
        for p in pivots:
            if p != asset and nx.has_path(g, p, asset):
                sp = nx.shortest_path(g, p, asset)
                if best is None or len(sp) < len(best):
                    best = sp
        if best:
            paths[asset] = best

    # Betweenness centrality is useful context, but it is not a containment
    # recommendation: the best central node may protect no crown jewels.
    bc = nx.betweenness_centrality(g) if (choke_points and g.number_of_nodes() > 2) else {}
    choke_points = sorted(bc, key=bc.get, reverse=True)[:3]

    # blast radius = everything reachable from ANY attacker pivot
    blast = set()
    for p in pivots:
        blast |= nx.descendants(g, p)
    blast = sorted(blast)

    isolation, isolation_cuts = _best_isolation(g, pivots, set(paths), len(blast), entry_host)

    return {
        "entry_host": entry_host,
        "attacker_pivots": pivots[:10],
        "n_pivots": len(pivots),
        "n_nodes": g.number_of_nodes(),
        "n_edges": g.number_of_edges(),
        "critical_assets_at_risk": sorted(paths),
        "paths_to_critical": paths,
        "choke_points": choke_points,
        "blast_radius_size": len(blast),      # total exposure, all pivots
        "blast_radius": blast[:20],           # cap for display
        "recommended_isolation": isolation,
        "isolation_cuts": isolation_cuts,     # what isolating that one host severs
    }


def _infer_entry(g: nx.DiGraph) -> str | None:
    """Entry host = highest out-degree source (the pivot point)."""
    if g.number_of_nodes() == 0:
        return None
    return max(g.nodes, key=lambda n: g.out_degree(n))


def _reachable_from_pivots(g: nx.DiGraph, pivots: list[str]) -> set[str]:
    reachable: set[str] = set()
    for p in pivots:
        if p in g:
            reachable |= nx.descendants(g, p)
    return reachable


def _critical_reachable(g: nx.DiGraph, pivots: list[str], critical: set[str]) -> set[str]:
    reached: set[str] = set()
    for asset in critical:
        if asset not in g:
            continue
        if any(p in g and p != asset and nx.has_path(g, p, asset) for p in pivots):
            reached.add(asset)
    return reached


def _best_isolation(g: nx.DiGraph, pivots: list[str], critical_at_risk: set[str],
                    blast_radius_size: int, fallback: str | None) -> tuple[str | None, int]:
    """Pick the host whose removal gives the strongest containment benefit."""
    candidates = [n for n in g.nodes if g.out_degree(n) > 0]
    if not candidates:
        return fallback, 0

    ranked = []
    for host in candidates:
        after = g.copy()
        after.remove_node(host)
        after_pivots = [p for p in pivots if p != host]
        after_critical = _critical_reachable(after, after_pivots, critical_at_risk - {host})
        after_blast = _reachable_from_pivots(after, after_pivots)
        protected = len(critical_at_risk - after_critical)
        cut = blast_radius_size - len(after_blast)
        ranked.append((protected, cut, -g.degree(host), host))

    protected, cut, _, host = max(ranked)
    if protected <= 0 and cut <= 0:
        return fallback, 0
    return host, cut
