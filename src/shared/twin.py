"""Cyber-resilience digital twin — counterfactual containment on the real graph.

"If we isolate this host, what actually changes?" is the question a responder has
to answer before they take a production system off the network in a hospital or
an exam board. This module answers it with graph analysis, not opinion:

  1. clone the incident's attack graph (the original is never mutated),
  2. apply a candidate containment (isolate a host, or cut one movement edge),
  3. recompute attacker reachability, crown-jewel exposure and choke points,
  4. return the before/after diff INCLUDING the operational cost, because a
     containment that severs 463 hosts is a decision, not a free win.

Everything here is deterministic NetworkX. No model, no LLM, no randomness — run
it twice on the same input and you get byte-identical output.

    from src.shared.twin import simulate, rank_candidates
    diff = simulate(graph_view, isolate_host="C2388")
"""
from __future__ import annotations

import networkx as nx

from src.shared.attack_graph import analyze


def graph_from_view(view: dict) -> nx.DiGraph:
    """Rebuild the incident DiGraph from the JSON graph payload the UI holds.

    The API is stateless: the client sends back the same graph it was given, so
    the twin operates on exactly the incident on screen.
    """
    g = nx.DiGraph()
    crit = set()
    for n in view.get("nodes", []):
        nid = n["id"] if isinstance(n, dict) else n
        is_crit = bool(isinstance(n, dict) and n.get("critical"))
        g.add_node(nid, critical=is_crit)
        if is_crit:
            crit.add(nid)
    for e in view.get("edges", []):
        src, dst = e.get("from"), e.get("to")
        if not src or not dst:
            continue
        for node in (src, dst):
            if node not in g:
                g.add_node(node, critical=False)
        g.add_edge(src, dst,
                   technique=e.get("technique"), tactic=e.get("tactic"),
                   score=e.get("score", 0), users=e.get("users", []),
                   event_count=e.get("event_count", 1))
    # crown jewels named by the analysis but absent from the drawn subgraph still count
    for asset in view.get("critical_assets_at_risk", []):
        if asset in g:
            g.nodes[asset]["critical"] = True
            crit.add(asset)
    return g


def _exposure(g: nx.DiGraph, critical: set[str], *, choke_points: bool = True) -> dict:
    """Reachability + crown-jewel exposure. `choke_points=False` skips betweenness
    centrality, which is the expensive part and is not needed when we are ranking
    hundreds of candidates by reachability alone."""
    a = analyze(g, critical_assets=critical or None, choke_points=choke_points)
    return {
        "blast_radius": a["blast_radius_size"],
        "crown_jewels_reachable": sorted(a["critical_assets_at_risk"]),
        "paths_to_critical": {k: v for k, v in a["paths_to_critical"].items()},
        "attacker_pivots": a["attacker_pivots"],
        "choke_points": a["choke_points"],
        "n_nodes": a["n_nodes"], "n_edges": a["n_edges"],
    }


def _operational_cost(g: nx.DiGraph, isolate_host: str | None,
                      cut_edge: tuple[str, str] | None) -> dict:
    """What the containment costs the business, in the same units as the benefit."""
    if isolate_host and isolate_host in g:
        users = sorted({u for _, _, d in g.in_edges(isolate_host, data=True)
                        for u in (d.get("users") or [])}
                       | {u for _, _, d in g.out_edges(isolate_host, data=True)
                          for u in (d.get("users") or [])})
        neighbours = sorted(set(g.predecessors(isolate_host)) | set(g.successors(isolate_host)))
        return {
            "action": f"isolate host {isolate_host}",
            "hosts_taken_offline": 1,
            "sessions_severed": g.in_degree(isolate_host) + g.out_degree(isolate_host),
            "accounts_disrupted": users,
            "adjacent_hosts_losing_a_link": neighbours,
            "host_is_crown_jewel": bool(g.nodes.get(isolate_host, {}).get("critical")),
        }
    if cut_edge and g.has_edge(*cut_edge):
        d = g.edges[cut_edge]
        return {
            "action": f"block {cut_edge[0]} -> {cut_edge[1]}",
            "hosts_taken_offline": 0,
            "sessions_severed": d.get("event_count", 1),
            "accounts_disrupted": sorted(d.get("users") or []),
            "adjacent_hosts_losing_a_link": [cut_edge[1]],
            "host_is_crown_jewel": bool(g.nodes.get(cut_edge[1], {}).get("critical")),
        }
    return {"action": "no-op", "hosts_taken_offline": 0, "sessions_severed": 0,
            "accounts_disrupted": [], "adjacent_hosts_losing_a_link": [],
            "host_is_crown_jewel": False}


def simulate(view: dict, *, isolate_host: str | None = None,
             cut_edge: list | tuple | None = None) -> dict:
    """Apply one candidate containment to a clone and diff the exposure."""
    g = graph_from_view(view)
    critical = {n for n, d in g.nodes(data=True) if d.get("critical")}
    edge = tuple(cut_edge) if cut_edge and len(cut_edge) == 2 else None

    if isolate_host and isolate_host not in g:
        raise ValueError(f"host '{isolate_host}' is not in this incident's graph")
    if edge and not g.has_edge(*edge):
        raise ValueError(f"edge {edge[0]} -> {edge[1]} is not in this incident's graph")
    if not isolate_host and not edge:
        raise ValueError("provide isolate_host or cut_edge")

    before = _exposure(g, critical)
    cost = _operational_cost(g, isolate_host, edge)

    after_g = g.copy()                      # the original incident graph is never touched
    if isolate_host:
        after_g.remove_node(isolate_host)
    if edge:
        after_g.remove_edge(*edge)
    after = _exposure(after_g, critical - ({isolate_host} if isolate_host else set()))

    saved = sorted(set(before["crown_jewels_reachable"]) - set(after["crown_jewels_reachable"]))
    still = after["crown_jewels_reachable"]
    br_before, br_after = before["blast_radius"], after["blast_radius"]
    return {
        "candidate": {"isolate_host": isolate_host,
                      "cut_edge": list(edge) if edge else None},
        "before": before,
        "after": after,
        "delta": {
            "blast_radius": br_after - br_before,
            "blast_radius_reduction_pct": (round(100.0 * (br_before - br_after) / br_before, 1)
                                           if br_before else 0.0),
            "crown_jewels_protected": saved,
            "crown_jewels_still_reachable": still,
            "hosts_no_longer_reachable": br_before - br_after,
        },
        "operational_cost": cost,
        "verdict": _verdict(br_before, br_after, saved, still, cost),
        "method": ("deterministic NetworkX reachability on a cloned graph; "
                   "no model, no randomness — identical input gives identical output"),
        "simulated": True,
        "note": "SIMULATION ONLY. No external system is contacted or changed.",
    }


def _verdict(br_before: int, br_after: int, saved: list, still: list, cost: dict) -> str:
    cut = br_before - br_after
    if saved and not still:
        return (f"Cuts the attacker off from every crown jewel ({', '.join(saved)}) and "
                f"{cut} hosts, at the cost of {cost['sessions_severed']} sessions "
                f"across {len(cost['accounts_disrupted'])} accounts.")
    if saved:
        return (f"Protects {', '.join(saved)} and removes {cut} hosts from reach, but "
                f"{', '.join(still)} stays reachable — a second action is needed.")
    if cut > 0:
        return (f"Removes {cut} hosts from the attacker's reach but protects no crown "
                f"jewel on its own.")
    return "Changes nothing measurable in this graph — do not take the outage."


def rank_candidates(view: dict, limit: int = 5) -> list[dict]:
    """Score every host in the graph as a containment candidate, best first.

    Ordering is by crown jewels protected, then blast-radius reduction, then
    LOWEST operational cost — so we never recommend a bigger outage for the same
    security benefit.
    """
    g = graph_from_view(view)
    out = []
    critical = {n for n, d in g.nodes(data=True) if d.get("critical")}
    before = _exposure(g, critical, choke_points=False)
    for host in sorted(n for n in g.nodes if g.out_degree(n) > 0):
        after_g = g.copy()
        after_g.remove_node(host)
        after = _exposure(after_g, critical - {host}, choke_points=False)
        cost = _operational_cost(g, host, None)
        saved = sorted(set(before["crown_jewels_reachable"]) - set(after["crown_jewels_reachable"]))
        cut = before["blast_radius"] - after["blast_radius"]
        out.append({
            "host": host,
            "crown_jewels_protected": saved,
            "blast_radius_reduction": cut,
            "blast_radius_reduction_pct": (round(100.0 * cut / before["blast_radius"], 1)
                                           if before["blast_radius"] else 0.0),
            "sessions_severed": cost["sessions_severed"],
            "accounts_disrupted": len(cost["accounts_disrupted"]),
            "is_crown_jewel": cost["host_is_crown_jewel"],
            "verdict": _verdict(before["blast_radius"], after["blast_radius"],
                                saved, after["crown_jewels_reachable"], cost),
        })
    out.sort(key=lambda c: (-len(c["crown_jewels_protected"]),
                            -c["blast_radius_reduction"], c["sessions_severed"], c["host"]))
    return out[:limit]


def demo() -> None:
    """Self-check: isolating the pivot protects the crown jewel; the original stands."""
    view = {
        "nodes": [{"id": "PC", "critical": False}, {"id": "JUMP", "critical": False},
                  {"id": "DB", "critical": True}, {"id": "SPARE", "critical": False}],
        "edges": [{"from": "PC", "to": "JUMP", "users": ["a@x"], "event_count": 3},
                  {"from": "JUMP", "to": "DB", "users": ["a@x"], "event_count": 2},
                  {"from": "JUMP", "to": "SPARE", "users": ["b@x"], "event_count": 1}],
        "critical_assets_at_risk": ["DB"],
    }
    s = simulate(view, isolate_host="JUMP")
    assert s["before"]["crown_jewels_reachable"] == ["DB"], s["before"]
    assert s["after"]["crown_jewels_reachable"] == [], s["after"]
    assert s["delta"]["crown_jewels_protected"] == ["DB"]
    assert s["operational_cost"]["sessions_severed"] == 3, s["operational_cost"]
    assert len(view["edges"]) == 3, "input graph was mutated"

    noop = simulate(view, isolate_host="SPARE")
    assert noop["delta"]["crown_jewels_protected"] == []
    best = rank_candidates(view)[0]
    assert best["host"] == "JUMP", best
    print(f"twin ok: isolating JUMP protects {s['delta']['crown_jewels_protected']}, "
          f"blast {s['before']['blast_radius']} -> {s['after']['blast_radius']}, "
          f"cost {s['operational_cost']['sessions_severed']} sessions; "
          f"best candidate {best['host']}")


if __name__ == "__main__":
    demo()
