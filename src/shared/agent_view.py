"""Project the 10-agent pipeline's output onto the standard bundle shape.

Lives here, not in `api/main.py`, and that placement is the fix for a real bug.
These three functions used to sit in the API layer while `src/shared/enrich.py`
imported them back out of it -- a library depending on the deployment shim. The
import was circular-adjacent, so it could not be allowed to fail, so it was
wrapped in a bare `except Exception: pass`.

The consequence of that swallow: if the mapping raised, the bundle silently kept
the UNMAPPED graph while `meta.pipeline` still read "standard+10-agent". The UI
rendered the standard graph and labelled it as the agent-integrated one, with no
note and no flag. `src/shared/llm.py` warns about exactly this in its own
docstring -- two silent excepts in this repo hid dead code for weeks.

With the dependency pointing the right way the try/except is unnecessary, and a
failure here is a failure enrich can report instead of hide.
"""
from __future__ import annotations


def _agent_output(agent_summary: dict, agent_name: str) -> dict:
    return _agent_trace(agent_summary, agent_name).get("output", {}) or {}

def _agent_technique_mapping(agent_summary: dict) -> list[dict]:
    from src.shared.attack_mapper import explanation
    from src.shared.views import _names

    names = _names()
    mapped = _agent_output(agent_summary, "intelligence").get("mapped", [])
    seen: set[str] = set()
    out: list[dict] = []
    for item in mapped:
        tid = item.get("technique_id")
        if not tid or tid in seen:
            continue
        seen.add(tid)
        out.append({
            "technique_id": tid,
            "name": item.get("technique_name") or names.get(tid, tid),
            "tactic": item.get("tactic") or "",
            "confidence": item.get("confidence", 0),
            "method": item.get("method", "agent_intelligence"),
            "explanation": explanation(tid),
        })
    return out

def _map_ranked_chains(agent_summary: dict) -> list[dict]:
    chains = agent_summary.get("ranked_chains") or _agent_output(agent_summary, "prioritizer").get("ranked_chains", [])
    out = []
    for i, chain in enumerate(chains, start=1):
        out.append({
            **chain,
            "rank": i,
            "id": f"chain-{i}",
            "title": chain.get("entity", f"Threat chain {i}"),
            "severity": chain.get("risk_band", "low"),
            "score": chain.get("risk_score", 0),
            "techniques": chain.get("technique_ids", []),
            "summary": (
                f"{chain.get('confirmation', 'unconfirmed')} chain on {chain.get('entity', 'unknown')} "
                f"with {len(chain.get('technique_ids', []))} ATT&CK technique(s)"
            ),
        })
    return out


def _agent_trace(agent_summary: dict, agent_name: str) -> dict:
    for trace in agent_summary.get("agent_traces", []):
        if trace.get("agent") == agent_name:
            return trace
    return {}


def _agent_pipeline_summary(result) -> dict:
    data = result.as_dict()
    return {
        "enabled": True,
        "status": data["status"],
        "incident_id": data["incident_id"],
        "scenario": data["scenario"],
        "severity": data["severity"],
        "total_ms": data["total_ms"],
        "point_b_method": data["point_b_method"],
        "incident_narrative": data["incident_narrative"],
        "agent_traces": data["agent_traces"],
        "ranked_chains": data["ranked_chains"],
        "chain_explanations": data["chain_explanations"],
        "predictions": data["predictions"],
        "evidence_refs": data["evidence_refs"],
        "notes": data["notes"],
    }


def _map_agent_graph(agent_summary: dict, base_graph: dict) -> dict | None:
    """Map the KB Connector's entity graph as advisory data.

    This graph is not the attack-path topology used by the twin. It may contain
    users or external IPs, so it must never replace the host graph's nodes/edges.
    """
    kb_graph = _agent_output(agent_summary, "kb_connector").get("graph_view", {})
    observer_nodes = _agent_output(agent_summary, "graph_observer").get("nodes", [])
    raw_nodes = kb_graph.get("nodes") or observer_nodes
    raw_edges = kb_graph.get("edges") or []

    if not raw_nodes:
        return None

    # The KB connector emits an ENTITY graph (users, external IPs). The attack
    # graph is a HOST topology, and the digital twin simulates containment on it.
    # Swapping one for the other left the bundle claiming a 28-host blast radius
    # over a 2-node graph, and made the twin recommend isolating a user account.
    # Keep both, clearly separated.
    authoritative_nodes = base_graph.get("nodes")
    authoritative_edges = base_graph.get("edges")

    entry_host = (
        base_graph.get("entry_host")
        or next((c.get("entity") for c in agent_summary.get("ranked_chains", []) if c.get("entity")), None)
        or raw_nodes[0].get("id")
    )
    critical_assets = set(base_graph.get("critical_assets_at_risk", []))
    nodes = []
    for node in raw_nodes:
        node_id = node.get("id")
        node_type = node.get("type", "host")
        nodes.append({
            "id": node_id,
            "type": node_type,
            "label": node.get("label", node_id),
            "critical": bool(node.get("critical") or node_type == "critical_asset" or node_id in critical_assets),
            "pivot": node_id == entry_host or node_type in {"user", "external_ip"},
            "entry": node_id == entry_host,
            "meta": node.get("meta", {}),
        })

    links = []
    for edge in raw_edges:
        src = edge.get("from")
        dst = edge.get("to")
        if not src or not dst:
            continue
        links.append({
            "source": src,
            "target": dst,
            "from": src,
            "to": dst,
            "relation": edge.get("relation", "related"),
            "technique": edge.get("technique") or "-",
            "tactic": edge.get("tactic", ""),
            "score": edge.get("score", 0),
            "event_count": edge.get("event_count", 1),
            "users": edge.get("users", []),
            "first_seen": edge.get("timestamp", edge.get("first_seen", 0)),
            "last_seen": edge.get("timestamp", edge.get("last_seen", 0)),
        })

    # The KB connector emits an ENTITY graph (users, hosts, external IPs). The
    # attack graph is a HOST topology, and the digital twin simulates containment
    # on it. Swapping one for the other left the bundle reporting a 28-host blast
    # radius over a 2-node graph, and made the twin recommend isolating
    # `reception.rao@AIIMS` -- a user account -- with a claimed 100% reduction.
    # Both views are kept, clearly separated, authoritative one untouched.
    agent_view = {
        "nodes": nodes,
        # the React force graph reads `edges`; 3D consumers usually read `links`
        "edges": links,
        "links": links,
        "n_nodes": len(nodes),
        "n_edges": len(links),
        "entry_host": entry_host,
        "note": ("Entity view from the KB-connector agent. Advisory: the attack-path "
                 "topology in nodes/edges is authoritative and is what containment "
                 "is simulated on."),
    }
    graph = {**base_graph, "agent_graph": agent_view}
    if not graph.get("nodes"):
        # no authoritative topology at all (an empty incident): the agent view is
        # better than nothing, and is labelled as the source.
        graph.update({"nodes": nodes, "edges": links, "links": links,
                      "n_nodes": len(nodes), "n_edges": len(links),
                      "entry_host": entry_host, "topology_source": "agent"})
    else:
        graph.setdefault("topology_source", "attack-path analysis")
    if not graph.get("attacker_pivots"):
        graph["attacker_pivots"] = [n["id"] for n in nodes if n["pivot"]][:5]
    graph["n_pivots"] = len(graph.get("attacker_pivots", []))
    return graph


def _map_agent_bundle(bundle: dict, agent_summary: dict) -> dict:
    """Map 10-agent output into the standard dashboard bundle shape."""
    narrative = agent_summary.get("incident_narrative", "")
    ranked_chains = _map_ranked_chains(agent_summary)
    technique_mapping = _agent_technique_mapping(agent_summary)

    # ADR 0007: the workflow is authoritative, the agent lane is advisory. Every
    # field below is ADDITIVE. The deterministic summary, report, host topology
    # and ATT&CK mapping stay exactly as computed.
    if narrative:
        bundle.setdefault("overview", {})["agent_narrative"] = narrative
        bundle.setdefault("report", {})["agent_narrative"] = narrative

    if ranked_chains:
        bundle.setdefault("incident", {})["agent_ranked_chains"] = ranked_chains
        bundle.setdefault("overview", {})["agent_ranked_chains"] = ranked_chains[:5]
        bundle.setdefault("report", {})["agent_ranked_chains"] = ranked_chains

    # The agent view is attached ALONGSIDE the authoritative topology, never in
    # place of it. `_map_agent_graph` keeps the real nodes/edges and adds its own
    # under `agent_graph`; the attack-path analysis and the digital twin continue
    # to read the host topology they were computed from.
    bundle["graph"] = _map_agent_graph(agent_summary, bundle.get("graph", {}))

    if technique_mapping:
        ti = bundle.setdefault("threat_intel", {})
        ti["agent_mapping"] = technique_mapping
        ti["agent_validated_technique_ids"] = [m["technique_id"] for m in technique_mapping]
        ti["agent_note"] = (
            "A second opinion: these ATT&CK techniques are emitted by the Intelligence "
            "agent and validated by the orchestrator's schema/evidence gates. The "
            "authoritative mapping above is unchanged."
        )

    predictions = agent_summary.get("predictions") or []
    if predictions:
        # already agent-prefixed and additive
        bundle.setdefault("report", {})["agent_predicted_next"] = predictions

    return bundle
