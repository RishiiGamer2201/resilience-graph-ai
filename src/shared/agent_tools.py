"""The fixed tool surface an agent may use. Nothing else is reachable.

An agent here cannot run a query, call a URL, or touch a file. It picks one of
these named tools with typed arguments, and each one is a thin wrapper over a
deterministic function that already exists and is already tested. That is the
whole containment strategy: the model chooses WHICH question to ask, and
deterministic Python answers it.

Every row that comes back carries an `evidence_id`. An agent's claim is only
accepted if it cites ids that appear in what it was actually given, which is
checked in `agent_loop.py` rather than requested in a prompt. A model cannot be
trusted to police its own citations, so it is not asked to.

Most of these read the attack graph, because the graph is where the answers live:
who reached what, from where, and what a containment would sever. Two of them
(`twin_isolate`, `attack_paths`) are the questions a responder actually asks
mid-incident and the reason this layer exists at all.
"""
from __future__ import annotations

from typing import Any, Callable

from src.shared import twin


def _ev(kind: str, i: int) -> str:
    return f"{kind}-{i:03d}"


# --------------------------------------------------------------------------- #
# the tools                                                                    #
# --------------------------------------------------------------------------- #
def list_alerts(bundle: dict, *, limit: int = 25) -> dict:
    """The alerts in this incident, newest first, with their techniques."""
    steps = [s for s in bundle["incident"].get("steps", []) if s.get("is_alert")]
    rows = []
    for i, s in enumerate(steps[:limit]):
        rows.append({
            "evidence_id": _ev("alert", i),
            "user": s.get("user"), "from": s.get("source_host"),
            "to": s.get("destination_host"),
            "technique": s.get("technique_id"), "tactic": s.get("tactic"),
            "score": s.get("anomaly_score"),
        })
    return {"rows": rows, "total_alerts": len(steps), "shown": len(rows)}


def graph_summary(bundle: dict) -> dict:
    """Shape of the attack path: pivots, blast radius, choke points."""
    g = bundle.get("graph", {}) or {}
    return {"rows": [{
        "evidence_id": "graph-000",
        "attacker_pivots": g.get("attacker_pivots", [])[:10],
        "hosts_in_graph": g.get("n_nodes"), "movements": g.get("n_edges"),
        "blast_radius": g.get("blast_radius_size"),
        "recommended_isolation": g.get("recommended_isolation"),
        "isolation_cuts": g.get("isolation_cuts"),
    }]}


def attack_paths(bundle: dict) -> dict:
    """Actual paths from an attacker pivot to a designated crown jewel."""
    paths = (bundle.get("graph", {}) or {}).get("paths_to_critical") or {}
    rows = [{"evidence_id": _ev("path", i), "crown_jewel": asset,
             "hops": max(0, len(p) - 1), "route": " -> ".join(p)}
            for i, (asset, p) in enumerate(sorted(paths.items()))]
    return {"rows": rows, "crown_jewels_reachable": len(rows)}


def technique_claims(bundle: dict) -> dict:
    """What is CLAIMED about each technique, and how well established it is.

    The status field is the point. `observed` was seen in the log; `inferred`
    means a rule fired on indirect evidence. An agent that treats those as the
    same thing is making the mistake this product exists to prevent.
    """
    claims = bundle.get("claims") or bundle.get("assessment", {}).get("claims") or []
    rows = [{"evidence_id": _ev("claim", i), "technique": c.get("external_id"),
             "status": c.get("status"), "confidence": c.get("confidence"),
             "actionable": c.get("actionable"),
             "missing_evidence": (c.get("missing_evidence") or [])[:3]}
            for i, c in enumerate(claims)]
    return {"rows": rows}


def calibration(bundle: dict) -> dict:
    """Which scale the scores are on, and whether they transfer to another log."""
    cal = (bundle.get("meta") or {}).get("calibration") or {}
    return {"rows": [{
        "evidence_id": "calib-000",
        "basis": cal.get("basis"),
        "out_of_distribution": cal.get("out_of_distribution"),
        "sample_confidence": cal.get("sample_confidence"),
        "unscored_events": cal.get("unscored_events"),
        "caveat": cal.get("note") or "none",
    }]}


def twin_isolate(bundle: dict, *, host: str) -> dict:
    """Counterfactual: isolate this host, recompute the graph, report BOTH sides.

    Returns the cost as well as the benefit, because a containment that severs
    hundreds of hosts is a decision rather than a free win, and an agent asked
    only for benefit will recommend unplugging the domain controller.
    """
    view = bundle.get("graph") or {}
    try:
        sim = twin.simulate(view, isolate_host=host)
    except Exception as e:                       # a bad host name is not a crash
        return {"rows": [], "error": f"{type(e).__name__}: {e}"}
    return {"rows": [{
        "evidence_id": f"twin-{host}",
        "host": host,
        "blast_radius_before": sim.get("before", {}).get("blast_radius"),
        "blast_radius_after": sim.get("after", {}).get("blast_radius"),
        "crown_jewels_saved": sim.get("crown_jewels_saved"),
        "crown_jewels_still_reachable": sim.get("crown_jewels_still_reachable"),
        "operational_cost": sim.get("operational_cost"),
        "verdict": sim.get("verdict"),
    }]}


def containment_candidates(bundle: dict, *, limit: int = 5) -> dict:
    """Hosts worth considering for isolation, ranked, with what each would cost."""
    try:
        cands = twin.rank_candidates(bundle.get("graph") or {}, limit=limit)
    except Exception as e:
        return {"rows": [], "error": f"{type(e).__name__}: {e}"}
    return {"rows": [{"evidence_id": _ev("cand", i), **c} for i, c in enumerate(cands)]}


# name -> (callable, human description shown to the model)
TOOLS: dict[str, tuple[Callable[..., dict], str]] = {
    "list_alerts": (list_alerts, "the alerts in this incident with technique, hosts and score"),
    "graph_summary": (graph_summary, "attacker pivots, blast radius, choke point"),
    "attack_paths": (attack_paths, "routes from a pivot to a designated crown jewel"),
    "technique_claims": (technique_claims, "each ATT&CK claim with its status: observed vs inferred"),
    "calibration": (calibration, "which scale the scores are on and whether they transfer"),
    "twin_isolate": (twin_isolate, "counterfactual: isolate {host}, returns benefit AND cost"),
    "containment_candidates": (containment_candidates, "ranked isolation options with cost"),
}


def describe() -> str:
    """The tool list, as the model sees it."""
    return "\n".join(f"- {name}: {desc}" for name, (_, desc) in TOOLS.items())


def accepts(name: str) -> set[str]:
    """Which keyword arguments this tool actually takes.

    Read off the signature rather than listed, because a list drifts. The caller
    needs it because the model is answering a strict schema that requires every
    argument key to be present, so it sends `host` and `limit` to all seven
    tools. Passing those through unfiltered made five of the seven return
    "bad arguments for ...", the agent correctly concluded it had no evidence,
    and the whole lane fell back to the template while looking like a model
    failure. It was a plumbing failure.
    """
    fn, _ = TOOLS.get(name, (None, ""))
    if fn is None:
        return set()
    import inspect
    return {p.name for p in inspect.signature(fn).parameters.values()
            if p.kind is inspect.Parameter.KEYWORD_ONLY}


def call(name: str, bundle: dict, **kwargs: Any) -> dict:
    """Run one tool. Unknown names are refused rather than guessed at."""
    if name not in TOOLS:
        return {"rows": [], "error": f"no such tool '{name}'. Available: "
                                     f"{', '.join(sorted(TOOLS))}"}
    fn, _ = TOOLS[name]
    try:
        return fn(bundle, **kwargs)
    except TypeError as e:                       # wrong or missing argument
        return {"rows": [], "error": f"bad arguments for {name}: {e}"}


def evidence_ids(results: list[dict]) -> set[str]:
    """Every id the agent was actually shown. Citations are checked against this."""
    out: set[str] = set()
    for r in results:
        for row in r.get("rows", []):
            if row.get("evidence_id"):
                out.add(row["evidence_id"])
    return out


def demo() -> None:
    """Self-check: tools are pure, refuse unknown names, and always tag evidence."""
    bundle = {
        "incident": {"steps": [
            {"is_alert": True, "user": "u@d", "source_host": "A",
             "destination_host": "B", "technique_id": "T1021",
             "tactic": "Lateral Movement", "anomaly_score": 88}]},
        "graph": {"attacker_pivots": ["A"], "n_nodes": 2, "n_edges": 1,
                  "blast_radius_size": 1, "recommended_isolation": "A",
                  "isolation_cuts": 1, "paths_to_critical": {"DC": ["A", "B", "DC"]}},
        "meta": {"calibration": {"basis": "fixed-anchors-lanl",
                                 "out_of_distribution": False}},
    }
    alerts = call("list_alerts", bundle)
    assert alerts["rows"][0]["evidence_id"] == "alert-000"
    assert alerts["total_alerts"] == 1

    paths = call("attack_paths", bundle)
    assert paths["rows"][0]["hops"] == 2, paths

    bad = call("no_such_tool", bundle)
    assert bad["rows"] == [] and "no such tool" in bad["error"]

    ids = evidence_ids([alerts, paths, call("graph_summary", bundle)])
    assert "alert-000" in ids and "graph-000" in ids and "path-000" in ids

    # a bad argument must be an error the agent can read, not a traceback
    assert "bad arguments" in call("twin_isolate", bundle, nope=1)["error"]

    # the model sends every schema key to every tool; only the accepted ones
    # may reach the function, or five of seven tools answer with an error
    assert accepts("twin_isolate") == {"host"}, accepts("twin_isolate")
    assert accepts("list_alerts") == {"limit"}
    assert accepts("graph_summary") == set()
    assert accepts("no_such_tool") == set()
    print(f"agent tools ok: {len(TOOLS)} tools, {len(ids)} evidence ids, "
          "unknown names and bad arguments refused")


if __name__ == "__main__":
    demo()
