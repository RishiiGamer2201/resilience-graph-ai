"""The bounded investigation workflow: Understand → Plan → Evidence → Signals →
Replan → Impact → Action.

This is a state graph, not an agent loop. Seven nodes run in a fixed order with
exactly one permitted replan, every node is timed, and every node returns a typed
result. A node that fails degrades to `status: "degraded"` and the investigation
continues — losing the evidence retriever must not erase the detection.

Why hand-rolled instead of LangGraph: the graph is seven nodes with one bounded
retry, and every node is a call into a domain function that already exists and is
already tested. Wrapping that in an orchestration framework would add a
dependency, deploy weight and a cold start to the demo without changing what
runs. The trade-off is written up in `docs/architecture/adr/0002-hand-rolled-workflow.md`
along with the evidence that would justify revisiting it.

Hard rules, enforced here rather than promised in a pitch:
  * every number the workflow emits is deterministic Python over typed inputs;
  * the LLM (when one is configured at all) may only reword an explanation and is
    labelled non-authoritative — it never scores, ranks, gates or approves;
  * retrieved document text is evidence, never instruction;
  * no action touches an external system. Ever.

    from src.shared.workflow import investigate
    result = investigate(scenario="aiims_ransomware")
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd

from src.shared.timeutil import fmt_ist

ROOT = Path(__file__).resolve().parents[2]
SCENARIOS = ROOT / "data" / "demo" / "scenarios"

MAX_REPLANS = 1          # bounded by construction: there is no loop to run away

NODES = ("understand", "plan", "evidence", "signals", "replan", "impact", "action")

# Headline metric weights. Documented here, echoed in the API payload, and shown
# in the UI behind the number — a judge can check the arithmetic on screen.
PROGRESSION_WEIGHTS = {
    "tactic_coverage": 0.30,      # distinct ATT&CK tactics seen / stages in an intrusion
    "detector_confidence": 0.30,  # calibrated max anomaly score (0-100 -> 0-1)
    "evidence_corroboration": 0.25,  # observed techniques with an official citation
    "path_depth": 0.15,           # longest attacker path / a 5-hop reference chain
}
PROGRESSION_STAGES = 6           # Initial Access, Credential Access, Discovery,
                                 # Lateral Movement, Collection, Exfiltration
PATH_DEPTH_REFERENCE = 5         # hops in a textbook end-to-end intrusion
EXPOSURE_HOP_DECAY = 0.9         # each extra hop to a crown jewel discounts exposure


@dataclass
class NodeResult:
    node: str
    status: str = "ok"           # ok | degraded | skipped | failed
    ms: float = 0.0
    summary: str = ""
    output: dict = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"node": self.node, "status": self.status, "ms": round(self.ms, 1),
                "summary": self.summary, "notes": self.notes, "output": self.output}


class Trace:
    """Ordered node results + wall-clock timing for the whole investigation."""

    def __init__(self):
        self.results: list[NodeResult] = []
        self.t0 = time.perf_counter()

    def run(self, node: str, fn, *, required: bool = False) -> NodeResult:
        t = time.perf_counter()
        try:
            res = fn()
        except Exception as e:                      # typed degradation, not a 500
            res = NodeResult(node, "failed" if required else "degraded",
                             summary=f"{type(e).__name__}: {e}"[:220],
                             notes=[("this node is required — the investigation is "
                                     "incomplete") if required else
                                    "the rest of the investigation continued without it"])
        res.ms = (time.perf_counter() - t) * 1000
        self.results.append(res)
        return res

    def get(self, node: str) -> NodeResult | None:
        for r in reversed(self.results):
            if r.node == node:
                return r
        return None

    def as_dict(self) -> dict:
        return {
            "nodes": [r.as_dict() for r in self.results],
            "total_ms": round((time.perf_counter() - self.t0) * 1000, 1),
            "bounded_by": f"fixed 7-node graph, at most {MAX_REPLANS} replan",
            "degraded": [r.node for r in self.results if r.status in ("degraded", "failed")],
        }


# --------------------------------------------------------------------------- #
# headline metrics — deterministic, explainable, checkable on screen           #
# --------------------------------------------------------------------------- #
def crown_jewel_exposure(graph: dict, designated: list[str]) -> dict:
    """0-100: how exposed the designated crown jewels are, right now.

    Per jewel: 100 if the attacker stands on it or is one hop away, decayed by
    0.9 for each additional hop, 0 if no path exists. The score is the mean over
    every DESIGNATED jewel — so protecting one of three genuinely moves it.
    """
    designated = sorted(set(designated or []))
    if not designated:
        return {"value": None, "unit": "0-100", "state": "not measured",
                "reason": "no crown-jewel assets were designated for this analysis",
                "terms": [], "formula": "mean over designated crown jewels"}
    paths = graph.get("paths_to_critical") or {}
    terms = []
    total = 0.0
    for jewel in designated:
        path = paths.get(jewel)
        if not path:
            terms.append({"asset": jewel, "hops": None, "score": 0.0,
                          "why": "no path from any attacker pivot"})
            continue
        hops = max(1, len(path) - 1)
        score = 100.0 * (EXPOSURE_HOP_DECAY ** (hops - 1))
        total += score
        terms.append({"asset": jewel, "hops": hops, "score": round(score, 1),
                      "why": " → ".join(path)})
    return {
        "value": round(total / len(designated), 1),
        "unit": "0-100",
        "state": "measured",
        "terms": terms,
        "formula": (f"mean over designated crown jewels of "
                    f"100 × {EXPOSURE_HOP_DECAY}^(hops−1), 0 when unreachable"),
        "designated": designated,
    }


def progression_confidence(incident: dict, graph: dict, cited_techniques: int) -> dict:
    """0-100: how strongly the evidence says a real intrusion is progressing."""
    tactics = sorted({t for t in incident.get("attack_chain", []) if t and t != "Normal"})
    tech = incident.get("technique_ids", [])
    paths = graph.get("paths_to_critical") or {}
    longest = max((len(p) - 1 for p in paths.values()), default=0)

    terms = {
        "tactic_coverage": {
            "value": round(min(1.0, len(tactics) / PROGRESSION_STAGES), 4),
            "detail": f"{len(tactics)} distinct ATT&CK tactics of {PROGRESSION_STAGES} "
                      f"intrusion stages: {', '.join(tactics) or 'none'}",
        },
        "detector_confidence": {
            "value": round(min(100, incident.get("max_anomaly_score", 0)) / 100, 4),
            "detail": f"peak calibrated anomaly score {incident.get('max_anomaly_score', 0)}/100 "
                      f"(50 = the 1% false-positive line)",
        },
        "evidence_corroboration": {
            "value": round((cited_techniques / len(tech)) if tech else 0.0, 4),
            "detail": f"{cited_techniques} of {len(tech)} observed techniques carry an "
                      f"official ATT&CK citation",
        },
        "path_depth": {
            "value": round(min(1.0, longest / PATH_DEPTH_REFERENCE), 4),
            "detail": f"longest attacker path to a crown jewel is {longest} hop(s) "
                      f"(reference chain {PATH_DEPTH_REFERENCE})",
        },
    }
    value = sum(PROGRESSION_WEIGHTS[k] * v["value"] for k, v in terms.items())
    return {
        "value": round(100 * value, 1),
        "unit": "0-100",
        "state": "measured",
        "terms": [{"name": k, "weight": PROGRESSION_WEIGHTS[k], **v} for k, v in terms.items()],
        "formula": " + ".join(f"{w}×{k}" for k, w in PROGRESSION_WEIGHTS.items()),
        "note": ("A confidence in the EVIDENCE, not a probability of attack. Every term "
                 "is measured from this log; none of it is a model opinion."),
    }


# --------------------------------------------------------------------------- #
# node implementations                                                         #
# --------------------------------------------------------------------------- #
def _n_understand(df: pd.DataFrame, scenario: str | None, critical: list[str],
                  incident_id: str) -> NodeResult:
    from src.schema import COLUMNS, coerce, resolve_aliases
    from src.shared.live_analyze import MAX_ROWS

    supplied = list(df.columns)
    resolved = list(resolve_aliases(df.copy()).columns)
    coerced = coerce(df)
    missing = [c for c in COLUMNS if c not in resolved]
    hosts = sorted(set(coerced["destination_host"].dropna().astype(str))
                   | set(coerced["source_host"].dropna().astype(str)))
    users = sorted(set(coerced["user"].dropna().astype(str)) - {""})
    unknown_crit = [c for c in critical if c not in hosts]

    notes = []
    if missing:
        notes.append(f"columns not supplied, defaulted by schema: {', '.join(missing)}")
    if unknown_crit:
        notes.append(f"designated crown jewels absent from this log: {', '.join(unknown_crit)}")
    if not critical:
        notes.append("no crown jewels designated — exposure cannot be measured")
    if len(df) > MAX_ROWS:
        notes.append(f"log exceeds the {MAX_ROWS}-row cap and will be rejected")

    return NodeResult(
        "understand",
        status="degraded" if unknown_crit or not critical else "ok",
        summary=(f"{len(df)} events · {len(users)} accounts · {len(hosts)} hosts · "
                 f"{len(critical)} crown jewel(s) designated"),
        output={
            "incident_id": incident_id,
            "provenance": "SAMPLE" if scenario else "LIVE",
            "source": f"shipped scenario '{scenario}'" if scenario else "uploaded event log",
            "n_events": int(len(df)),
            "columns_supplied": supplied,
            "columns_missing": missing,
            "accounts": users[:20], "accounts_total": len(users),
            "hosts_total": len(hosts),
            "time_range": [int(coerced["timestamp"].min()), int(coerced["timestamp"].max())],
            "crown_jewels_designated": critical,
            "crown_jewels_not_in_log": unknown_crit,
        },
        notes=notes,
    )


def _n_plan(understand: NodeResult, want_evidence: bool, want_vuln: bool) -> NodeResult:
    steps = [
        {"node": "evidence", "tool": "EvidenceRepository.search (bundled BM25 index)",
         "selected": want_evidence,
         "why": "every ATT&CK conclusion needs an official citation"},
        {"node": "signals", "tool": "live_analyze.analyze_events (detector → correlate → "
                                    "ATT&CK map → graph → SOAR → attribute → predict)",
         "selected": True, "why": "the detection spine; always runs"},
        {"node": "replan", "tool": "evidence gap check", "selected": want_evidence,
         "why": f"at most {MAX_REPLANS} bounded retry when evidence is missing or stale"},
        {"node": "impact", "tool": "attack_graph.analyze + twin.simulate + vuln.prioritize",
         "selected": True,
         "why": "reachability, crown-jewel exposure and counterfactual containment"},
        {"node": "action", "tool": "soar.recommend + rbac.policy_for + RFI template",
         "selected": True, "why": "gated, simulated recommendations plus what we still need"},
    ]
    skipped = [s["node"] for s in steps if not s["selected"]]
    return NodeResult(
        "plan", status="ok",
        summary=f"{sum(s['selected'] for s in steps)} of {len(steps)} tools selected"
                + (f"; skipping {', '.join(skipped)}" if skipped else ""),
        output={"steps": steps,
                "vulnerability_prioritisation": want_vuln,
                "bounded": f"fixed order, at most {MAX_REPLANS} replan, no free-running loop"},
        notes=([] if want_vuln else
               ["vulnerability prioritisation is off: no asset inventory for this log"]),
    )


def _n_evidence(query: str, technique_ids: list[str], k: int) -> NodeResult:
    from src.shared import evidence as ev
    repo = ev.repository()
    # Exact technique lookup stays lexical (an analyst asking for T1550.002 wants
    # that page); the free-text half uses whichever backend is live.
    cites = ev.search_for_techniques(technique_ids, k_each=1) if technique_ids else []
    extra = ev.search(query, k=k) if query else []
    seen = {c["chunk_id"] for c in cites}
    cites += [e for e in extra if e["chunk_id"] not in seen][: max(0, k - len(cites))]
    stats = repo.stats()
    return NodeResult(
        "evidence",
        status="ok" if cites else "degraded",
        summary=(f"{len(cites)} citation(s) from {stats['chunks']} official chunks "
                 f"({', '.join(f'{k2}:{v}' for k2, v in sorted(stats['by_publisher'].items()))})"),
        output={"citations": cites,
                "index_built_at": stats.get("built_at"),
                "corpus": stats["by_publisher"],
                "query": query, "technique_ids": technique_ids,
                "backend": ev.active_backend(),
                "retrieval": (
                    "MiniLM + ChromaDB semantic search over the 3,692-chunk corpus, "
                    "with exact-identifier lookup kept lexical"
                    if ev.active_backend() == "semantic" else
                    "BM25 + exact identifier boost, bundled read-only index, no network")},
        notes=([] if cites else ["no official evidence matched — say so, do not improvise"]),
    )


def _n_signals(df: pd.DataFrame, critical: list[str], incident_id: str,
               account: str | None) -> NodeResult:
    from src.shared.live_analyze import analyze_events
    bundle = analyze_events(df, critical_assets=set(critical), incident_id=incident_id,
                            account=account)
    inc, g = bundle["incident"], bundle["graph"]
    return NodeResult(
        "signals", status="ok",
        summary=(f"{inc['alert_count']} alerts from {inc['event_count']} events correlated "
                 f"into 1 incident · {len(inc['technique_ids'])} ATT&CK techniques · "
                 f"severity {inc['severity']}"),
        output={"bundle": bundle},
    )


def _n_replan(evidence: NodeResult, technique_ids: list[str], attempt: int) -> NodeResult:
    """Detect an evidence gap. Permits at most one retry — by construction."""
    cited = {i for c in (evidence.output.get("citations") or []) for i in c["identifiers"]}
    missing = [t for t in technique_ids if t not in cited]
    stale = [c["title"] for c in (evidence.output.get("citations") or [])
             if not c.get("published")]
    retry = bool(missing) and attempt < MAX_REPLANS
    return NodeResult(
        "replan", status="ok",
        summary=("no gap — evidence covers every observed technique" if not missing else
                 f"{len(missing)} technique(s) lack a citation"
                 + (" → retrying evidence once" if retry else " → reported as unevidenced")),
        output={"techniques_without_citation": missing,
                "citations_without_a_document_date": stale,
                "retry": retry, "attempt": attempt, "max_replans": MAX_REPLANS},
        notes=(["evidence retrieved once more, scoped to the observed techniques"] if retry
               else [] if not missing else
               ["these techniques are reported WITHOUT supporting evidence, on purpose"]),
    )


def _n_impact(bundle: dict, critical: list[str], scenario: str | None,
              cited_techniques: int) -> NodeResult:
    from src.shared.twin import rank_candidates, simulate
    from src.shared.vuln import load_inventory, prioritize

    graph_view, inc = bundle["graph"], bundle["incident"]
    exposure = crown_jewel_exposure(graph_view, critical)
    progression = progression_confidence(inc, graph_view, cited_techniques)

    candidates = rank_candidates(graph_view, limit=5)
    best = candidates[0]["host"] if candidates else None
    counterfactual = simulate(graph_view, isolate_host=best) if best else None

    inventory = load_inventory(scenario)
    vulns = (prioritize(inventory, graph_view, inc["technique_ids"], limit=10)
             if inventory.get("assets") else
             {"findings": [], "total_findings": 0,
              "inventory_provenance": inventory.get("provenance", "NOT_PROVIDED"),
              "inventory_note": inventory.get("note", ""),
              "assets_considered": 0, "note": inventory.get("note", "")})

    notes = []
    if not vulns["findings"]:
        notes.append("no vulnerability findings: " + (vulns.get("inventory_note") or
                     "no asset inventory supplied — host software is never guessed"))
    return NodeResult(
        "impact", status="ok",
        summary=(f"crown-jewel exposure {exposure['value'] if exposure['value'] is not None else 'not measured'}"
                 f" · blast radius {graph_view['blast_radius_size']} hosts"
                 + (f" · isolating {best} protects "
                    f"{len(counterfactual['delta']['crown_jewels_protected'])} jewel(s)"
                    if counterfactual else "")),
        output={
            "crown_jewel_exposure": exposure,
            "attack_progression_confidence": progression,
            "blast_radius": graph_view["blast_radius_size"],
            "paths_to_critical": graph_view["paths_to_critical"],
            "containment_candidates": candidates,
            "counterfactual": counterfactual,
            "vulnerabilities": vulns,
        },
        notes=notes,
    )


def _rfi(bundle: dict, critical: list[str], counterfactual: dict | None) -> dict:
    """Deterministic request-for-information: exactly what we still need, and why.

    With no LLM configured this template IS the product. An optional provider may
    only reword it; the required fields are generated here and never dropped.
    """
    inc, g = bundle["incident"], bundle["graph"]
    host = (counterfactual or {}).get("candidate", {}).get("isolate_host") or g["entry_host"]
    jewels = ", ".join(g["critical_assets_at_risk"]) or "none reached yet"
    accounts = ", ".join(inc.get("users_involved", [])[:5]) or "unknown"
    questions = [
        {"field": "asset_owner",
         "ask": f"Who owns {host}, and who can authorise taking it off the network?",
         "why": "the proposed containment isolates this host"},
        {"field": "business_criticality",
         "ask": f"What breaks if {host} is isolated during the next 30 minutes?",
         "why": "we can measure security benefit but not clinical or operational harm"},
        {"field": "maintenance_window",
         "ask": f"Is {host} inside a maintenance or patching window right now?",
         "why": "routine admin activity can look identical to lateral movement"},
        {"field": "identity_context",
         "ask": f"Are the accounts {accounts} expected to authenticate from {g['entry_host']}?",
         "why": "the detector is behavioural — a legitimate role change reproduces this pattern"},
        {"field": "edr_result",
         "ask": f"What does EDR report on {host} and on {jewels} for this window?",
         "why": "auth logs alone cannot confirm code execution or persistence"},
        {"field": "patch_status",
         "ask": f"Are the known-exploited CVEs on {jewels} patched or compensated?",
         "why": "prioritisation assumes the inventory's software versions are current"},
    ]
    return {
        "to": "Asset owner / SOC lead",
        "subject": f"[{inc['incident_id']}] Information needed before containment",
        "context": (f"{inc['severity'].upper()} incident: {inc['alert_count']} correlated "
                    f"alerts, {len(inc['technique_ids'])} ATT&CK techniques, crown jewels "
                    f"reachable: {jewels}."),
        "questions": questions,
        "generated_by": "deterministic template (LLM_PROVIDER=none)",
        "note": "Required fields are generated here; an optional LLM may only reword them.",
    }


def _n_action(bundle: dict, impact: NodeResult, principal: dict | None) -> NodeResult:
    from src.shared.rbac import policy_for

    soar = bundle["soar"]
    cf = impact.output.get("counterfactual")
    exposure = impact.output.get("crown_jewel_exposure", {})
    jewels = set(exposure.get("designated") or [])

    proposals = []
    for a in soar["actions"]:
        kind = ("monitor" if "monitor" in a["action"].lower() else
                "ticket" if "ticket" in a["action"].lower() else
                "isolate" if "isolate" in a["action"].lower() else "contain")
        touches = bool(cf and set(cf["delta"]["crown_jewels_protected"]) & jewels) \
            if kind == "isolate" else False
        blast = cf["delta"]["hosts_no_longer_reachable"] if (cf and kind == "isolate") else 0
        proposal = {
            "id": f"ACT-{len(proposals) + 1:02d}",
            "kind": kind,
            "tactic": a["tactic"],
            "action": a["action"],
            "touches_crown_jewel": touches,
            "blast_radius_affected": blast,
            "hosts_taken_offline": (cf["operational_cost"]["hosts_taken_offline"]
                                    if cf and kind == "isolate" else 0),
            "simulated": True,
        }
        proposal["policy"] = policy_for(proposal)
        proposals.append(proposal)

    gated = sum(1 for p in proposals if p["policy"]["requires_approval"])
    return NodeResult(
        "action", status="ok",
        summary=(f"{len(proposals)} simulated action(s) proposed · {gated} require named "
                 f"human approval · 0 executed"),
        output={
            "proposals": proposals,
            "mitre_mitigations": soar.get("mitre_mitigations", []),
            "gating_policy": soar["gating_policy"],
            "rfi": _rfi(bundle, sorted(jewels), cf),
            "executed": 0,
            "note": ("SIMULATION ONLY. Nothing here contacts an external system. "
                     "Approval is recorded in the tamper-evident audit chain."),
        },
        notes=([] if principal else ["no principal supplied — approval cannot be recorded"]),
    )


# --------------------------------------------------------------------------- #
# orchestration                                                                #
# --------------------------------------------------------------------------- #
def investigate(*, df: pd.DataFrame | None = None, scenario: str | None = None,
                critical_assets: list[str] | None = None,
                incident_id: str = "INC-LIVE-001", account: str | None = None,
                principal: dict | None = None, evidence_k: int = 6) -> dict:
    """Run the seven-node investigation and return the trace plus the result."""
    from src.shared.vuln import load_inventory

    if df is None:
        if not scenario:
            raise ValueError("provide a scenario name or an events frame")
        path = SCENARIOS / f"{scenario}.csv"
        if not path.exists():
            raise ValueError(f"unknown scenario '{scenario}'")
        df = pd.read_csv(path)
    critical = list(critical_assets or [])
    trace = Trace()

    understand = trace.run("understand",
                           lambda: _n_understand(df, scenario, critical, incident_id))

    want_vuln = bool(load_inventory(scenario).get("assets"))
    from src.shared.evidence import available as evidence_available
    want_evidence = evidence_available()
    trace.run("plan", lambda: _n_plan(understand, want_evidence, want_vuln))

    # pass 1: scope-level evidence, before we know the techniques
    seed_query = (f"{scenario or 'uploaded event log'} lateral movement credential access "
                  f"critical infrastructure")
    evidence = (trace.run("evidence", lambda: _n_evidence(seed_query, [], evidence_k))
                if want_evidence else
                trace.run("evidence", lambda: NodeResult(
                    "evidence", "skipped",
                    summary="evidence index not built — run scripts.build_evidence_index",
                    notes=["conclusions will be reported without citations"])))

    signals = trace.run("signals",
                        lambda: _n_signals(df, critical, incident_id, account),
                        required=True)
    if signals.status == "failed":
        return {"ok": False, "trace": trace.as_dict(), "error": signals.summary,
                "generated_at": fmt_ist()}
    bundle = signals.output["bundle"]
    techniques = bundle["incident"]["technique_ids"]

    if want_evidence:
        replan = trace.run("replan", lambda: _n_replan(evidence, techniques, 0))
        if replan.output.get("retry"):
            # the single bounded retry: same tool, now scoped to what we observed
            evidence = trace.run("evidence",
                                 lambda: _n_evidence(seed_query, techniques, evidence_k))
            trace.run("replan", lambda: _n_replan(evidence, techniques, 1))
    else:
        trace.run("replan", lambda: NodeResult(
            "replan", "skipped", summary="nothing to replan without an evidence index"))

    cited = len({i for c in (evidence.output.get("citations") or [])
                 for i in c["identifiers"] if i in set(techniques)})
    impact = trace.run("impact",
                       lambda: _n_impact(bundle, critical, scenario, cited))
    action = trace.run("action", lambda: _n_action(bundle, impact, principal))

    # A degraded node returns output={}. Typed degradation is only useful if the
    # SHAPE survives it too, otherwise every consumer has to guess which keys
    # vanished. Merge each optional node's output over a skeleton so the contract
    # holds whether the node succeeded, degraded or failed.
    evidence_out = {"citations": [], "corpus": {}, "index_built_at": None,
                    "retrieval": "unavailable", "query": "", "technique_ids": [],
                    **evidence.output}
    impact_out = {"crown_jewel_exposure": None, "attack_progression_confidence": None,
                  "blast_radius": None, "paths_to_critical": {},
                  "containment_candidates": [], "counterfactual": None,
                  "vulnerabilities": {"findings": [], "total_findings": 0,
                                      "assets_considered": 0,
                                      "inventory_provenance": "UNKNOWN"},
                  **impact.output}
    action_out = {"proposals": [], "mitre_mitigations": [], "gating_policy": "",
                  "rfi": None, "executed": 0,
                  "note": "SIMULATION ONLY. Nothing contacts an external system.",
                  **action.output}

    return {
        "ok": True,
        "generated_at": fmt_ist(),
        "incident_id": incident_id,
        "scenario": scenario,
        "trace": trace.as_dict(),
        "understand": understand.output,
        "evidence": evidence_out,
        "signals": {k: v for k, v in bundle.items() if k != "meta"},
        "meta": bundle["meta"],
        "impact": impact_out,
        "action": action_out,
        "headline": {
            "attack_progression_confidence": impact_out["attack_progression_confidence"],
            "crown_jewel_exposure": impact_out["crown_jewel_exposure"],
        },
        "llm": {"provider": "none", "used_for": [],
                "note": "No LLM is in this path. Every number above is deterministic Python."},
    }


def demo() -> None:
    """Self-check: the full graph runs on a shipped scenario and stays bounded."""
    r = investigate(scenario="aiims_ransomware",
                    critical_assets=["PATIENT-DB-01", "DC-AIIMS-01"])
    assert r["ok"], r.get("error")
    nodes = [n["node"] for n in r["trace"]["nodes"]]
    assert nodes[0] == "understand" and nodes[-1] == "action", nodes
    assert nodes.count("evidence") <= 1 + MAX_REPLANS, nodes
    hl = r["headline"]
    assert 0 <= hl["crown_jewel_exposure"]["value"] <= 100, hl
    assert 0 <= hl["attack_progression_confidence"]["value"] <= 100, hl
    assert r["action"]["executed"] == 0
    print(f"workflow ok: {len(nodes)} node runs {nodes} in {r['trace']['total_ms']:.0f} ms; "
          f"progression {hl['attack_progression_confidence']['value']} · "
          f"exposure {hl['crown_jewel_exposure']['value']} · "
          f"{len(r['evidence'].get('citations', []))} citations · "
          f"{len(r['action']['proposals'])} gated proposals")


if __name__ == "__main__":
    demo()
