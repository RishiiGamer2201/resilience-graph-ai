"""Cross-check: does a second, differently-built analysis agree?

Two pipelines now read the same event log:

  the workflow   src/shared/workflow.py — seven bounded nodes, severity from the
                 peak calibrated anomaly score, claims from behavioural rules.
  the agent lane src/agents/ — ten agents over behavioural chunks, severity from
                 a prioritiser's risk band over ranked attack chains.

They disagree sometimes, and the honest response is neither to hide that nor to
average it away. **The workflow stays authoritative.** The agent lane is a
cross-check: when it agrees, that is corroboration from a differently-constructed
analysis and evidence confidence rises; when it contradicts, confidence falls and
the disagreement is shown.

How independent are they really? Partially. They read the same log and share
`src.shared.attack_mapper`, so they are not two separate sensors and this module
says so in every result it returns. The corroboration they can contribute is
capped accordingly — a second opinion derived from the same evidence is worth
something, but it is not worth a second sensor.

    from src.shared.crosscheck import crosscheck
    cc = crosscheck(workflow_result, agent_result)
    cc["verdict"]      # "corroborates" | "partially corroborates" | "contradicts"
"""
from __future__ import annotations

SEVERITY_ORDER = ["low", "medium", "high", "critical"]

# A second opinion built from the same log and the same rule table is not an
# independent sensor. This caps what agreement between them can be worth.
MAX_CORROBORATION = 0.45
SHARED_COMPONENTS = ["the same event log", "src.shared.attack_mapper rule table"]


def _rank(sev: str) -> int:
    try:
        return SEVERITY_ORDER.index(str(sev or "").lower())
    except ValueError:
        return -1


def _severity_agreement(a: str, b: str) -> tuple[str, int]:
    """exact / adjacent / conflicting, plus the distance in severity steps."""
    ra, rb = _rank(a), _rank(b)
    if ra < 0 or rb < 0:
        return "unknown", -1
    d = abs(ra - rb)
    return ("exact" if d == 0 else "adjacent" if d == 1 else "conflicting"), d


def crosscheck(workflow_result: dict, agent_result: dict | None) -> dict:
    """Compare the authoritative analysis with the agent lane's second opinion."""
    if not agent_result or not agent_result.get("status"):
        return {
            "available": False,
            "reason": "the agent lane did not produce a result for this log",
            "verdict": "not available",
            "authoritative": "workflow",
        }

    inc = workflow_result.get("signals", {}).get("incident", {})
    wf_sev = inc.get("severity", "")
    ag_sev = agent_result.get("severity", "")
    agreement, distance = _severity_agreement(wf_sev, ag_sev)

    wf_tech = [t for t in inc.get("technique_ids", []) if t and t != "-"]
    ag_tech = [t for t in agent_result.get("evidence_refs", []) if t.startswith("T")]
    shared = sorted(set(wf_tech) & set(ag_tech))
    union = set(wf_tech) | set(ag_tech)
    overlap = round(len(shared) / len(union), 4) if union else 0.0

    # Verdict. Severity carries more weight than technique overlap, because the
    # two lanes deliberately map techniques at different granularities.
    if agreement == "exact" and shared:
        verdict, strength = "corroborates", MAX_CORROBORATION
    elif agreement in ("exact", "adjacent") and shared:
        verdict, strength = "partially corroborates", MAX_CORROBORATION * 0.6
    elif agreement == "conflicting":
        verdict, strength = "contradicts", 0.0
    elif shared:
        verdict, strength = "partially corroborates", MAX_CORROBORATION * 0.4
    else:
        verdict, strength = "inconclusive", 0.0

    degraded = [a["agent"] for a in agent_result.get("agent_traces", [])
                if a.get("status") != "ok"]
    if degraded:
        strength *= 0.5          # a degraded second opinion corroborates less

    return {
        "available": True,
        "authoritative": "workflow",
        "verdict": verdict,
        "corroboration_strength": round(strength, 4),
        "independence_group": "agent-lane",
        "severity": {
            "workflow": wf_sev, "agent_lane": ag_sev,
            "agreement": agreement, "distance": distance,
            "basis_workflow": "peak calibrated anomaly score across correlated alerts",
            "basis_agent_lane": "prioritiser risk band over ranked attack chains",
        },
        "techniques": {
            "workflow": wf_tech, "agent_lane": ag_tech,
            "shared": shared,
            "workflow_only": sorted(set(wf_tech) - set(ag_tech)),
            "agent_lane_only": sorted(set(ag_tech) - set(wf_tech)),
            "overlap": overlap,
        },
        "agent_lane_degraded": degraded,
        "narrative": agent_result.get("incident_narrative", ""),
        "narrative_method": agent_result.get("point_b_method", "template"),
        "narrative_authoritative": False,
        "partial_independence": {
            "shared_components": SHARED_COMPONENTS,
            "cap": MAX_CORROBORATION,
            "note": ("These two analyses read the same log and share the ATT&CK rule "
                     "table, so they are a second opinion rather than a second sensor. "
                     f"Agreement between them is capped at {MAX_CORROBORATION} "
                     "corroboration strength for that reason."),
        },
        "explanation": _explain(verdict, agreement, wf_sev, ag_sev, shared, degraded),
    }


def _explain(verdict: str, agreement: str, wf: str, ag: str,
             shared: list[str], degraded: list[str]) -> str:
    if verdict == "corroborates":
        return (f"A separately-built analysis reached the same severity ({wf}) and "
                f"agrees on {len(shared)} technique(s). That is corroboration from a "
                f"different method, not a repeat of the same signal.")
    if verdict == "contradicts":
        return (f"The two analyses disagree materially: the workflow says {wf}, the "
                f"agent lane says {ag}. They measure severity differently — peak "
                f"anomaly score versus ranked-chain risk — so this is a real "
                f"disagreement to resolve, not noise. The workflow governs; "
                f"confidence is reduced until it is understood.")
    if verdict == "partially corroborates":
        extra = (f" The agent lane was degraded ({', '.join(degraded)}), which further "
                 f"limits what its agreement is worth." if degraded else "")
        return (f"Severity agreement is {agreement} (workflow {wf}, agent lane {ag}) "
                f"with {len(shared)} shared technique(s). Partial support.{extra}")
    return ("The two analyses share no techniques, so the second opinion neither "
            "supports nor contradicts the first.")


def as_evidence(cc: dict):
    """The cross-check as an Evidence item for the claim confidence model."""
    from src.shared.claims import Evidence

    if not cc.get("available") or cc.get("corroboration_strength", 0) <= 0:
        return None
    return Evidence(
        id="crosscheck:agent-lane",
        kind="independent-analysis",
        source="src/agents 10-agent pipeline",
        independence_group=cc["independence_group"],
        strength=float(cc["corroboration_strength"]),
        reliability=1.0,
        detail=cc["explanation"],
    )


def demo() -> None:
    """Self-check: agreement corroborates, conflict contradicts, and neither
    can pretend to be a fully independent sensor."""
    wf = {"signals": {"incident": {"severity": "high",
                                   "technique_ids": ["T1078", "T1021"]}}}

    agree = crosscheck(wf, {"status": "ok", "severity": "high",
                            "evidence_refs": ["T1021"], "agent_traces": []})
    assert agree["verdict"] == "corroborates", agree["verdict"]
    assert agree["corroboration_strength"] == MAX_CORROBORATION
    assert agree["techniques"]["shared"] == ["T1021"]

    conflict = crosscheck(wf, {"status": "ok", "severity": "low",
                               "evidence_refs": ["T1021"], "agent_traces": []})
    assert conflict["verdict"] == "contradicts", conflict["verdict"]
    assert conflict["corroboration_strength"] == 0.0

    degraded = crosscheck(wf, {"status": "ok", "severity": "high",
                               "evidence_refs": ["T1021"],
                               "agent_traces": [{"agent": "intelligence",
                                                 "status": "degraded"}]})
    assert degraded["corroboration_strength"] < agree["corroboration_strength"]

    missing = crosscheck(wf, None)
    assert missing["available"] is False and missing["authoritative"] == "workflow"

    ev = as_evidence(agree)
    assert ev is not None and ev.support <= MAX_CORROBORATION
    assert as_evidence(conflict) is None

    print(f"crosscheck ok: agreement {agree['verdict']} at {agree['corroboration_strength']}, "
          f"conflict {conflict['verdict']}, degraded {degraded['corroboration_strength']}, "
          f"capped at {MAX_CORROBORATION} for partial independence")


if __name__ == "__main__":
    demo()
