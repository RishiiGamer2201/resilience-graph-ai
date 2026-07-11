"""
Milestone 4 · S5 — Simulated SOAR response (confidence-gated).

Turns an incident into recommended containment actions. Actions are seeded from
the REAL ATT&CK mitigations for the incident's techniques (attack_lookups.pkl),
then gated by confidence + asset criticality so nothing dangerous auto-fires.

⚠️ All actions are SIMULATED. Critical-asset actions require human approval.

    from src.shared.soar import recommend
"""
from __future__ import annotations

import pickle
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LOOKUPS = ROOT / "data" / "processed" / "mitre_attack" / "attack_lookups.pkl"

# concrete response actions per tactic (what a SOC playbook would do)
TACTIC_ACTIONS = {
    "Credential Access": ("Force password reset + enable MFA", "medium"),
    "Initial Access":    ("Disable / step-up verify the account", "high"),
    "Lateral Movement":  ("Isolate the pivot host, block SMB/NTLM between segments", "high"),
    "Discovery":         ("Increase logging, monitor the account", "low"),
    "Collection":        ("Isolate critical-asset session, preserve forensic snapshot", "high"),
    "Exfiltration":      ("Block the external destination, quarantine the host", "critical"),
}


def _mitigations(technique_ids: list[str]) -> list[str]:
    with LOOKUPS.open("rb") as f:
        lk = pickle.load(f)
    m2t = lk.get("technique_to_mitigations", {})
    out = []
    for tid in technique_ids:
        for m in m2t.get(tid, [])[:2]:
            if m not in out:
                out.append(m)
    return out[:6]


def _gate(severity: str, involves_critical: bool) -> str:
    if involves_critical:
        return "requires human approval"
    return {"critical": "simulate containment", "high": "simulate containment",
            "medium": "create ticket + enrich", "low": "monitor only"}.get(severity, "monitor only")


def recommend(incident: dict, graph_analysis: dict | None = None) -> dict:
    """Produce gated, ATT&CK-grounded response actions for an incident."""
    severity = incident["severity"]
    involves_critical = bool(graph_analysis and graph_analysis.get("critical_assets_at_risk"))
    tactics = []
    for t in incident["attack_chain"]:
        if t not in tactics and t != "Normal":
            tactics.append(t)

    actions = []
    for tactic in tactics:
        if tactic in TACTIC_ACTIONS:
            action, min_sev = TACTIC_ACTIONS[tactic]
            actions.append({
                "tactic": tactic,
                "action": action,
                "mode": _gate(severity, involves_critical),
            })

    if graph_analysis and graph_analysis.get("recommended_isolation"):
        actions.append({
            "tactic": "Containment",
            "action": f"Isolate choke-point host {graph_analysis['recommended_isolation']} "
                      f"(cuts blast radius of {graph_analysis.get('blast_radius_size', 0)} hosts)",
            "mode": "requires human approval" if involves_critical else "simulate containment",
        })

    actions.append({
        "tactic": "Coordination",
        "action": f"Open incident ticket {incident['incident_id']} + notify SOC lead",
        "mode": "automatic",
    })

    return {
        "incident_id": incident["incident_id"],
        "severity": severity,
        "gating_policy": "low=monitor · medium=ticket · high=contain · critical-asset=human approval",
        "mitre_mitigations": _mitigations(incident["technique_ids"]),
        "actions": actions,
    }
