"""Technique- and asset-aware simulated response playbooks.

The response layer proposes work; it never contacts a control plane. A proposal
is selected from the observed ATT&CK technique, bound to the event that
triggered it and carries enough operational context for a responder to decide
whether it is safe. Missing architecture is reported explicitly rather than
replaced with a tactic-level guess.
"""
from __future__ import annotations

import pickle
from pathlib import Path
from typing import Any

from src.shared.severity import LEVELS, severity_from_score

ROOT = Path(__file__).resolve().parents[2]
LOOKUPS = ROOT / "data" / "processed" / "mitre_attack" / "attack_lookups.pkl"


# ATT&CK identification is produced upstream and is merely the lookup key here.
# Each response record is complete enough to review before a simulation.
PLAYBOOKS: dict[str, dict[str, Any]] = {
    "T1110": {
        "name": "Brute Force", "kind": "identity_containment", "target": "user",
        "minimum_severity": "medium",
        "action": "Temporarily lock {target} and review failed sign-in sources",
        "prerequisites": ["confirm the account owner", "retain sign-in and MFA logs"],
        "operational_cost": "Account access is interrupted until the lock is reversed.",
        "rollback": "Unlock the account and restore its previous access policy.",
        "verification": "Confirm failed attempts stop and the owner completes a safe sign-in.",
    },
    "T1078": {
        "name": "Valid Accounts", "kind": "identity_containment", "target": "user",
        "minimum_severity": "medium",
        "action": "Revoke active sessions for {target} and require step-up verification",
        "prerequisites": ["confirm the identity-provider tenant", "preserve sign-in evidence"],
        "operational_cost": "The user must authenticate again; active sessions are interrupted.",
        "rollback": "Remove temporary sign-in restrictions after the owner is verified.",
        "verification": "Confirm old session tokens fail and a new MFA-backed session succeeds.",
    },
    "T1190": {
        "name": "Exploit Public-Facing Application", "kind": "application_containment",
        "target": "destination_host", "minimum_severity": "high",
        "action": "Restrict public traffic to {target}, apply a tested patch or WAF virtual patch",
        "prerequisites": ["asset is confirmed as a public-facing application",
                          "application owner and rollback window are identified"],
        "operational_cost": "Public application traffic may be reduced or briefly interrupted.",
        "rollback": "Remove the WAF rule or restore the previous application release.",
        "verification": "Retest the exploit path and confirm healthy requests still succeed.",
        "asset_types": {"public_web_application", "web_application"},
        "controls": {"waf", "patch_management"},
    },
    "T1021": {
        "name": "Remote Services", "kind": "network_containment",
        "target": "destination_host", "minimum_severity": "medium",
        "action": "Temporarily restrict remote-service access to {target} from {source}",
        "prerequisites": ["identify the remote service and its business owner",
                          "preserve authentication and connection logs"],
        "operational_cost": "Administrative sessions from the source host may be interrupted.",
        "rollback": "Restore the previous service ACL after the source is cleared.",
        "verification": "Confirm the source can no longer open the service while approved paths work.",
    },
    "T1550.002": {
        "name": "Use Alternate Authentication Material: Pass the Hash",
        "kind": "host_containment", "target": "source_host", "minimum_severity": "high",
        "action": "Isolate {target} and invalidate exposed NTLM credentials used toward {destination}",
        "prerequisites": ["capture volatile endpoint evidence", "confirm an alternate admin path"],
        "operational_cost": "The source host loses normal network access during investigation.",
        "rollback": "Restore network access after credential rotation and endpoint clearance.",
        "verification": "Confirm NTLM reuse stops and the rotated credentials reject old material.",
    },
    "T1018": {
        "name": "Remote System Discovery", "kind": "increase_logging",
        "target": "source_host", "minimum_severity": "medium",
        "action": "Increase process and network telemetry on {target} and restrict unauthorised scans",
        "prerequisites": ["confirm no authorised discovery or inventory job is running"],
        "operational_cost": "Additional telemetry increases short-term storage and analyst load.",
        "rollback": "Return telemetry retention and scan policy to their previous settings.",
        "verification": "Confirm discovery traffic stops or is attributed to an approved scanner.",
    },
    "T1213": {
        "name": "Data from Information Repositories", "kind": "repository_containment",
        "target": "destination_host", "minimum_severity": "high",
        "action": "Suspend the suspicious repository session on {target} and preserve access records",
        "prerequisites": ["identify the repository owner", "preserve query and export logs"],
        "operational_cost": "The suspicious session is interrupted; shared service remains online.",
        "rollback": "Restore the session only after the account and endpoint are cleared.",
        "verification": "Confirm the session is closed and no new unauthorised export begins.",
    },
    "T1041": {
        "name": "Exfiltration Over C2 Channel", "kind": "network_containment",
        "target": "source_host", "minimum_severity": "critical",
        "action": "Block the observed outbound path from {target} and preserve a forensic snapshot",
        "prerequisites": ["confirm the destination is not an approved backup or sync service",
                          "record the current firewall and routing policy"],
        "operational_cost": "Outbound connectivity from the source may be interrupted.",
        "rollback": "Restore the previous egress rule after destination ownership is resolved.",
        "verification": "Confirm outbound transfer stops and approved traffic remains healthy.",
    },
}


def _mitigations(technique_ids: list[str]) -> list[str]:
    with LOOKUPS.open("rb") as file:
        lookups = pickle.load(file)
    mapped = lookups.get("technique_to_mitigations", {})
    result: list[str] = []
    for technique_id in technique_ids:
        for mitigation in mapped.get(technique_id, [])[:2]:
            if mitigation not in result:
                result.append(mitigation)
    return result[:6]


def _at_least(actual: str, minimum: str) -> bool:
    try:
        return LEVELS.index(actual) >= LEVELS.index(minimum)
    except ValueError:
        return False


def _evidence_for(incident: dict, technique_id: str) -> dict | None:
    matches = [step for step in incident.get("alerts", [])
               if step.get("technique_id") == technique_id]
    if not matches:
        return None
    step = max(matches, key=lambda item: float(item.get("anomaly_score") or 0))
    return {
        "technique_id": technique_id,
        "technique": step.get("technique") or PLAYBOOKS[technique_id]["name"],
        "tactic": step.get("tactic") or "Unknown",
        "event_type": step.get("event_type") or "unknown",
        "anomaly_score": int(step.get("anomaly_score") or 0),
        "timestamp": step.get("timestamp"),
        "user": step.get("user") or None,
        "source_host": step.get("source_host") or None,
        "destination_host": step.get("destination_host") or None,
    }


def _target(evidence: dict, field: str) -> str | None:
    value = evidence.get(field)
    return str(value) if value is not None and str(value).strip() else None


def _applicability(playbook: dict, evidence: dict, architecture: dict) -> tuple[str, str]:
    target = _target(evidence, playbook["target"])
    if not target:
        return "not_applicable", f"No {playbook['target']} target was present in the evidence."

    allowed_types = set(playbook.get("asset_types") or [])
    if allowed_types:
        asset_types = architecture.get("asset_types")
        if not isinstance(asset_types, dict):
            return "not_configured", "Asset types are not configured for this investigation."
        actual = str(asset_types.get(target) or "")
        if not actual:
            return "not_configured", f"No asset type is configured for {target}."
        if actual not in allowed_types:
            return "not_applicable", f"{target} is recorded as {actual}, not a public web application."

    required_controls = set(playbook.get("controls") or [])
    if required_controls and "controls" in architecture:
        configured = set(architecture.get("controls") or [])
        if not (configured & required_controls):
            names = " or ".join(sorted(required_controls))
            return "not_configured", f"Neither required control ({names}) is configured."
    return "applicable", "Observed evidence supplies a target for this manual simulated playbook."


def _proposal(playbook: dict, evidence: dict, architecture: dict) -> dict:
    target = _target(evidence, playbook["target"])
    applicability, reason = _applicability(playbook, evidence, architecture)
    values = {
        "target": target or "the unresolved target",
        "source": evidence.get("source_host") or "the observed source",
        "destination": evidence.get("destination_host") or "the observed destination",
    }
    return {
        "technique_id": evidence["technique_id"], "technique": evidence["technique"],
        "tactic": evidence["tactic"], "kind": playbook["kind"],
        "action": playbook["action"].format(**values), "target": target,
        "triggering_evidence": evidence,
        "prerequisites": list(playbook["prerequisites"]),
        "operational_cost": playbook["operational_cost"],
        "rollback": playbook["rollback"], "verification": playbook["verification"],
        "minimum_severity": playbook["minimum_severity"],
        "applicability": applicability, "applicability_reason": reason,
    }


def recommend(incident: dict, graph_analysis: dict | None = None,
              architecture: dict | None = None) -> dict:
    """Return evidence-bound response proposals; never execute them.

    ``architecture`` may contain ``asset_types`` (host -> type) and ``controls``
    (installed control names). Missing facts are never replaced with guessed
    product names. Playbooks that need those facts return ``not_configured``.
    """
    architecture = architecture or incident.get("response_architecture") or {}
    actions: list[dict] = []
    skipped: list[dict] = []
    for technique_id in incident.get("technique_ids", []):
        playbook = PLAYBOOKS.get(technique_id)
        if not playbook:
            skipped.append({"technique_id": technique_id,
                            "reason": "no technique-specific response playbook is configured"})
            continue
        evidence = _evidence_for(incident, technique_id)
        if not evidence:
            skipped.append({"technique_id": technique_id,
                            "reason": "the technique list had no matching alert evidence"})
            continue
        evidence_severity = severity_from_score(evidence["anomaly_score"])
        if not _at_least(evidence_severity, playbook["minimum_severity"]):
            skipped.append({
                "technique_id": technique_id,
                "reason": (f"evidence severity {evidence_severity} is below playbook minimum "
                           f"{playbook['minimum_severity']}"),
                "triggering_evidence": evidence,
            })
            continue
        actions.append(_proposal(playbook, evidence, architecture))

    return {
        "incident_id": incident["incident_id"], "severity": incident["severity"],
        "gating_policy": ("Technique minimum severity is enforced before proposal; "
                          "RBAC then gates each applicable simulation by impact."),
        "mitre_mitigations": _mitigations(incident.get("technique_ids", [])),
        "actions": actions, "skipped_actions": skipped, "operational": False,
        "note": "Simulation only; no response connector is called.",
    }
