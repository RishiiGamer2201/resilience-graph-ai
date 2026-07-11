"""
Milestone 4 · S3 — MITRE ATT&CK mapper.

Maps normalized events to ATT&CK tactic/technique. Two entry points:
  * RULE_MAP + map_event(): rule-based lookup for named event types (demo + any
    upstream detector that emits an event_type).
  * infer_lanl_event_type(): derive an event type for a raw LANL auth event from
    its behavioral features (new-host, failed, NTLM) so real auth data maps too.

Explanations are pulled from the real ATT&CK descriptions (attack_lookups.pkl),
so the text is grounded, not invented.

    from src.shared.attack_mapper import map_event, infer_lanl_event_type
"""
from __future__ import annotations

import pickle
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LOOKUPS = ROOT / "data" / "processed" / "mitre_attack" / "attack_lookups.pkl"

# event_type -> (tactic, technique name, technique id, base severity 0-100)
RULE_MAP: dict[str, tuple[str, str, str, int]] = {
    "failed_login_burst":       ("Credential Access", "Brute Force", "T1110", 55),
    "unusual_successful_login": ("Initial Access", "Valid Accounts", "T1078", 65),
    "new_host_auth":            ("Lateral Movement", "Remote Services", "T1021", 60),
    "ntlm_lateral_movement":    ("Lateral Movement", "Use Alternate Authentication Material: Pass the Hash", "T1550.002", 78),
    "discovery":                ("Discovery", "Remote System Discovery", "T1018", 50),
    "critical_asset_access":    ("Collection", "Data from Information Repositories", "T1213", 85),
    "large_outbound_transfer":  ("Exfiltration", "Exfiltration Over C2 Channel", "T1041", 92),
    "normal_auth":              ("Normal", "Expected Activity", "-", 5),
    "normal_login":             ("Normal", "Expected Activity", "-", 5),
}

_LOOKUPS = None


def _lookups() -> dict:
    global _LOOKUPS
    if _LOOKUPS is None:
        with LOOKUPS.open("rb") as f:
            _LOOKUPS = pickle.load(f)
    return _LOOKUPS


def explanation(technique_id: str) -> str:
    """First sentence of the real ATT&CK description for a technique id."""
    if technique_id == "-":
        return "Expected activity."
    desc = _lookups().get("technique_to_desc", {}).get(technique_id, "")
    return (desc.split(". ")[0].strip() + ".") if desc else ""


def map_event(event_type: str) -> dict:
    """Rule-based ATT&CK mapping for a named event type."""
    tactic, tech, tid, sev = RULE_MAP.get(
        event_type, ("Unknown", "Unmapped", "-", 10))
    return {
        "event_type": event_type,
        "tactic": tactic,
        "technique": tech,
        "technique_id": tid,
        "base_severity": sev,
        "explanation": explanation(tid),
    }


def infer_lanl_event_type(row: dict) -> str:
    """Derive an event type from a LANL auth row's behavioral features.

    Expects the engineered columns from src.engine1.lanl_detect.engineer()
    (is_fail, new_dst_for_user, is_ntlm). Falls back gracefully if absent.
    """
    if row.get("is_fail"):
        return "failed_login_burst"
    new_host = bool(row.get("new_dst_for_user"))
    ntlm = bool(row.get("is_ntlm"))
    if new_host and ntlm:
        return "ntlm_lateral_movement"
    if new_host:
        return "new_host_auth"
    return "normal_auth"
