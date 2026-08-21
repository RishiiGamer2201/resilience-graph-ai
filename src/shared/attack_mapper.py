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

# How much each rule's observation actually supports its ATT&CK technique, and
# what would settle it. An anomaly establishes that behaviour is unusual for its
# baseline; a technique additionally asserts adversary behaviour, and most of
# these rules cannot see the difference from authentication logs alone.
#
# `strength` feeds src.shared.claims.Evidence. It is not a probability that an
# attack occurred; it is how much weight this single observation carries toward
# the technique, before independent corroboration.
CLAIM_RULES: dict[str, dict] = {
    "unusual_successful_login": {
        "status": "inferred",
        "strength": 0.3,
        "missing_evidence": [
            "endpoint process telemetry for the session",
            "whether the source device is managed and enrolled",
            "MFA result and whether the method was downgraded",
            "whether the account changed role or was travelling",
        ],
        "alternatives": [
            "role change or new team assignment",
            "travel, or a first login from a new office or VPN gateway",
            "scheduled maintenance or an administrative task",
            "new device enrollment",
        ],
        "note": ("The detector saw behaviour unusual for this account. T1078 "
                 "additionally asserts adversarial use of a legitimate account, "
                 "which authentication logs alone cannot establish. Reported as a "
                 "candidate, not an observation."),
    },
    "new_host_auth": {
        "status": "inferred",
        "strength": 0.45,
        "missing_evidence": [
            "whether the destination is in this account's normal scope of work",
            "the process that initiated the connection",
        ],
        "alternatives": [
            "legitimate first-time access to a newly assigned system",
            "an administrator working outside their usual hosts",
        ],
        "note": ("First-ever authentication to this host by this account. "
                 "Suggestive of remote-service use; not proof of it."),
    },
    "ntlm_lateral_movement": {
        "status": "inferred",
        "strength": 0.6,
        "missing_evidence": [
            "evidence that authentication material was stolen rather than typed",
            "endpoint credential-access telemetry on the source host",
        ],
        "alternatives": [
            "a legacy application or appliance that only supports NTLM",
            "a misconfigured client falling back from Kerberos",
        ],
        "note": ("New-host authentication over NTLM. Pass-the-Hash is the "
                 "strongest reading, but NTLM fallback has benign causes; "
                 "T1550.002 needs evidence about the credential material."),
    },
    "failed_login_burst": {
        "status": "observed",
        "strength": 0.7,
        "missing_evidence": ["whether the attempts came from one source or many"],
        "alternatives": [
            "an expired password with a client retrying automatically",
            "a service account with stale credentials after a rotation",
        ],
        "note": ("Repeated authentication failures are directly observable, which "
                 "is why this one is 'observed' rather than 'inferred'. The "
                 "benign causes are common and are kept on the record."),
    },
    "critical_asset_access": {
        "status": "observed",
        "strength": 0.55,
        "missing_evidence": ["whether this account is authorised for this asset"],
        "alternatives": ["routine authorised access by an entitled user"],
        "note": "Access to a designated crown jewel is observed; intent is not.",
    },
    "large_outbound_transfer": {
        "status": "observed",
        "strength": 0.65,
        "missing_evidence": ["the destination's reputation and ownership",
                             "whether an approved backup or sync job was running"],
        "alternatives": ["scheduled backup, replication or a large legitimate export"],
        "note": "Volume is observed; exfiltration is an interpretation of it.",
    },
    "discovery": {
        "status": "inferred",
        "strength": 0.5,
        "missing_evidence": ["the process and account performing the enumeration"],
        "alternatives": ["an authorised vulnerability scan or asset inventory sweep"],
        "note": "Scanning behaviour has a common, authorised twin.",
    },
}

# Rules with no entry assert nothing beyond the observation itself.
DEFAULT_CLAIM = {
    "status": "inferred", "strength": 0.25,
    "missing_evidence": ["corroborating telemetry from another source"],
    "alternatives": ["benign activity that resembles this pattern"],
    "note": "No calibrated rule for this event type.",
}


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
    """Rule-based ATT&CK mapping, carrying how much the rule actually supports it.

    The technique is a CANDIDATE unless the observation itself is the technique.
    Callers get `claim_status`, `claim_strength`, `missing_evidence` and
    `alternatives` so the UI can say "inferred, low confidence, here is what
    would settle it" instead of printing a technique id as though it were a fact.
    """
    tactic, tech, tid, sev = RULE_MAP.get(
        event_type, ("Unknown", "Unmapped", "-", 10))
    rule = CLAIM_RULES.get(event_type, DEFAULT_CLAIM if tid != "-" else {
        "status": "observed", "strength": 0.0, "missing_evidence": [],
        "alternatives": [], "note": "Expected activity; no technique claimed."})
    return {
        "event_type": event_type,
        "tactic": tactic,
        "technique": tech,
        "technique_id": tid,
        "base_severity": sev,
        "explanation": explanation(tid),
        "claim_status": rule["status"],
        "claim_strength": rule["strength"],
        "missing_evidence": list(rule["missing_evidence"]),
        "alternatives": list(rule["alternatives"]),
        "claim_note": rule["note"],
    }


def claim_for_event(step: dict) -> dict:
    """Build a full evidence-backed Claim for one correlated step.

    The detector and the ATT&CK rule are deliberately placed in the SAME
    independence group: the rule fires *because* of the detector's features, so
    treating them as two sources would be exactly the duplicate-evidence
    inflation the research warns about.
    """
    from src.shared.claims import Claim, ClaimStatus, Evidence

    tid = step.get("technique_id") or "-"
    mapping = map_event(step.get("event_type") or "normal_auth")
    claim = Claim(
        subject=f"account:{step.get('user') or 'unknown'}",
        predicate="MAPS_TO",
        object=mapping["technique"],
        external_id=tid,
        status=ClaimStatus(mapping["claim_status"]),
        mapper="src.shared.attack_mapper.RULE_MAP",
        missing_evidence=mapping["missing_evidence"],
        alternatives=mapping["alternatives"],
        note=mapping["claim_note"],
    )
    if tid != "-":
        score = float(step.get("anomaly_score") or 0)
        claim.add_evidence(Evidence(
            id=f"step:{step.get('timestamp')}:{step.get('destination_host')}",
            kind="behavioural-anomaly",
            source="src.shared.detector (benign-trained autoencoder)",
            # one group: the rule reads the detector's own features
            independence_group="detector+rule",
            strength=mapping["claim_strength"],
            reliability=min(1.0, score / 100.0),
            detail=(f"calibrated anomaly score {score:.0f}/100 on "
                    f"{step.get('source_host')} -> {step.get('destination_host')}"),
        ))
    return claim.as_dict()


ALERT_SCORE = 50            # matches correlate.ALERT_THRESHOLD (the 1% FPR line)


def infer_lanl_event_type(row: dict, alert_threshold: int = ALERT_SCORE) -> str:
    """Derive an event type from a LANL auth row's behavioral features.

    Expects the engineered columns from src.engine1.lanl_detect.engineer()
    (is_fail, new_dst_for_user, is_ntlm). Falls back gracefully if absent.

    A flagged event that is neither a failure nor a first-time host still gets an
    ATT&CK candidate, because reaching an analyst with no context at all is its
    own failure (that path was 37.5% mapping coverage). But the candidate is a
    CANDIDATE: `map_event` returns it with claim status `inferred`, strength 0.3,
    the evidence that would settle it, and the benign alternatives that have not
    been excluded. An anomaly establishes that behaviour is unusual for this
    account; T1078 additionally asserts adversarial use of a legitimate account,
    and authentication logs alone cannot tell those apart.
    """
    if row.get("is_fail"):
        return "failed_login_burst"
    new_host = bool(row.get("new_dst_for_user"))
    ntlm = bool(row.get("is_ntlm"))
    if new_host and ntlm:
        return "ntlm_lateral_movement"
    if new_host:
        return "new_host_auth"
    if float(row.get("anomaly_score") or 0) >= alert_threshold:
        return "unusual_successful_login"
    return "normal_auth"
