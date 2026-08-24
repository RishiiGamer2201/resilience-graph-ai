"""Role-based access control and the human-approval policy.

Two separate questions, deliberately kept apart:

  * AUTHORISATION — "is this caller allowed to attempt this?"  `require()`
  * APPROVAL POLICY — "does this specific action need a human to say yes?"
    `policy_for()`, which decides from the action's blast radius and whether a
    crown jewel is involved, not from who is asking.

Both are enforced in the API layer on every mutating endpoint. Hiding a button in
the SPA is not access control; the backend refuses regardless of the UI.

Identity, honestly:
  * Default (demo) — `auth_mode = "demo-headers"`. The caller declares a role in
    `X-Role`. This is AUTHORISATION WITHOUT AUTHENTICATION and the capabilities
    endpoint says so out loud. It exists so a judge can switch roles and watch
    the server refuse, with zero signup.
  * Configured — set
    `NEXTATTACK_ROLE_TOKENS="tok1:responder:ravi@soc:Ravi Kumar"` and the service
    requires a matching `Authorization: Bearer <token>`. Role, immutable subject
    and optional display name all come from that trusted binding; `X-Role` and
    `X-Actor` are ignored. Still not an identity provider, and we do not claim it
    is.

    from src.shared.rbac import resolve_principal, require, policy_for
"""
from __future__ import annotations

import hashlib
import hmac
import os

ROLES = ("viewer", "analyst", "responder", "admin")

# permission -> the roles that hold it. Additive and explicit; no inheritance
# magic, because "why was this allowed?" must be answerable by reading one dict.
PERMISSIONS: dict[str, tuple[str, ...]] = {
    "read":              ("viewer", "analyst", "responder", "admin"),
    "analyze":           ("analyst", "responder", "admin"),
    "propose_action":    ("analyst", "responder", "admin"),
    "simulate":          ("analyst", "responder", "admin"),
    "approve_low":       ("responder", "admin"),
    "approve_critical":  ("responder", "admin"),
    "export_audit":      ("analyst", "responder", "admin"),
    "verify_audit":      ("viewer", "analyst", "responder", "admin"),
    "rotate_audit":      ("admin",),
}

DEFAULT_ROLE = "viewer"


class AuthError(Exception):
    """401 — the caller could not be identified with the configured scheme."""


class Denied(Exception):
    """403 — identified, but this role may not do this."""

    def __init__(self, role: str, permission: str):
        self.role, self.permission = role, permission
        super().__init__(
            f"role '{role}' is not permitted to '{permission}'. "
            f"Allowed roles: {', '.join(PERMISSIONS.get(permission, ()))}.")


def _token_map() -> dict[str, dict[str, str | None]]:
    """Parse token bindings without ever exposing a raw token as identity.

    Preferred format is ``token:role:subject[:display name]``. The legacy
    ``token:role`` form remains valid, but receives a stable pseudonymous subject
    derived from a one-way token fingerprint. In both forms the caller's headers
    cannot alter the authenticated identity.
    """
    raw = os.environ.get("NEXTATTACK_ROLE_TOKENS", "").strip()
    out: dict[str, dict[str, str | None]] = {}
    for pair in raw.split(","):
        parts = [part.strip() for part in pair.split(":", 3)]
        if len(parts) < 2:
            continue
        tok, role = parts[0], parts[1]
        if not tok or role not in ROLES:
            continue
        if len(parts) >= 3 and parts[2]:
            subject = parts[2][:120]
            display_name = parts[3][:120] if len(parts) == 4 and parts[3] else None
        else:
            fingerprint = hashlib.sha256(tok.encode("utf-8")).hexdigest()[:16]
            subject = f"legacy-token:{fingerprint}"
            display_name = None
        out[tok] = {
            "role": role,
            "subject": subject,
            "display_name": display_name,
        }
    return out


def auth_mode() -> str:
    return "bearer-tokens" if _token_map() else "demo-headers"


def resolve_principal(role_header: str | None, actor_header: str | None,
                      authorization: str | None) -> dict:
    """Work out who is calling, under whichever scheme is configured."""
    tokens = _token_map()
    if tokens:
        prefix = "bearer "
        if not authorization or not authorization.lower().startswith(prefix):
            raise AuthError("bearer token required (NEXTATTACK_ROLE_TOKENS is configured)")
        supplied = authorization[len(prefix):].strip()
        for tok, binding in tokens.items():
            if hmac.compare_digest(tok, supplied):     # constant-time compare
                subject = str(binding["subject"])
                display_name = binding.get("display_name")
                return {
                    "role": binding["role"],
                    "actor": display_name or subject,
                    "subject": subject,
                    "display_name": display_name,
                    "auth_mode": "bearer-tokens",
                    "authenticated": True,
                }
        raise AuthError("unrecognised bearer token")

    role = (role_header or DEFAULT_ROLE).strip().lower()
    if role not in ROLES:
        role = DEFAULT_ROLE
    return {"role": role, "actor": (actor_header or f"demo-{role}").strip()[:80],
            "subject": None, "display_name": None,
            "auth_mode": "demo-headers", "authenticated": False}


def require(principal: dict, permission: str) -> None:
    """Raise Denied unless the principal's role holds `permission`."""
    role = principal.get("role", DEFAULT_ROLE)
    if role not in PERMISSIONS.get(permission, ()):
        raise Denied(role, permission)


def permissions_for(role: str) -> list[str]:
    return sorted(p for p, roles in PERMISSIONS.items() if role in roles)


# --------------------------------------------------------------------------- #
# approval policy                                                              #
# --------------------------------------------------------------------------- #
# A simulated, reversible, low-blast action may be pre-approved by policy so the
# SOC is not drowned in ceremony. Anything touching a crown jewel or a wide blast
# radius requires a named human and a written reason — on critical national
# infrastructure that is the whole point.
BLAST_APPROVAL_THRESHOLD = 10       # hosts taken out of reach by the action

LOW_IMPACT_ACTIONS = {
    "monitor", "enrich", "ticket", "increase_logging", "notify", "snapshot",
}


def policy_for(action: dict) -> dict:
    """Decide the gate for one proposed action. Deterministic, input-driven."""
    kind = str(action.get("kind", "contain")).lower()
    crown = bool(action.get("touches_crown_jewel"))
    blast = int(action.get("blast_radius_affected") or 0)
    hosts_offline = int(action.get("hosts_taken_offline") or 0)

    reasons = []
    if crown:
        reasons.append("the action touches a designated crown-jewel asset")
    if blast >= BLAST_APPROVAL_THRESHOLD:
        reasons.append(f"it changes reachability for {blast} hosts "
                       f"(threshold {BLAST_APPROVAL_THRESHOLD})")
    if hosts_offline > 0 and kind not in LOW_IMPACT_ACTIONS:
        reasons.append(f"it takes {hosts_offline} production host(s) offline")

    if kind in LOW_IMPACT_ACTIONS and not crown and blast < BLAST_APPROVAL_THRESHOLD:
        return {
            "requires_approval": False,
            "gate": "pre-approved by policy",
            "required_permission": "approve_low",
            "reasons": ["low-impact, reversible, no crown jewel, "
                        f"blast radius {blast} < {BLAST_APPROVAL_THRESHOLD}"],
            "policy_version": "1.0.0",
        }
    return {
        "requires_approval": True,
        "gate": "requires named human approval with a written reason",
        "required_permission": "approve_critical" if crown else "approve_low",
        "reasons": reasons or ["containment actions are gated by default"],
        "policy_version": "1.0.0",
    }


def demo() -> None:
    """Self-check: the gate opens and closes on the right inputs."""
    viewer = resolve_principal("viewer", None, None)
    responder = resolve_principal("responder", "asha@soc", None)
    require(viewer, "read")
    try:
        require(viewer, "approve_critical")
        raise AssertionError("viewer must not be able to approve")
    except Denied:
        pass
    require(responder, "approve_critical")

    low = policy_for({"kind": "monitor", "blast_radius_affected": 2})
    assert low["requires_approval"] is False, low
    crown = policy_for({"kind": "isolate", "touches_crown_jewel": True,
                        "blast_radius_affected": 1, "hosts_taken_offline": 1})
    assert crown["requires_approval"] and crown["required_permission"] == "approve_critical"
    wide = policy_for({"kind": "isolate", "blast_radius_affected": 463,
                       "hosts_taken_offline": 1})
    assert wide["requires_approval"], wide
    assert auth_mode() in ("demo-headers", "bearer-tokens")
    print(f"rbac ok ({auth_mode()}): viewer denied approve_critical; "
          f"responder allowed; monitor pre-approved; crown-jewel isolation gated")


if __name__ == "__main__":
    demo()
