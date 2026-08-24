"""Server-issued, immutable action proposals.

The browser is an approval console, not the source of truth.  This store keeps
the action, policy, evidence and affected assets that the investigation issued;
an approval request carries only the opaque proposal id and the human decision.

The default in-memory database is appropriate for the zero-configuration demo:
a restart invalidates every outstanding proposal instead of accepting stale
browser state.  When ``NEXTATTACK_PROPOSAL_DB`` is set (or the audit database is
configured), SQLite persists proposals across restarts and the conditional
status update remains atomic.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from src.shared.audit import canonical

DEFAULT_TTL_SECONDS = 30 * 60
PROPOSAL_DB_ENV = "NEXTATTACK_PROPOSAL_DB"
PROPOSAL_TTL_ENV = "NEXTATTACK_PROPOSAL_TTL_SECONDS"


class ProposalError(RuntimeError):
    """Base class for safe API errors from the proposal store."""


class ProposalNotFound(ProposalError):
    pass


class ProposalExpired(ProposalError):
    pass


class ProposalAlreadyDecided(ProposalError):
    pass


class ProposalIntegrityError(ProposalError):
    pass


def digest(value: dict) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _ttl_seconds() -> int:
    raw = os.environ.get(PROPOSAL_TTL_ENV, "").strip()
    if not raw:
        return DEFAULT_TTL_SECONDS
    try:
        return max(60, min(int(raw), 24 * 60 * 60))
    except ValueError:
        return DEFAULT_TTL_SECONDS


def _configured_path() -> Path | None:
    raw = os.environ.get(PROPOSAL_DB_ENV, "").strip()
    if raw.lower() in ("off", "none", "memory", ":memory:"):
        return None
    if raw:
        return Path(raw)

    # A durable audit deployment should not lose pending approvals on restart.
    audit_raw = os.environ.get("NEXTATTACK_AUDIT_DB", "").strip()
    if audit_raw and audit_raw.lower() not in ("off", "none", "memory", ":memory:"):
        audit_path = Path(audit_raw)
        return audit_path.with_name("proposals.db")
    return None


class ProposalStore:
    """SQLite-backed proposal registry with an atomic pending-to-decided gate."""

    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            str(self.path) if self.path else ":memory:",
            check_same_thread=False,
            isolation_level=None,
            timeout=10,
        )
        self._conn.row_factory = sqlite3.Row
        if self.path is not None:
            self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS proposals (
                proposal_id TEXT PRIMARY KEY,
                proposal_digest TEXT NOT NULL,
                incident_id TEXT NOT NULL,
                input_digest TEXT NOT NULL,
                policy_version TEXT NOT NULL,
                issued_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                status TEXT NOT NULL,
                payload TEXT NOT NULL,
                decided_at TEXT,
                decision TEXT,
                decision_actor TEXT,
                decision_role TEXT,
                decision_reason TEXT
            )"""
        )

    @property
    def durable(self) -> bool:
        return self.path is not None

    def issue(
        self,
        *,
        incident_id: str,
        action: dict,
        input_digest: str,
        evidence: list[dict] | None = None,
        technique_ids: list[str] | None = None,
        affected_assets: list[str] | None = None,
        now: datetime | None = None,
        ttl_seconds: int | None = None,
    ) -> dict:
        issued = now or _now()
        expires = issued + timedelta(seconds=ttl_seconds if ttl_seconds is not None else _ttl_seconds())
        detached_action = json.loads(json.dumps(action))
        policy_version = (detached_action.get("policy") or {}).get("policy_version")
        if not policy_version:
            raise ProposalIntegrityError("server-issued action has no policy version")
        proposal_id = f"PRP-{secrets.token_urlsafe(24)}"
        payload = {
            "proposal_id": proposal_id,
            "incident_id": incident_id,
            # JSON round-tripping detaches caller-owned mutable containers.
            "action": detached_action,
            "input_digest": input_digest,
            "policy_version": str(policy_version),
            "issued_at": _iso(issued),
            "expires_at": _iso(expires),
            "evidence": json.loads(json.dumps(evidence or [])),
            "technique_ids": list(technique_ids or []),
            "affected_assets": list(affected_assets or []),
        }
        proposal_digest = digest(payload)
        with self._lock:
            self._conn.execute(
                """INSERT INTO proposals (
                    proposal_id, proposal_digest, incident_id, input_digest,
                    policy_version, issued_at, expires_at, status, payload
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?)""",
                (
                    proposal_id,
                    proposal_digest,
                    incident_id,
                    input_digest,
                    str(policy_version),
                    payload["issued_at"],
                    payload["expires_at"],
                    json.dumps(payload, sort_keys=True, separators=(",", ":")),
                ),
            )
        return {
            **payload["action"],
            "proposal_id": payload["proposal_id"],
            "proposal_digest": proposal_digest,
            "input_digest": input_digest,
            "policy_version": payload["policy_version"],
            "issued_at": payload["issued_at"],
            "expires_at": payload["expires_at"],
            "status": "pending",
        }

    def _row(self, proposal_id: str) -> sqlite3.Row:
        row = self._conn.execute(
            "SELECT * FROM proposals WHERE proposal_id = ?", (proposal_id,)
        ).fetchone()
        if row is None:
            raise ProposalNotFound("unknown server-issued proposal")
        return row

    @staticmethod
    def _verified(row: sqlite3.Row) -> dict:
        try:
            payload = json.loads(row["payload"])
        except (TypeError, ValueError) as exc:
            raise ProposalIntegrityError("stored proposal payload is unreadable") from exc
        if digest(payload) != row["proposal_digest"]:
            raise ProposalIntegrityError("stored proposal digest does not match its payload")
        bound_columns = {
            "proposal_id": "proposal_id",
            "incident_id": "incident_id",
            "input_digest": "input_digest",
            "policy_version": "policy_version",
            "issued_at": "issued_at",
            "expires_at": "expires_at",
        }
        for payload_key, row_key in bound_columns.items():
            if payload.get(payload_key) != row[row_key]:
                raise ProposalIntegrityError(
                    f"stored proposal {payload_key} binding does not match"
                )
        return {
            **payload,
            "proposal_digest": row["proposal_digest"],
            "status": row["status"],
            "decision": row["decision"],
        }

    def get(self, proposal_id: str) -> dict:
        with self._lock:
            return self._verified(self._row(proposal_id))

    def decide(
        self,
        proposal_id: str,
        *,
        decision: str,
        actor: str,
        role: str,
        reason: str,
        now: datetime | None = None,
    ) -> dict:
        """Atomically consume one pending proposal and return its immutable data."""
        decided_at = now or _now()
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._row(proposal_id)
                proposal = self._verified(row)
                if row["status"] != "pending":
                    raise ProposalAlreadyDecided(
                        f"proposal was already {row['status']}"
                    )
                if _parse(row["expires_at"]) <= decided_at:
                    self._conn.execute(
                        "UPDATE proposals SET status = 'expired' "
                        "WHERE proposal_id = ? AND status = 'pending'",
                        (proposal_id,),
                    )
                    self._conn.execute("COMMIT")
                    raise ProposalExpired("server-issued proposal has expired")

                cursor = self._conn.execute(
                    """UPDATE proposals
                       SET status = ?, decided_at = ?, decision = ?,
                           decision_actor = ?, decision_role = ?, decision_reason = ?
                       WHERE proposal_id = ? AND status = 'pending'""",
                    (
                        "approved" if decision == "approve" else "rejected",
                        _iso(decided_at),
                        decision,
                        actor,
                        role,
                        reason,
                        proposal_id,
                    ),
                )
                if cursor.rowcount != 1:
                    raise ProposalAlreadyDecided("proposal already has a decision")
                self._conn.execute("COMMIT")
                proposal["status"] = "approved" if decision == "approve" else "rejected"
                proposal["decision"] = decision
                proposal["decided_at"] = _iso(decided_at)
                return proposal
            except ProposalExpired:
                # The expiry transition was intentionally committed above.
                raise
            except Exception:
                self._conn.execute("ROLLBACK")
                raise


_store: ProposalStore | None = None
_store_lock = threading.Lock()


def store() -> ProposalStore:
    global _store
    with _store_lock:
        if _store is None:
            _store = ProposalStore(_configured_path())
        return _store


def reset_store_for_tests(path: str | Path | None = None) -> ProposalStore:
    """Replace the process store. Intended for isolated tests only."""
    global _store
    with _store_lock:
        if _store is not None:
            _store._conn.close()
        _store = ProposalStore(path)
        return _store


def demo() -> None:
    s = ProposalStore()
    p = s.issue(
        incident_id="INC-DEMO",
        action={"kind": "isolate", "policy": {
            "required_permission": "approve_critical", "policy_version": "1.0.0"}},
        input_digest=digest({"events": 3}),
    )
    decided = s.decide(
        p["proposal_id"], decision="approve", actor="ravi@soc", role="responder", reason="demo"
    )
    assert decided["proposal_digest"] == p["proposal_digest"]
    try:
        s.decide(
            p["proposal_id"], decision="approve", actor="ravi@soc", role="responder", reason="again"
        )
    except ProposalAlreadyDecided:
        pass
    else:
        raise AssertionError("a proposal accepted two decisions")


if __name__ == "__main__":
    demo()
    print("proposals: self-check passed")
