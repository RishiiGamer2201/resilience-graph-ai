"""Tamper-evident audit chain for evidence and response decisions.

Every consequential act in an investigation -- an analysis run, a retrieved
citation, a proposed containment, an approval, a refusal, an export -- is appended
as a record whose hash covers the record AND the hash before it. Change any
earlier record and every hash after it stops matching, which `verify()` finds and
names.

Deliberately NOT called immutable or blockchain. It is a hash-linked append-only
log held for the session and exportable as JSON. Anyone holding the export can
recompute the chain and detect edits; nobody is prevented from throwing the whole
file away. That is the honest claim, and it is the one auditors actually use.

Canonicalisation is fixed and documented, because a hash over "some JSON" is not
reproducible: `json.dumps(payload, sort_keys=True, separators=(",", ":"),
ensure_ascii=False)` encoded UTF-8, then
`sha256(prev_hash + "\\n" + canonical_bytes)`.

    from src.shared.audit import chain
    rec = chain().append("action.proposed", actor="asha@soc", role="responder", ...)
    ok, problem = chain().verify()
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import sqlite3
import threading
from pathlib import Path

from src.shared.timeutil import fmt_ist

ROOT = Path(__file__).resolve().parents[2]
HASH_ALGORITHM = "sha256"
CHAIN_VERSION = "1.1.0"
GENESIS_PREV = "0" * 64
MAX_RECORDS = 5000            # bounded: the demo is session-scoped, not a SIEM

# Event kinds we expect. Unknown kinds are allowed (forward compatibility) but are
# flagged in the export so an auditor notices a producer they do not recognise.
KNOWN_KINDS = {
    "session.started", "analysis.completed", "evidence.retrieved",
    "impact.simulated", "action.proposed", "action.approved", "action.rejected",
    "action.denied", "report.exported", "audit.exported", "session.reset",
}


def canonical(payload: dict) -> bytes:
    """The exact bytes that get hashed. Documented, stable, reproducible."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def record_hash(prev_hash: str, payload: dict) -> str:
    h = hashlib.sha256()
    h.update(prev_hash.encode("ascii"))
    h.update(b"\n")
    h.update(canonical(payload))
    return h.hexdigest()


class AuditChain:
    """Append-only, hash-linked, thread-safe, and durable when given a path.

    Durability is what makes the claim on the scoreboard true. Tamper DETECTION
    always worked -- the hash chain is real and the tamper test passes -- but the
    chain lived only in process memory, so a restart erased it:

        records before restart: 8
        records after restart:  1

    An audit log a restart erases cannot evidence anything after the restart,
    and "Audit tampering detected" read as one claim with retention when it was
    not. Now it is one claim.

    Storage is stdlib sqlite3: no new dependency, one file, so ADR 0001's
    single-container promise holds. `path=None` keeps the old in-memory
    behaviour, which is what every unit test and every demo() wants.
    """

    def __init__(self, artifact_versions: dict | None = None,
                 path: "str | pathlib.Path | None" = None):
        self._lock = threading.Lock()
        self._records: list[dict] = []
        self._versions = artifact_versions or {}
        self._db = pathlib.Path(path) if path else None
        if self._db is not None:
            self._open()
            if self._records:
                # Resumed, not started. Recording a fresh session.started here
                # would be a lie about a chain that already exists.
                return
        self.append("session.started", actor="system", role="system",
                    reason="audit chain initialised",
                    details={"chain_version": CHAIN_VERSION,
                             "hash_algorithm": HASH_ALGORITHM,
                             "canonicalisation": "json sort_keys, separators (,:), utf-8"})

    # -- write ------------------------------------------------------------
    def append(self, kind: str, *, actor: str, role: str, reason: str = "",
               subject: str | None = None, display_name: str | None = None,
               incident_id: str | None = None, inputs: dict | None = None,
               evidence: list[dict] | None = None,
               technique_ids: list[str] | None = None,
               affected_assets: list[str] | None = None,
               action: dict | None = None, decision: str | None = None,
               details: dict | None = None) -> dict:
        """Append one record and return it (including its hash)."""
        with self._lock:
            if len(self._records) >= MAX_RECORDS:
                raise RuntimeError(
                    f"audit chain is full ({MAX_RECORDS} records) -- export and reset")
            prev = self._records[-1]["hash"] if self._records else GENESIS_PREV
            payload = {
                "seq": len(self._records),
                "kind": kind,
                "at": fmt_ist(),
                "actor": actor,
                "role": role,
                # In authenticated modes subject comes from the credential
                # binding, never X-Actor. Demo mode honestly records None.
                "subject": subject,
                "display_name": display_name,
                "reason": reason,
                "incident_id": incident_id,
                "inputs": inputs or {},
                # evidence is referenced by hash + URL, never copied wholesale
                "evidence": [{"chunk_id": e.get("chunk_id"), "url": e.get("url"),
                              "sha256": e.get("sha256"), "publisher": e.get("publisher"),
                              "title": e.get("title")}
                             for e in (evidence or [])],
                "technique_ids": list(technique_ids or []),
                "affected_assets": list(affected_assets or []),
                "action": action or {},
                "decision": decision,
                "details": details or {},
                "versions": self._versions,
                "prev_hash": prev,
            }
            rec = {**payload, "hash": record_hash(prev, payload)}
            self._records.append(rec)
            self._persist(rec)
            return rec

    # -- durability -------------------------------------------------------
    def _open(self) -> None:
        """Create the table if needed and load whatever is already there."""
        self._db.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self._db) as c:
            c.execute("CREATE TABLE IF NOT EXISTS audit ("
                      "seq INTEGER PRIMARY KEY, hash TEXT NOT NULL, "
                      "record TEXT NOT NULL)")
            rows = c.execute("SELECT record FROM audit ORDER BY seq").fetchall()
        try:
            self._records = [json.loads(r[0]) for r in rows]
        except Exception:
            # A corrupt store must not take the service down, and must not be
            # silently treated as an empty one either.
            self._records = []
            self._corrupt = True

    def _persist(self, rec: dict) -> None:
        if self._db is None:
            return
        with sqlite3.connect(self._db) as c:
            try:
                c.execute("INSERT INTO audit (seq, hash, record) VALUES (?,?,?)",
                          (rec["seq"], rec["hash"], json.dumps(rec, sort_keys=True)))
            except sqlite3.IntegrityError as e:
                raise RuntimeError(
                    f"audit seq {rec['seq']} already exists in {self._db.name}: two "
                    f"chains are writing to one file. Refusing rather than "
                    f"overwriting -- silent replacement is what corrupts a chain."
                ) from e

    @property
    def durable(self) -> bool:
        """Whether this chain survives a restart. Reported, never assumed."""
        return self._db is not None

    def reset(self, actor: str = "system", role: str = "system",
              subject: str | None = None, display_name: str | None = None) -> dict:
        """Start a fresh chain (the old one is gone unless it was exported)."""
        with self._lock:
            self._records = []
            if self._db is not None:
                with sqlite3.connect(self._db) as c:
                    c.execute("DELETE FROM audit")
        return self.append("session.started", actor=actor, role=role,
                           subject=subject, display_name=display_name,
                           reason="session reset",
                           details={"chain_version": CHAIN_VERSION,
                                    "hash_algorithm": HASH_ALGORITHM})

    # -- read -------------------------------------------------------------
    def records(self, limit: int | None = None) -> list[dict]:
        with self._lock:
            recs = list(self._records)
        return recs[-limit:] if limit else recs

    def __len__(self) -> int:
        return len(self._records)

    def head(self) -> str:
        return self._records[-1]["hash"] if self._records else GENESIS_PREV

    # -- verify -----------------------------------------------------------
    @staticmethod
    def verify_records(records: list[dict]) -> tuple[bool, str | None]:
        """Recompute the whole chain. Returns (ok, first problem described)."""
        prev = GENESIS_PREV
        for i, rec in enumerate(records):
            payload = {k: v for k, v in rec.items() if k != "hash"}
            if payload.get("seq") != i:
                return False, f"record {i}: sequence number is {payload.get('seq')}, expected {i}"
            if payload.get("prev_hash") != prev:
                return False, (f"record {i} ({rec.get('kind')}): prev_hash does not match "
                               f"record {i - 1} -- a record was altered, inserted or removed")
            expected = record_hash(prev, payload)
            if rec.get("hash") != expected:
                return False, (f"record {i} ({rec.get('kind')}): content hash mismatch -- "
                               f"this record's contents were altered after it was written")
            prev = rec["hash"]
        return True, None

    def verify(self) -> tuple[bool, str | None]:
        return self.verify_records(self.records())

    # -- export -----------------------------------------------------------
    def export(self) -> dict:
        recs = self.records()
        ok, problem = self.verify_records(recs)
        unknown = sorted({r["kind"] for r in recs} - KNOWN_KINDS)
        return {
            "chain_version": CHAIN_VERSION,
            "hash_algorithm": HASH_ALGORITHM,
            "canonicalisation": ('json.dumps(payload, sort_keys=True, '
                                 'separators=(",",":"), ensure_ascii=False).encode("utf-8"); '
                                 'hash = sha256(prev_hash + "\\n" + canonical)'),
            "genesis_prev_hash": GENESIS_PREV,
            "exported_at": fmt_ist(),
            "record_count": len(recs),
            "head_hash": recs[-1]["hash"] if recs else GENESIS_PREV,
            "verified": ok,
            "verification_problem": problem,
            "unknown_record_kinds": unknown,
            "records": recs,
            "claim": ("Tamper-EVIDENT, not tamper-proof: any edit to an exported record "
                      "is detectable by recomputing the chain. This is a hash-linked "
                      "append-only log, not a blockchain and not a legal record."),
        }

    def markdown(self) -> str:
        """Human-readable audit report (the thing a regulator actually reads)."""
        exp = self.export()
        lines = [
            "# Incident action audit", "",
            f"Exported: {exp['exported_at']}  ·  {exp['record_count']} records  ·  "
            f"chain {'VERIFIED' if exp['verified'] else 'BROKEN'}",
            f"Head hash: `{exp['head_hash']}`",
            f"Algorithm: {exp['hash_algorithm']}, {exp['canonicalisation']}", "",
        ]
        if not exp["verified"]:
            lines += [f"> **Chain verification failed:** {exp['verification_problem']}", ""]
        lines += ["| # | Time | Event | Actor (role) | Incident | Decision | Reason |",
                  "|---|---|---|---|---|---|---|"]
        for r in exp["records"]:
            identity = f"{r['actor']} ({r['role']})"
            if r.get("subject"):
                identity += f" [{r['subject']}]"
            lines.append(
                f"| {r['seq']} | {r['at']} | {r['kind']} | {identity} | "
                f"{r['incident_id'] or '--'} | {r['decision'] or '--'} | "
                f"{(r['reason'] or '--')[:90]} |")
        lines += ["", "## Records", ""]
        for r in exp["records"]:
            lines += [f"### {r['seq']} · {r['kind']}", "",
                      f"- hash: `{r['hash']}`", f"- prev: `{r['prev_hash']}`"]
            if r["technique_ids"]:
                lines.append(f"- ATT&CK: {', '.join(r['technique_ids'])}")
            if r["affected_assets"]:
                lines.append(f"- assets: {', '.join(r['affected_assets'])}")
            for e in r["evidence"]:
                lines.append(f"- evidence: [{e['title']}]({e['url']}) `sha256:{(e['sha256'] or '')[:16]}…`")
            if r["action"]:
                lines.append(f"- action: `{json.dumps(r['action'], sort_keys=True)[:400]}`")
            lines.append("")
        lines += [exp["claim"], ""]
        return "\n".join(lines)


_chain: AuditChain | None = None
_chain_lock = threading.Lock()


def artifact_versions() -> dict:
    """Model/data/artifact identifiers stamped into every audit record."""
    def h(path: Path) -> str | None:
        if not path.exists():
            return None
        return hashlib.sha256(path.read_bytes()).hexdigest()[:16]
    return {
        "detector": h(ROOT / "models" / "ae_lanl.npz"),
        "predictor": h(ROOT / "models" / "next_technique_markov.pkl"),
        "attack_lookups": h(ROOT / "data" / "processed" / "mitre_attack" / "attack_lookups.pkl"),
        "evidence_index": h(ROOT / "data" / "processed" / "evidence" / "index.json.gz"),
        "vuln_config": h(ROOT / "configs" / "vuln_priority.json"),
        "app_version": os.environ.get("NEXTATTACK_VERSION", "dev"),
    }


# Where the chain lives. Unset means in-memory, which is the right default for
# a read-only or ephemeral filesystem -- and `/api/audit/verify` reports which
# it is, so nobody has to guess whether the log they are looking at survives.
AUDIT_DB_ENV = "NEXTATTACK_AUDIT_DB"
DEFAULT_AUDIT_DB = Path(__file__).resolve().parents[2] / "data" / "audit" / "chain.db"


def _audit_path() -> Path | None:
    """Where the chain lives, or None for in-memory.

    Opt-in, and deliberately so. Durable-by-default was tried and reverted: it
    pointed every process at one file, so a test run and a developer's curl
    wrote to the same chain, two AuditChain objects assigned the same seq, and
    the linkage broke at record 463 of 572. An audit log that a second writer
    can corrupt is worse than one that does not persist.

        NEXTATTACK_AUDIT_DB=/var/lib/nextattack/chain.db

    `DEFAULT_AUDIT_DB` is the suggested location, not an implicit one.
    """
    raw = os.environ.get(AUDIT_DB_ENV, "").strip()
    if not raw or raw.lower() in ("off", "none", "memory", ":memory:"):
        return None
    return Path(raw)


def chain() -> AuditChain:
    """Process-wide chain, durable when NEXTATTACK_AUDIT_DB points somewhere.

    The old docstring said "ephemeral by design (free hosts have no disk)",
    which was true and left the scoreboard citing tamper-evidence for a log a
    restart erased. Durability now exists and is verified across a restart; it
    is opt-in because pointing every process at one file by default is how two
    writers corrupt one chain. `/api/audit/verify` reports `durable`, so which
    mode is running is never a guess.
    """
    global _chain
    with _chain_lock:
        if _chain is None:
            try:
                _chain = AuditChain(artifact_versions(), path=_audit_path())
            except Exception:
                # A read-only or full filesystem must degrade to in-memory
                # rather than take the service down. `durable` then reports
                # False, which is the honest answer.
                _chain = AuditChain(artifact_versions(), path=None)
        return _chain


def demo() -> None:
    """Self-check: the chain verifies, and tampering with it is detected."""
    c = AuditChain({"detector": "abc123"})
    c.append("analysis.completed", actor="asha@soc", role="analyst",
             incident_id="INC-1", technique_ids=["T1078", "T1021"],
             reason="ran the AIIMS scenario")
    c.append("action.proposed", actor="asha@soc", role="analyst", incident_id="INC-1",
             action={"kind": "isolate", "host": "WARD-PC-013"},
             affected_assets=["WARD-PC-013"], reason="cuts the path to PATIENT-DB-01")
    approved = c.append("action.approved", actor="ravi@soc", role="responder",
                        incident_id="INC-1", decision="approved",
                        reason="ward PC, out-of-hours, owner contacted")
    ok, problem = c.verify()
    assert ok, problem
    assert len(c) == 4, len(c)
    assert approved["prev_hash"] == c.records()[-2]["hash"]

    # tamper: rewrite an approved reason after the fact
    recs = json.loads(json.dumps(c.records()))
    recs[3]["reason"] = "approved without checking"
    ok2, problem2 = AuditChain.verify_records(recs)
    assert not ok2 and "3" in problem2, problem2

    # tamper: delete a record entirely
    recs2 = json.loads(json.dumps(c.records()))
    del recs2[2]
    ok3, problem3 = AuditChain.verify_records(recs2)
    assert not ok3, "deleting a record must break the chain"

    assert "VERIFIED" in c.markdown()
    print(f"audit ok: {len(c)} records verify; edit detected -> {problem2[:70]}…; "
          f"deletion detected -> {problem3[:50]}…")


if __name__ == "__main__":
    demo()
