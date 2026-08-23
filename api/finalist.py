"""Finalist API surface: investigation workflow, evidence, vulnerabilities,
digital twin, explainability, RBAC-gated approvals, audit chain and scoreboard.

Kept in its own router so `api/main.py` stays the deployment shim (cache, live
analysis, SPA) and this file owns the PS7 decision surface. Registered before the
SPA catch-all in `main.py`, otherwise the catch-all would shadow every GET here.

Two rules hold across every route in this file:
  * authorisation is enforced HERE, server-side, on every mutating endpoint —
    hiding a button in the SPA is not access control;
  * no route contacts, changes or executes anything on an external system.
"""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
from fastapi import APIRouter, Depends, Header, HTTPException, Response
from pydantic import BaseModel, Field

from src.shared import audit as audit_mod
from src.shared import evidence as evidence_mod
from src.shared import rbac

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "data" / "demo" / "scenarios"
CACHE = ROOT / "api" / "cache"

router = APIRouter(prefix="/api")


# --------------------------------------------------------------------------- #
# principal                                                                    #
# --------------------------------------------------------------------------- #
def principal(x_role: str | None = Header(default=None, alias="X-Role"),
              x_actor: str | None = Header(default=None, alias="X-Actor"),
              authorization: str | None = Header(default=None)) -> dict:
    try:
        return rbac.resolve_principal(x_role, x_actor, authorization)
    except rbac.AuthError as e:
        raise HTTPException(401, str(e))


def _require(p: dict, permission: str, *, incident_id: str | None = None) -> None:
    """Authorise, and record the refusal in the audit chain when it is one."""
    try:
        rbac.require(p, permission)
    except rbac.Denied as e:
        audit_mod.chain().append(
            "action.denied", actor=p["actor"], role=p["role"], incident_id=incident_id,
            decision="denied", reason=str(e),
            details={"permission": permission, "auth_mode": p["auth_mode"]})
        raise HTTPException(403, str(e))


# --------------------------------------------------------------------------- #
# capability + readiness                                                       #
# --------------------------------------------------------------------------- #
def _llm_capability() -> dict:
    """No LLM touches a decision. One optional path rewords a narrative.

    If it is switched on it sends incident summaries to Google, so this reports
    the egress explicitly rather than describing the product as offline while a
    key is quietly set.
    """
    import os

    key_set = bool(os.environ.get("GEMINI_API_KEY", "").strip())
    return {
        "state": "byok-narrative" if key_set else "none",
        "provider": "gemini-1.5-flash" if key_set else "none",
        "keys_required": [],
        "in_decision_path": False,
        "data_leaves_host": key_set,
        "detail": (
            "GEMINI_API_KEY is set: the 10-agent pipeline may call Google to reword "
            "the incident narrative, which TRANSMITS INCIDENT SUMMARIES OFF THIS "
            "HOST. The text is labelled non-authoritative and no score, ranking, "
            "gate or hash depends on it. Unset the variable to disable."
            if key_set else
            "No LLM is configured. Every score, ranking, gate and hash is "
            "deterministic Python, narratives come from templates, and no "
            "incident-derived content leaves this host."),
    }


def _capabilities() -> dict:
    from src.shared import detector

    ev_ok = evidence_mod.available()
    ev_stats = {}
    if ev_ok:
        try:
            ev_stats = evidence_mod.repository().stats()
        except Exception as e:                       # a corrupt artifact must not 500
            ev_ok, ev_stats = False, {"error": str(e)[:160]}
    inv = ROOT / "data" / "demo" / "scenarios" / "asset_inventory.json"
    metrics = ROOT / "reports" / "metrics.json"

    return {
        "detection": {
            "state": "live" if detector.available() else "degraded",
            "detail": ("benign-trained autoencoder (NumPy inference)"
                       if detector.available() else
                       "autoencoder artifact missing — falling back to IsolationForest, "
                       "which catches materially fewer red-team events at 1% FPR"),
        },
        "evidence": {
            "state": "bundled" if ev_ok else "unavailable",
            "detail": (f"{ev_stats.get('chunks', 0)} official chunks, built "
                       f"{ev_stats.get('built_at', 'unknown')}" if ev_ok else
                       "run python -m scripts.build_evidence_index"),
            "corpus": ev_stats.get("by_publisher", {}),
            "network_required": False,
            # Which retriever is actually answering. Semantic when the vector
            # store and its dependencies are present, lexical otherwise -- the
            # slim deploy image ships neither, and still works.
            "backend": evidence_mod.active_backend(),
            "backend_detail": (
                "MiniLM + ChromaDB over 3,692 chunks (measured recall@5 1.00, "
                "MRR 0.85 on the gold set)"
                if evidence_mod.active_backend() == "semantic" else
                "BM25 + exact-identifier boost over the bundled index "
                "(measured recall@5 0.80, MRR 0.68). The semantic backend is not "
                "installed; build it with python -m src.retrieval.ingest && "
                "python -m src.retrieval.embed"),
        },
        "vulnerability_prioritisation": {
            "state": "bundled" if inv.exists() else "unavailable",
            "detail": ("CISA KEV facts from the bundled index, matched against a supplied "
                       "asset inventory. Host software is never guessed."),
        },
        "threat_radar": {
            "state": "cache-first",
            "detail": ("Free CTI feeds, fetched only on explicit refresh through the "
                       "host-allowlisted fetcher. Falls back to the bundled snapshot."),
            "network_required": True, "optional": True,
        },
        "llm": _llm_capability(),
        "authorisation": {
            "state": rbac.auth_mode(),
            "roles": list(rbac.ROLES),
            "detail": ("Bearer tokens configured via NEXTATTACK_ROLE_TOKENS."
                       if rbac.auth_mode() == "bearer-tokens" else
                       "DEMO MODE: the caller declares a role in X-Role. This is "
                       "authorisation without authentication — deliberately, so a judge "
                       "can switch roles with no signup. Set NEXTATTACK_ROLE_TOKENS to "
                       "require bearer tokens."),
        },
        "audit": {
            "state": "session-scoped",
            "detail": ("Hash-linked append-only chain held in memory and exportable. "
                       "Tamper-evident, not tamper-proof; not persisted across restarts "
                       "because free hosts have an ephemeral filesystem."),
            "records": len(audit_mod.chain()),
            "head": audit_mod.chain().head(),
        },
        "metrics": {
            "state": "bundled" if metrics.exists() else "unavailable",
            "detail": "reports/metrics.json — written by the evaluation scripts",
        },
        "sample_cache": {
            "state": "built" if (CACHE / "overview.json").exists() else "missing",
            "detail": "a real analysis of a shipped scenario, served when nothing is live",
        },
    }


@router.get("/capabilities")
def capabilities():
    caps = _capabilities()
    degraded = [k for k, v in caps.items()
                if v.get("state") in ("degraded", "unavailable", "missing")]
    return {
        "capabilities": caps,
        "degraded": degraded,
        "usable_offline": True,
        "keys_required": [],
        "versions": audit_mod.artifact_versions(),
        "note": ("Everything required runs with no API key, no account and no network. "
                 "Optional components report themselves unavailable rather than "
                 "pretending."),
    }


@router.get("/readiness")
def readiness(response: Response):
    """Is the service ready to serve a demo? Names what is missing if not."""
    required = {
        "detector": (ROOT / "models" / "ae_lanl.npz").exists()
                    or (ROOT / "models" / "iforest_lanl.joblib").exists(),
        "attack_lookups": (ROOT / "data" / "processed" / "mitre_attack"
                           / "attack_lookups.pkl").exists(),
        "predictor": (ROOT / "models" / "next_technique_markov.pkl").exists(),
        "score_ref": (CACHE / "score_ref.json").exists(),
        "scenarios": any(SCENARIOS.glob("*.csv")),
    }
    optional = {
        "evidence_index": evidence_mod.available(),
        "sample_cache": (CACHE / "overview.json").exists(),
        "metrics": (ROOT / "reports" / "metrics.json").exists(),
        "asset_inventory": (SCENARIOS / "asset_inventory.json").exists(),
    }
    ready = all(required.values())
    if not ready:
        response.status_code = 503
    return {
        "ready": ready,
        "required": required,
        "optional": optional,
        "missing_required": [k for k, v in required.items() if not v],
        "degraded_optional": [k for k, v in optional.items() if not v],
        "hint": ("run python -m scripts.build_cache and "
                 "python -m scripts.build_evidence_index" if not ready else None),
    }


# --------------------------------------------------------------------------- #
# investigation                                                                #
# --------------------------------------------------------------------------- #
class InvestigateRequest(BaseModel):
    scenario: str | None = None
    events: list[dict] | None = None
    critical_assets: list[str] = Field(default_factory=list)
    incident_id: str = "INC-LIVE-001"
    account: str | None = None
    evidence_k: int = 6


@router.post("/investigate")
def investigate(req: InvestigateRequest, p: dict = Depends(principal)):
    """Run the seven-node investigation and record it in the audit chain."""
    _require(p, "analyze", incident_id=req.incident_id)
    from src.shared.workflow import investigate as run

    df = None
    if req.events:
        df = pd.DataFrame(req.events)
    elif not req.scenario:
        raise HTTPException(422, "provide either 'scenario' or 'events'")

    crit = list(req.critical_assets)
    if req.scenario and not crit:
        from api.main import SCENARIO_META
        crit = SCENARIO_META.get(req.scenario, {}).get("critical_default", [])
    try:
        result = run(df=df, scenario=req.scenario, critical_assets=crit,
                     incident_id=req.incident_id, account=req.account,
                     principal=p, evidence_k=max(1, min(req.evidence_k, 20)))
    except ValueError as e:
        raise HTTPException(422, str(e))
    if not result.get("ok"):
        raise HTTPException(422, result.get("error", "investigation failed"))

    inc = result["signals"]["incident"]
    c = audit_mod.chain()
    c.append("analysis.completed", actor=p["actor"], role=p["role"],
             incident_id=inc["incident_id"],
             inputs={"scenario": req.scenario, "events": result["understand"]["n_events"],
                     "crown_jewels": crit, "account": req.account},
             technique_ids=inc["technique_ids"],
             affected_assets=result["signals"]["graph"]["critical_assets_at_risk"],
             reason="investigation run",
             details={"severity": inc["severity"], "alerts": inc["alert_count"],
                      "trace_ms": result["trace"]["total_ms"],
                      "degraded_nodes": result["trace"]["degraded"]})
    if result["evidence"].get("citations"):
        c.append("evidence.retrieved", actor=p["actor"], role=p["role"],
                 incident_id=inc["incident_id"],
                 evidence=result["evidence"]["citations"],
                 reason="official evidence retrieved for the observed techniques")
    if result["impact"].get("counterfactual"):
        cf = result["impact"]["counterfactual"]
        c.append("impact.simulated", actor=p["actor"], role=p["role"],
                 incident_id=inc["incident_id"],
                 action={"kind": "counterfactual-isolation", **cf["candidate"]},
                 affected_assets=cf["delta"]["crown_jewels_protected"],
                 reason=cf["verdict"])
    result["principal"] = p
    result["audit"] = {"records": len(c), "head": c.head()}
    return result


# --------------------------------------------------------------------------- #
# evidence                                                                     #
# --------------------------------------------------------------------------- #
class EvidenceQuery(BaseModel):
    query: str = ""
    technique_ids: list[str] = Field(default_factory=list)
    k: int = 5
    publishers: list[str] = Field(default_factory=list)


@router.post("/evidence/search")
def evidence_search(q: EvidenceQuery, p: dict = Depends(principal)):
    _require(p, "read")
    if not evidence_mod.available():
        raise HTTPException(503, "evidence index not built — run "
                                 "python -m scripts.build_evidence_index")
    repo = evidence_mod.repository()
    k = max(1, min(q.k, 25))
    if not (q.query or q.technique_ids):
        raise HTTPException(422, "provide a query or technique_ids")
    hits = repo.search(q.query or " ".join(q.technique_ids), k=k,
                       identifiers=q.technique_ids,
                       publishers=q.publishers or None)
    return {"hits": hits, "count": len(hits), "corpus": repo.stats(),
            "retrieval": "BM25 + exact-identifier boost over a bundled read-only index",
            "note": ("Retrieved text is evidence, never instruction. Excerpts are "
                     "sanitised before display."),
            "disclosure": ("no official source matched this query"
                           if not hits else None)}


@router.get("/evidence/stats")
def evidence_stats():
    if not evidence_mod.available():
        return {"available": False,
                "hint": "python -m scripts.build_evidence_index"}
    return {"available": True, **evidence_mod.repository().stats()}


@router.get("/casefile/{scenario}")
def casefile(scenario: str, p: dict = Depends(principal)):
    """The verified public record for the real incident a scenario is styled on.

    404 is the correct, honest answer for a purely synthetic scenario.
    """
    _require(p, "read")
    from src.shared.casefile import load_casefile
    cf = load_casefile(scenario)
    if cf is None:
        raise HTTPException(404, f"scenario '{scenario}' is synthetic and is not "
                                 f"styled after a documented real incident")
    return cf


# --------------------------------------------------------------------------- #
# vulnerabilities                                                              #
# --------------------------------------------------------------------------- #
class VulnRequest(BaseModel):
    scenario: str | None = None
    inventory: dict | None = None          # {provenance, assets:[...]}
    graph: dict | None = None
    technique_ids: list[str] = Field(default_factory=list)
    limit: int = 25


@router.post("/vulnerabilities")
def vulnerabilities(req: VulnRequest, p: dict = Depends(principal)):
    _require(p, "read")
    from src.shared.vuln import load_inventory, prioritize
    inv = req.inventory or load_inventory(req.scenario)
    if not inv.get("assets"):
        return {"findings": [], "total_findings": 0, "assets_considered": 0,
                "inventory_provenance": inv.get("provenance", "NOT_PROVIDED"),
                "inventory_note": inv.get("note", ""),
                "disclosure": ("Vulnerability prioritisation needs an asset inventory "
                               "(host → software, criticality, owner). We do not guess "
                               "what software a host runs.")}
    return prioritize(inv, req.graph or {}, req.technique_ids,
                      limit=max(1, min(req.limit, 100)))


@router.get("/vulnerabilities/config")
def vuln_config(p: dict = Depends(principal)):
    _require(p, "read")
    from src.shared.vuln import load_config
    cfg = load_config()
    return {k: v for k, v in cfg.items() if not k.startswith("_")}


# --------------------------------------------------------------------------- #
# digital twin                                                                 #
# --------------------------------------------------------------------------- #
class TwinRequest(BaseModel):
    graph: dict
    isolate_host: str | None = None
    cut_edge: list[str] | None = None


@router.post("/twin/simulate")
def twin_simulate(req: TwinRequest, p: dict = Depends(principal)):
    _require(p, "simulate")
    from src.shared.twin import simulate
    try:
        return simulate(req.graph, isolate_host=req.isolate_host, cut_edge=req.cut_edge)
    except ValueError as e:
        raise HTTPException(422, str(e))


class TwinRankRequest(BaseModel):
    graph: dict
    limit: int = 5


@router.post("/twin/candidates")
def twin_candidates(req: TwinRankRequest, p: dict = Depends(principal)):
    _require(p, "simulate")
    from src.shared.twin import rank_candidates
    return {"candidates": rank_candidates(req.graph, limit=max(1, min(req.limit, 25))),
            "ordering": ("crown jewels protected, then blast-radius reduction, then the "
                         "LOWEST operational cost — never a bigger outage for the same "
                         "security benefit"),
            "simulated": True}


class TwinChatRequest(BaseModel):
    message: str
    history: list[dict] = Field(default_factory=list)
    scenario: str | None = None
    incident_id: str = "INC-LIVE-001"
    graph: dict | None = None


@router.post("/twin/chat")
def twin_chat(req: TwinChatRequest, p: dict = Depends(principal)):
    """Digital Twin AI Advisor: plain-language RAG chatbot for non-technical stakeholders."""
    _require(p, "read")
    from src.shared.chat_advisor import ask_advisor
    return ask_advisor(
        req.message,
        history=req.history,
        graph=req.graph,
        scenario=req.scenario,
        incident_id=req.incident_id,
    )


# --------------------------------------------------------------------------- #
# explainability                                                               #
# --------------------------------------------------------------------------- #
class ExplainRequest(BaseModel):
    scenario: str | None = None
    events: list[dict] | None = None
    critical_assets: list[str] = Field(default_factory=list)
    step_index: int = 0


@router.post("/explain")
def explain(req: ExplainRequest, p: dict = Depends(principal)):
    """Full raw-event → action provenance chain for one alert."""
    _require(p, "read")
    from src.engine1.lanl_detect import engineer
    from src.schema import coerce
    from src.shared.explain import explain_step
    from src.shared.live_analyze import _score, analyze_events

    if req.events:
        raw = pd.DataFrame(req.events)
    elif req.scenario:
        path = SCENARIOS / f"{req.scenario}.csv"
        if not path.exists():
            raise HTTPException(404, f"unknown scenario '{req.scenario}'")
        raw = pd.read_csv(path)
    else:
        raise HTTPException(422, "provide either 'scenario' or 'events'")

    try:
        bundle = analyze_events(raw.copy(), critical_assets=set(req.critical_assets))
        df = engineer(coerce(raw.copy()))
        df["anomaly_score"] = _score(df).round().astype(int)
    except ValueError as e:
        raise HTTPException(422, str(e))

    cites = []
    if evidence_mod.available():
        cites = evidence_mod.repository().for_techniques(
            bundle["incident"]["technique_ids"], k_each=1)
    return explain_step(df, bundle, req.step_index, citations=cites)


# --------------------------------------------------------------------------- #
# actions: propose is free, approving is not                                   #
# --------------------------------------------------------------------------- #
class ApprovalRequest(BaseModel):
    incident_id: str
    action: dict                       # the proposal, as returned by /investigate
    decision: str                      # "approve" | "reject"
    reason: str = ""
    affected_assets: list[str] = Field(default_factory=list)
    evidence: list[dict] = Field(default_factory=list)
    technique_ids: list[str] = Field(default_factory=list)


@router.post("/actions/approve")
def approve(req: ApprovalRequest, p: dict = Depends(principal)):
    """Record a human decision on a simulated action. Nothing is executed."""
    decision = req.decision.strip().lower()
    if decision not in ("approve", "reject"):
        raise HTTPException(422, "decision must be 'approve' or 'reject'")

    policy = rbac.policy_for(req.action)
    _require(p, policy["required_permission"], incident_id=req.incident_id)

    if decision == "approve" and policy["requires_approval"] and not req.reason.strip():
        audit_mod.chain().append(
            "action.denied", actor=p["actor"], role=p["role"],
            incident_id=req.incident_id, decision="rejected-by-policy",
            action=req.action, reason="approval attempted without a written reason",
            details={"policy": policy})
        raise HTTPException(422, "this action requires a written reason for approval")

    rec = audit_mod.chain().append(
        "action.approved" if decision == "approve" else "action.rejected",
        actor=p["actor"], role=p["role"], incident_id=req.incident_id,
        action={**req.action, "policy": policy, "executed": False},
        decision="approved" if decision == "approve" else "rejected",
        reason=req.reason.strip() or "(no reason given)",
        evidence=req.evidence, technique_ids=req.technique_ids,
        affected_assets=req.affected_assets,
        details={"simulated": True, "auth_mode": p["auth_mode"],
                 "authenticated": p["authenticated"]})
    return {
        "recorded": True,
        "executed": False,
        "decision": rec["decision"],
        "policy": policy,
        "record": {
            "seq": rec["seq"],
            "hash": rec["hash"],
            "at": rec["at"],
            "actor": rec["actor"],
            "role": rec["role"],
        },
        "chain": {"records": len(audit_mod.chain()), "head": audit_mod.chain().head()},
        "note": ("SIMULATION ONLY. The decision is recorded in the tamper-evident audit "
                 "chain; no external system was contacted."),
    }


# --------------------------------------------------------------------------- #
# audit                                                                        #
# --------------------------------------------------------------------------- #
@router.get("/audit")
def audit_records(limit: int = 100, p: dict = Depends(principal)):
    _require(p, "read")
    c = audit_mod.chain()
    ok, problem = c.verify()
    return {"records": c.records(limit=max(1, min(limit, 500))),
            "count": len(c), "head": c.head(),
            "verified": ok, "problem": problem}


@router.get("/audit/verify")
def audit_verify(p: dict = Depends(principal)):
    _require(p, "verify_audit")
    ok, problem = audit_mod.chain().verify()
    return {"verified": ok, "problem": problem, "records": len(audit_mod.chain()),
            "hash_algorithm": audit_mod.HASH_ALGORITHM,
            "claim": "tamper-evident, not tamper-proof"}


@router.post("/audit/verify-export")
def audit_verify_export(export: dict, p: dict = Depends(principal)):
    """Re-verify an audit export someone hands you. Proves the chain travels."""
    _require(p, "verify_audit")
    recs = export.get("records")
    if not isinstance(recs, list):
        raise HTTPException(422, "export must contain a 'records' list")
    if len(recs) > audit_mod.MAX_RECORDS:
        raise HTTPException(422, f"too many records (max {audit_mod.MAX_RECORDS})")
    ok, problem = audit_mod.AuditChain.verify_records(recs)
    return {"verified": ok, "problem": problem, "records": len(recs)}


@router.get("/audit/export")
def audit_export(p: dict = Depends(principal)):
    _require(p, "export_audit")
    exp = audit_mod.chain().export()
    audit_mod.chain().append("audit.exported", actor=p["actor"], role=p["role"],
                             reason="audit chain exported as JSON",
                             details={"records": exp["record_count"]})
    return exp


@router.get("/audit/export.md")
def audit_export_md(p: dict = Depends(principal)):
    _require(p, "export_audit")
    md = audit_mod.chain().markdown()
    audit_mod.chain().append("report.exported", actor=p["actor"], role=p["role"],
                             reason="audit chain exported as Markdown")
    return Response(md, media_type="text/markdown; charset=utf-8",
                    headers={"Content-Disposition":
                             'attachment; filename="incident-audit.md"'})


@router.post("/audit/reset")
def audit_reset(p: dict = Depends(principal)):
    """One-click demo reset. Export first if you want to keep the chain."""
    _require(p, "reset_session")
    rec = audit_mod.chain().reset(actor=p["actor"], role=p["role"])
    return {"reset": True, "records": len(audit_mod.chain()), "head": rec["hash"]}


# --------------------------------------------------------------------------- #
# scoreboard                                                                   #
# --------------------------------------------------------------------------- #
@router.get("/scoreboard")
def scoreboard():
    from src.shared.scoreboard import scoreboard as build
    try:
        return build()
    except FileNotFoundError as e:
        raise HTTPException(503, f"metrics store missing: {e}")


@router.get("/report/{incident_id}/audit.json")
def incident_audit(incident_id: str, p: dict = Depends(principal)):
    """The audit records for one incident, hash-linked and verifiable."""
    _require(p, "export_audit")
    exp = audit_mod.chain().export()
    recs = [r for r in exp["records"] if r.get("incident_id") == incident_id]
    return {**exp, "records": recs, "filtered_to_incident": incident_id,
            "note": ("Filtered view. Verify the FULL export — a subset cannot be "
                     "chain-verified on its own, by design."),
            "verified": None}


__all__ = ["router"]
