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
from pydantic import BaseModel, ConfigDict, Field

from src.shared import audit as audit_mod
from src.shared import evidence as evidence_mod
from src.shared import proposals as proposal_mod
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
    """What the language-model layer is actually doing, right now.

    Derived from `src.shared.llm.status()` rather than from key presence.
    Those are different questions and this endpoint used to conflate them: it
    read GEMINI_API_KEY and reported egress whenever a key existed, so a
    developer .env carrying keys with the provider switched OFF was described as
    transmitting incident summaries off the host, and a host configured for
    OpenAI was reported as Google. The endpoint whose job is telling a reviewer
    the truth about the system was wrong in both directions.

    A key alone enables nothing. NEXTATTACK_LLM_PROVIDER has to select one too.
    """
    from src.shared import llm

    st = llm.status()
    active = st["active_provider"]
    if not active:
        keys = [name for name, p in st["providers"].items() if p["key_present"]]
        held = (f" Keys are present for {', '.join(keys)} but "
                f"NEXTATTACK_LLM_PROVIDER is '{st['requested']}', so no provider "
                f"is enabled and nothing is sent." if keys else "")
        return {
            "state": "none",
            "provider": "none",
            "keys_required": [],
            "in_decision_path": False,
            "data_leaves_host": False,
            "detail": (
                "No language model is enabled. Every score, ranking, gate and "
                "hash is deterministic Python, narratives come from templates, "
                "and no incident-derived content leaves this host." + held
            ),
        }

    model = st["providers"][active]["model"]
    vendor = {"openai": "OpenAI", "gemini": "Google"}.get(active, active)
    return {
        "state": "byok-narrative",
        "provider": f"{active}:{model}",
        "keys_required": [],
        "in_decision_path": False,
        "data_leaves_host": True,
        "detail": (
            f"NEXTATTACK_LLM_PROVIDER is '{st['requested']}' and {active} is "
            f"active ({model}): the advisor and the incident narrative may call "
            f"{vendor} to reword them, which TRANSMITS INCIDENT-DERIVED TEXT OFF "
            f"THIS HOST. The wording is labelled non-authoritative and no score, "
            f"ranking, gate or hash depends on it. Set NEXTATTACK_LLM_PROVIDER=off "
            f"to disable."
        ),
    }


def _baseline_capability() -> dict:
    """Whether features come from per-entity history or from the uploaded file.

    This is the single biggest thing a reader should know about a score, so it
    is reported rather than inferred. Off is the default and the honest one
    today: every published metric was measured on file-local features, and
    switching modes silently would make `reports/` describe a product that is
    no longer running.
    """
    from src.shared import baseline

    st = baseline.status()
    return {
        "state": st.get("state", "off"),
        "detail": st.get("detail", ""),
        "days_of_history": st.get("days"),
        "accounts": st.get("users"),
        "events": st.get("events"),
        "minimum_history_days": st.get("min_history_days"),
        "learning_progress_percent": st.get("progress_percent"),
        "operational_alerts_enabled": st.get("allow_operational_alerts"),
        "network_required": False,
        "note": ("With no baseline, `new host for this account` means first in "
                 "THIS file, so a clean log still alerts on up to 48.2% of "
                 "events -- measured, in reports/clean_log.md. A store makes it "
                 "mean first ever. Published metrics were measured in the "
                 "file-local mode, so it stays the default until they are "
                 "re-run."),
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
        "entity_baseline": _baseline_capability(),
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

    # Proposals become approvable only after the server binds their immutable
    # action, policy and evidence context to an opaque id. The browser receives
    # the id but never becomes the source of any decision input.
    graph = result["signals"]["graph"]
    evidence = result["evidence"].get("citations") or []
    input_digest = proposal_mod.digest({
        "incident": inc,
        "graph": graph,
        "evidence": evidence,
        "scenario": req.scenario,
        "events": result["understand"]["n_events"],
    })
    issued = []
    try:
        for action in result["action"].get("proposals") or []:
            server_proposal = proposal_mod.store().issue(
                incident_id=inc["incident_id"],
                action=action,
                input_digest=input_digest,
                evidence=evidence,
                technique_ids=inc["technique_ids"],
                affected_assets=graph["critical_assets_at_risk"],
            )
            issued.append(server_proposal)
            c.append(
                "action.proposed", actor=p["actor"], role=p["role"],
                incident_id=inc["incident_id"], action=server_proposal,
                evidence=evidence, technique_ids=inc["technique_ids"],
                affected_assets=graph["critical_assets_at_risk"],
                reason="server-issued simulated response proposal",
                details={
                    "proposal_id": server_proposal["proposal_id"],
                    "proposal_digest": server_proposal["proposal_digest"],
                    "input_digest": input_digest,
                    "policy_version": server_proposal["policy_version"],
                    "expires_at": server_proposal["expires_at"],
                    "store_durable": proposal_mod.store().durable,
                },
            )
    except Exception as exc:
        raise HTTPException(503, f"could not register response proposals: {exc}")
    result["action"]["proposals"] = issued
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
    require_llm: bool = False
    assistant_mode: str = "incident"


class AgentInvestigateRequest(BaseModel):
    scenario: str | None = None
    events: list[dict] | None = None
    critical_assets: list[str] = Field(default_factory=list)
    incident_id: str = "INC-LIVE-001"


@router.post("/agents/reason")
def agents_reason(req: AgentInvestigateRequest, p: dict = Depends(principal)):
    """Investigator and Critic over the graph tools. Advisory, never authoritative.

    ADR 0007 holds: the workflow decides, this lane comments. What makes it worth
    running is that the two are built differently -- the workflow follows a fixed
    seven-node path, this one lets a model choose which of seven graph questions
    to ask next, then puts a second model on refuting the answer.

    Citations are filtered against tool output in `agent_loop`, so a hypothesis
    that cites evidence it never saw arrives here with an empty `evidence_ids`
    and zero confidence. That has already happened on a live run, which is the
    reason the filter is code rather than a line in the prompt.
    """
    _require(p, "read")
    # The costliest route in the service: up to fourteen provider calls, on a
    # shared per-minute quota, with retries. One caller must not be able to
    # spend everyone else's budget.
    from api.main import _limit
    _limit(p, "agents")
    from src.shared.agent_loop import investigate_with_agents
    from src.shared.workflow import investigate as run

    df = pd.DataFrame(req.events) if req.events else None
    if df is None and not req.scenario:
        raise HTTPException(422, "provide either 'scenario' or 'events'")

    crit = list(req.critical_assets)
    if req.scenario and not crit:
        from api.main import SCENARIO_META
        crit = SCENARIO_META.get(req.scenario, {}).get("critical_default", [])

    result = run(df=df, scenario=req.scenario, critical_assets=crit,
                 incident_id=req.incident_id, principal=p, evidence_k=1)
    if not result.get("ok"):
        raise HTTPException(422, result.get("error", "investigation failed"))

    # The agents read the finished analysis. They do not re-run detection, so
    # nothing they say can change a score -- only comment on one.
    bundle = {**result["signals"], "meta": result["meta"],
              "claims": result["impact"].get("claims") or []}
    out = investigate_with_agents(bundle)

    inc = result["signals"]["incident"]
    audit_mod.chain().append(
        "agents.reasoned", actor=p["actor"], role=p["role"],
        incident_id=inc["incident_id"], technique_ids=out.get("techniques") or [],
        reason="advisory agent lane run over the graph tools",
        details={"provider": out.get("provider"),
                 "tool_calls": len(out.get("tool_calls") or []),
                 "cited": len(out.get("evidence_ids") or []),
                 "rejected_citations": len(out.get("rejected_citations") or []),
                 "refuted": out.get("refuted"), "authoritative": False})
    out["incident_id"] = inc["incident_id"]
    out["workflow_severity"] = inc.get("severity")
    out["workflow_techniques"] = inc.get("technique_ids") or []
    return out


@router.post("/twin/chat")
def twin_chat(req: TwinChatRequest, p: dict = Depends(principal)):
    """Digital Twin AI Advisor: plain-language RAG chatbot for non-technical stakeholders."""
    _require(p, "read")
    from src.shared.chat_advisor import ask_advisor
    reply = ask_advisor(
        req.message,
        history=req.history,
        graph=req.graph,
        scenario=req.scenario,
        incident_id=req.incident_id,
        assistant_mode=("general" if req.assistant_mode == "general" else "incident"),
    )
    if req.require_llm and reply.get("method") == "deterministic":
        detail = reply.get("llm_error") or (reply.get("llm") or {}).get("note")
        raise HTTPException(503, detail or "The configured language model is unavailable.")
    return reply


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
        # _score returns (scores, calibration); the calibration block records
        # whether the shipped anchors applied or the log was scored by rank.
        df["anomaly_score"] = _score(df)[0].astype(int)
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
    model_config = ConfigDict(extra="forbid")

    proposal_id: str = Field(min_length=10, max_length=128)
    decision: str                      # "approve" | "reject"
    reason: str = ""


@router.post("/actions/approve")
def approve(req: ApprovalRequest, p: dict = Depends(principal)):
    """Record a human decision on a simulated action. Nothing is executed."""
    decision = req.decision.strip().lower()
    if decision not in ("approve", "reject"):
        raise HTTPException(422, "decision must be 'approve' or 'reject'")

    try:
        stored = proposal_mod.store().get(req.proposal_id)
    except proposal_mod.ProposalNotFound as exc:
        raise HTTPException(404, str(exc))
    except proposal_mod.ProposalIntegrityError as exc:
        raise HTTPException(409, str(exc))

    action = stored["action"]
    policy = action.get("policy")
    if not isinstance(policy, dict) or not policy.get("required_permission"):
        raise HTTPException(409, "stored proposal has no valid server policy")
    incident_id = stored["incident_id"]
    _require(p, policy["required_permission"], incident_id=incident_id)

    if decision == "approve" and policy["requires_approval"] and not req.reason.strip():
        audit_mod.chain().append(
            "action.denied", actor=p["actor"], role=p["role"],
            incident_id=incident_id, decision="rejected-by-policy",
            action=action, reason="approval attempted without a written reason",
            details={"policy": policy, "proposal_id": req.proposal_id,
                     "proposal_digest": stored["proposal_digest"]})
        raise HTTPException(422, "this action requires a written reason for approval")

    try:
        decided = proposal_mod.store().decide(
            req.proposal_id,
            decision=decision,
            actor=p["actor"],
            role=p["role"],
            reason=req.reason.strip() or "(no reason given)",
        )
    except proposal_mod.ProposalExpired as exc:
        raise HTTPException(410, str(exc))
    except proposal_mod.ProposalAlreadyDecided as exc:
        raise HTTPException(409, str(exc))
    except proposal_mod.ProposalIntegrityError as exc:
        raise HTTPException(409, str(exc))

    rec = audit_mod.chain().append(
        "action.approved" if decision == "approve" else "action.rejected",
        actor=p["actor"], role=p["role"], incident_id=incident_id,
        action={**action, "policy": policy, "executed": False},
        decision="approved" if decision == "approve" else "rejected",
        reason=req.reason.strip() or "(no reason given)",
        evidence=decided["evidence"], technique_ids=decided["technique_ids"],
        affected_assets=decided["affected_assets"],
        details={"simulated": True, "auth_mode": p["auth_mode"],
                 "authenticated": p["authenticated"],
                 "proposal_id": req.proposal_id,
                 "proposal_digest": decided["proposal_digest"],
                 "input_digest": decided["input_digest"],
                 "policy_version": decided["policy_version"],
                 "store_durable": proposal_mod.store().durable})
    return {
        "recorded": True,
        "executed": False,
        "decision": rec["decision"],
        "proposal_id": req.proposal_id,
        "proposal_digest": decided["proposal_digest"],
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
    c = audit_mod.chain()
    ok, problem = c.verify()
    return {"verified": ok, "problem": problem, "records": len(c),
            "hash_algorithm": audit_mod.HASH_ALGORITHM,
            # Whether this log survives a restart. Reported rather than assumed:
            # tamper DETECTION always worked, but the chain used to live only in
            # process memory, so the retention half of the claim was not true and
            # nothing said so.
            "durable": c.durable,
            "claim": ("tamper-evident, not tamper-proof; retained across restarts"
                      if c.durable else
                      "tamper-evident within this process only -- NOT retained "
                      "across a restart. Set NEXTATTACK_AUDIT_DB to a path to "
                      "persist it. Opt-in on purpose: one shared default file "
                      "let two writers assign the same sequence number and "
                      "broke a 572-record chain at record 463.")}


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
