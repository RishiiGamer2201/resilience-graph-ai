"""
M5.1 — nextATT&CKs · SOC Command Center API (FastAPI).

Serves the pre-computed cache (fast, reliable) plus two genuinely LIVE endpoints:
  POST /api/score-event    — behavioral features → live anomaly score + severity
  POST /api/predict-next   — partial ATT&CK chain → live next-technique prediction

Cached GETs are just JSON files built by `scripts/build_cache.py`.

Run:
    ./.venv/Scripts/python.exe -m uvicorn api.main:app --reload --port 8000
"""
from __future__ import annotations

import io
import json
import threading
import os
import pickle
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from fastapi import Depends, FastAPI, Header, HTTPException, UploadFile, File, Form
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# One RBAC implementation for the whole service. `api/finalist.py` already owns
# the principal resolution and the deny-and-audit helper; importing them here
# means there is exactly one place where "who is calling?" and "is that allowed?"
# are answered, rather than a second copy that drifts.
from api.finalist import principal as _finalist_principal, _require

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / "api" / "cache"
LANL_MODEL = ROOT / "models" / "iforest_lanl.joblib"
MARKOV = ROOT / "models" / "next_technique_markov.pkl"
LOOKUPS = ROOT / "data" / "processed" / "mitre_attack" / "attack_lookups.pkl"
SCENARIOS = ROOT / "data" / "demo" / "scenarios"


def _default_critical() -> list[str]:
    """Crown jewels derived in export_demo_events (hosts most accounts depend on).
    LANL has no criticality labels, so this is a stated heuristic, not ground truth."""
    f = SCENARIOS / "critical_assets.json"
    if f.exists():
        return [a["host"] for a in json.loads(f.read_text())["assets"]]
    return []

_DEFAULT_CRIT = _default_critical()

# Human labels for the shipped demo scenarios (files live in SCENARIOS/).
SCENARIO_META = {
    "lanl_campaign_all": {
        "label": "LANL red-team campaign — all 104 accounts (real)",
        "description": "The full campaign: 2,732 auth events covering every compromised "
                       "account (702 red-team events) from the attacker's 4 pivot hosts. "
                       "The default view.",
        "critical_default": _DEFAULT_CRIT,
    },
    "lanl_redteam_u66": {
        "label": "LANL red-team — single account U66 (real)",
        "description": "215 events from one compromised account's pivot — the narrow "
                       "view, useful for a focused walkthrough.",
        "critical_default": _DEFAULT_CRIT,
    },
    "aiims_ransomware": {
        "label": "AIIMS-style hospital ransomware (India · synthetic)",
        "description": "Synthetic auth log styled after the AIIMS Delhi 2022 ransomware "
                       "attack: a phished ward PC pivots across the hospital to the patient "
                       "database and domain controller. Concrete Indian-CNI scenario.",
        "critical_default": ["PATIENT-DB-01", "DC-AIIMS-01"],
    },
    "cbse_exam_breach": {
        "label": "CBSE-style exam-board breach (India · synthetic)",
        "description": "Synthetic auth log styled after an Indian education-board attack: "
                       "a phished office PC pivots to the exam-paper server, results database "
                       "and student-data store — paper leak / result tampering.",
        "critical_default": ["EXAM-PAPERS-SRV-01", "RESULTS-DB-01", "STUDENT-DATA-DB-01", "DC-CBSE-01"],
    },
}

FEATURES = ["is_fail", "new_dst_for_user", "new_src_for_user",
            "user_distinct_dst_sofar", "user_fail_rate_sofar", "dst_rarity", "is_ntlm"]

# Trust boundary: the largest upload body we will hold in memory at all.
#
# `MAX_ROWS` in src/shared/live_analyze is a *row* cap, and it is only reached
# after pandas has already parsed the entire file -- a 2 GB CSV therefore killed
# the container before anything got to reject it. This byte cap is checked while
# the body is still being read, so the oversized upload never becomes a DataFrame.
MAX_UPLOAD_MB = float(os.environ.get("NEXTATTACK_MAX_UPLOAD_MB", "64"))
MAX_UPLOAD_BYTES = int(MAX_UPLOAD_MB * 1024 * 1024)
UPLOAD_CHUNK = 1 << 20                      # 1 MiB per read


def _cors_origins() -> list[str]:
    """Which browser origins may call this API cross-site.

    It used to be `["*"]`, which meant any page on the internet could make a
    browser drive this API with whatever role header it liked. The single-
    container deploy serves the SPA from the same origin as /api, so CORS is not
    involved there at all and the tight default costs that deploy nothing; the
    default list exists only for `npm run dev`, where Vite is on :5173.

      NEXTATTACK_CORS_ORIGINS="https://soc.example.org,https://x.example.org"
      NEXTATTACK_DEV=1        # local only: back to "*"
    """
    raw = os.environ.get("NEXTATTACK_CORS_ORIGINS", "").strip()
    if raw:
        return [o.strip() for o in raw.split(",") if o.strip()]
    if os.environ.get("NEXTATTACK_DEV", "").strip() == "1":
        return ["*"]
    return ["http://localhost:5173", "http://127.0.0.1:5173",
            "http://localhost:8000", "http://127.0.0.1:8000",
            "http://localhost:4173", "http://127.0.0.1:4173"]   # vite preview


app = FastAPI(title="nextATT&CKs — SOC Command Center", version="1.0")
# Methods and headers are the ones this API actually uses; there is no PUT,
# DELETE or PATCH anywhere in the service, so there is nothing to allow.
app.add_middleware(CORSMiddleware,
                   allow_origins=_cors_origins(),
                   allow_methods=["GET", "POST", "OPTIONS"],
                   allow_headers=["Content-Type", "Authorization", "X-Role", "X-Actor"])


# --- lazy singletons (loaded once, on first use) ---
_state: dict = {}
# Both loaders below are check-then-set on a shared dict, and sync handlers run
# in FastAPI's threadpool, so two concurrent cold requests could both miss and
# both load -- including a duplicate pickle.load of the lookups file. Benign
# under the GIL today, but it is a trap for whoever next puts something
# non-atomic in _state. audit.py already does this correctly with _chain_lock.
_state_lock = threading.Lock()


def _score_ref():
    """Fixed 0-100 calibration anchors. The detector itself lives in
    src/shared/detector.py (NumPy inference over the exported autoencoder)."""
    with _state_lock:
        if "ref" not in _state:
            _state["ref"] = json.loads((CACHE / "score_ref.json").read_text())
        return _state["ref"]


def _technique_names() -> dict:
    """Technique display names. The transition model itself is served by
    src/shared/predictor.py, which owns the artifact format.

    Was `_markov()` returning `(None, names, None)`, so every caller wrote
    `_, names, _ =` and the signature advertised two things that never existed.
    """
    with _state_lock:
        if "names" not in _state:
            with LOOKUPS.open("rb") as f:
                lk = pickle.load(f)
            _state["names"] = lk["technique_to_name"]
        return _state["names"]


def _severity(score: float) -> str:
    return ("critical" if score >= 90 else "high" if score >= 70
            else "medium" if score >= 45 else "low")


# --- cached endpoints ---
def _cached(name: str) -> dict:
    path = CACHE / f"{name}.json"
    if not path.exists():
        raise HTTPException(503, f"cache '{name}' not built — run scripts.build_cache")
    return json.loads(path.read_text(encoding="utf-8"))


@app.get("/api/health")
def health():
    """Liveness. Keeps its original shape; /api/readiness has the detail."""
    from src.shared import evidence as _ev
    from src.shared import llm as _llm
    return {"ok": True,
            "cache_built": (CACHE / "overview.json").exists(),
            "evidence_index": _ev.available(),
            # Whether a language model is on, and which. Reported so a reader
            # never has to guess whether prose came from a model or a template,
            # and so an unintended provider is visible rather than silent.
            "llm": _llm.status(),
            "version": os.environ.get("NEXTATTACK_VERSION", "dev")}


@app.get("/api/llm")
def llm_status():
    """What the language-model layer is doing. Never returns a key."""
    from src.shared import llm as _llm
    return _llm.status()


@app.get("/api/overview")
def overview():
    return _cached("overview")


@app.get("/api/incident")
def incident():
    return _cached("incident")


@app.get("/api/graph")
def graph():
    return _cached("graph")


@app.get("/api/threat-intel")
def threat_intel():
    return _cached("threat_intel")


@app.get("/api/metrics")
def metrics():
    return _cached("metrics")


@app.get("/api/methodology")
def methodology():
    return _cached("methodology")


@app.get("/api/report")
def report():
    return _cached("report")


@app.get("/api/attackers")
def attackers():
    """Per-account breakdown of the campaign — the 'who' table."""
    meta = _cached("attackers_meta")
    return {"attackers": _cached("attackers"),
            "scenario": meta.get("scenario")}


@app.get("/api/threat-radar")
def threat_radar():
    """External CTI (cached at build time) mapped to ATT&CK."""
    data = _cached("threat_radar")
    data.setdefault("meta", {})["source"] = "cache"
    return data


class RadarRequest(BaseModel):
    technique_ids: list[str] = []      # the incident being investigated
    actors: list[str] = []             # its attributed actors
    edges: list[dict] = []             # its graph edges (for the exposure bridge)
    refresh: bool = False              # re-fetch the feeds live?


@app.post("/api/threat-radar")
def threat_radar_scored(req: RadarRequest,
                        # The stricter principal, not analyze_principal: this
                        # route can trigger outbound fetches to third-party CTI
                        # feeds, and it was reachable with no header at all.
                        # An egress trigger should not inherit the demo-headers
                        # concession that exists for EventSource.
                        p: dict = Depends(_finalist_principal)):
    """Radar cross-referenced against the incident you're investigating.

    Scoring runs here (one implementation, `src.shared.osint.relevance`) rather
    than in the frontend. `refresh` re-fetches the free feeds live; if no source
    responds we serve the cache — never an empty radar labelled live.
    """
    _require(p, "analyze")
    from src.shared.osint import collect as collect_osint, relevance   # noqa: PLC0415

    data = None
    if req.refresh:
        try:
            live = collect_osint()
            # collect() isolates each feed, so it succeeds even with everything
            # down; only accept it if a source actually returned something.
            if any(s["ok"] for s in live.get("sources", [])) and live.get("items"):
                live.setdefault("meta", {})["source"] = "live"
                data = live
        except Exception:
            data = None
    if data is None:
        data = _cached("threat_radar")
        data.setdefault("meta", {})["source"] = "cache"

    # Technique bridge: for each ATT&CK technique in a radar item, which of YOUR
    # own movements use that same technique. Real on both sides — the external
    # report and your graph edges — so "this is in the news, where am I exposed?"
    # is answered without inventing anything.
    edges = req.edges
    if not edges:
        try:
            edges = _cached("graph").get("edges", [])   # default: the campaign graph
        except HTTPException:
            edges = []
    from src.shared.osint import tactics_of
    by_tech: dict[str, list[dict]] = {}
    by_tactic: dict[str, list[dict]] = {}
    for e in edges:
        mv = {"from": e.get("from"), "to": e.get("to"), "score": e.get("score"),
              "event_count": e.get("event_count", 1), "technique": e.get("technique")}
        by_tech.setdefault(e.get("technique"), []).append(mv)
        for tac in tactics_of([e.get("technique")]):
            by_tactic.setdefault(tac, []).append(mv)

    for item in data.get("items", []):
        rel = relevance(item, req.technique_ids, req.actors)
        item["relevance"] = rel
        # exact-technique exposure (strongest), else tactic-level (broader, honest)
        exp = {t: by_tech.get(t, [])[:20] for t in rel["matched_techniques"] if by_tech.get(t)}
        exp_tac = ({} if exp else
                   {tac: by_tactic.get(tac, [])[:20] for tac in rel["matched_tactics"] if by_tactic.get(tac)})
        item["your_exposure"] = exp
        item["your_exposure_tactic"] = exp_tac

    data["items"].sort(key=lambda i: (i["relevance"]["score"], i.get("published", "")),
                       reverse=True)
    data["relevant_count"] = sum(1 for i in data["items"] if i["relevance"]["score"] > 0)
    return data


def _limit(p: dict, bucket: str) -> None:
    """429 when a principal is using more than its share of a costly endpoint.

    Applied to the analyze pipeline and the agent lane only: those are the two
    that spend CPU seconds and third-party quota. Everything else is a cached
    read. The refusal is a 429 with Retry-After, not a silent slowdown.
    """
    from src.shared import ratelimit
    ok, wait = ratelimit.check(bucket, p.get("actor") or "anonymous")
    if not ok:
        raise HTTPException(
            429, f"rate limit for '{bucket}': try again in {wait:.0f}s",
            headers={"Retry-After": str(max(1, int(wait + 0.5)))})


def analyze_principal(
        x_role: str | None = Header(default=None, alias="X-Role"),
        x_actor: str | None = Header(default=None, alias="X-Actor"),
        authorization: str | None = Header(default=None)) -> dict:
    """The principal for the live-analysis and agent endpoints.

    These endpoints had NO authorisation at all: `/api/analyze`, the two upload
    routes and the SSE streams were open while eighteen endpoints on the finalist
    router were gated. They now go through the same `principal` / `_require`
    pair, so `analyze` is enforced in one place for the whole service.

    One documented concession, and it is worth being blunt about it. When
    `NEXTATTACK_ROLE_TOKENS` is unset the service runs in demo-headers mode,
    where the role is self-declared and there is no authentication whatsoever --
    a caller who does not like being a viewer just sends `X-Role: admin`. In
    that mode a caller who declares NOTHING is treated as the demo operator
    ("analyst") rather than as a viewer. That is not laziness: both SSE screens
    (the incident replay and the agent stream) are driven by `EventSource`, which
    has no API for setting a request header, so gating them on one would break
    the zero-config demo without denying a single real attacker -- the header is
    free to forge in this mode anyway.

    A DECLARED role is always enforced, so `X-Role: viewer` is refused here. And
    the moment `NEXTATTACK_ROLE_TOKENS` is configured this concession disappears
    entirely: `resolve_principal` raises before any defaulting happens, so an
    anonymous caller gets 401 and these endpoints are genuinely closed -- which
    was not previously possible at any setting.
    """
    p = _finalist_principal(x_role, x_actor, authorization)
    if p["auth_mode"] == "demo-headers" and not (x_role or "").strip():
        p = {**p, "role": "analyst", "actor": (x_actor or "demo-analyst")}
    return p


# --- LIVE endpoint 1: score an event ---
class EventFeatures(BaseModel):
    """The exact seven inputs the client emits, all required, all bounded.

    These used to default -- is_fail=0, dst_rarity=4.0 and so on -- so
    `POST /api/score-event {}` returned 200 with a score for an event nobody
    described. A detector result for a fabricated all-default event is worse
    than an error, because it looks like a measurement.
    """
    is_fail: int = Field(ge=0, le=1)
    new_dst_for_user: int = Field(ge=0, le=1)
    new_src_for_user: int = Field(ge=0, le=1)
    user_distinct_dst_sofar: float = Field(ge=0)
    user_fail_rate_sofar: float = Field(ge=0, le=1)
    dst_rarity: float = Field(ge=0)
    is_ntlm: int = Field(ge=0, le=1)


@app.post("/api/score-event")
def score_event(f: EventFeatures, p: dict = Depends(analyze_principal)):
    _require(p, "analyze")
    from src.shared import detector
    x = [[getattr(f, k) for k in FEATURES]]
    raw = float(detector.raw_scores(x)[0])
    score = float(detector.calibrate([raw], _score_ref())[0])
    # Report which detector actually produced this. The UI used to hardcode
    # "Isolation-Forest" while the autoencoder was the shipped model, so the one
    # label on screen naming a model named the wrong one.
    return {"anomaly_score": round(score, 1), "severity": _severity(score),
            "raw": round(raw, 4),
            "detector": "autoencoder" if detector.available() else "isolation-forest"}


# --- LIVE endpoint 2: predict next technique ---
class Chain(BaseModel):
    technique_ids: list[str] = Field(min_length=1)
    k: int = Field(default=5, ge=1, le=50)


@app.post("/api/predict-next")
def predict_next(c: Chain, p: dict = Depends(analyze_principal)):
    """Next-technique ranking from the shipped interpolated Markov model.

    Scores are real interpolated transition probabilities
    (l2*order2 + l1*order1 + l0*unigram), not a bare ranked list.
    """
    _require(p, "analyze")
    from src.shared import predictor
    names = _technique_names()                 # technique_id -> display name
    top, source = predictor.rank_next(list(c.technique_ids), max(1, c.k))
    preds = [{"rank": i + 1, "technique_id": t, "name": names.get(t, t),
              "score": round(p, 3)}
             for i, (t, p) in enumerate(top)]
    narrative = predictor.generate_prediction_narrative(preds, list(c.technique_ids))
    return {"given": c.technique_ids,
            "predictions": preds,
            "projection_narrative": narrative,
            "source": source}


# --- LIVE endpoint 3: full pipeline analysis of an event log ---------------
# This is what makes the app WORK rather than replay one baked incident: score
# every event → correlate → graph → SOAR → attribute → predict, computed live.
from src.shared.live_analyze import analyze_events, MAX_ROWS   # noqa: E402
# Moved to src/shared so a library no longer has to import this module back out
# of the API layer. See src/shared/agent_view.py for why that mattered.
from src.shared.agent_view import (                                # noqa: E402
    _agent_pipeline_summary, _map_agent_bundle, _map_agent_graph)


async def _read_upload(file: UploadFile) -> bytes:
    """Read an upload with a hard byte ceiling, refusing before anything parses.

    Every handler here used to do a bare `raw = await file.read()`, which reads
    the whole body into memory no matter how big it is. The only size check in
    the product was `MAX_ROWS`, and that lives inside live_analyze._prepare --
    i.e. *after* `pd.read_csv` has already materialised the entire file. A 2 GB
    CSV therefore OOM-killed the container before any limit was consulted.

    So: read in chunks, stop the moment the cap is crossed, and 413 with both
    limits named so the caller knows which wall they hit and which is next.
    """
    buf = bytearray()
    while chunk := await file.read(UPLOAD_CHUNK):
        buf.extend(chunk)
        if len(buf) > MAX_UPLOAD_BYTES:
            raise HTTPException(
                413, f"upload exceeds the {MAX_UPLOAD_MB:g} MB limit "
                     f"(NEXTATTACK_MAX_UPLOAD_MB); the row limit is "
                     f"{MAX_ROWS:,} events -- upload a focused window")
    return bytes(buf)


_GEN_DONE = object()


async def _astep(iterator):
    """Pull one item from a synchronous generator without blocking the loop.

    `iter_pipeline` is a plain generator and each `next()` runs one whole agent --
    seconds of pandas and model work. Driving it from an SSE `async def gen()`
    with a normal `for` froze the event loop for the entire stream, which is a
    particularly silly way to serve a progress feed: nothing else could be
    answered, and the progress frames could not even be flushed on time.
    StopIteration cannot cross a threadpool boundary, hence the sentinel.
    """
    return await run_in_threadpool(next, iterator, _GEN_DONE)


@app.get("/api/scenarios")
def scenarios():
    """List the shipped demo event logs for 1-click analysis."""
    out = []
    if SCENARIOS.exists():
        for csv in sorted(SCENARIOS.glob("*.csv")):
            meta = SCENARIO_META.get(csv.stem, {})
            try:
                n = sum(1 for _ in csv.open(encoding="utf-8")) - 1  # minus header
            except OSError:
                n = None
            out.append({"name": csv.stem,
                        "label": meta.get("label", csv.stem),
                        "description": meta.get("description", ""),
                        "n_events": n,
                        "critical_default": meta.get("critical_default", [])})
    return {"scenarios": out}


class AnalyzeRequest(BaseModel):
    events: list[dict] | None = None       # rows in the common event schema
    scenario: str | None = None            # OR the name of a shipped scenario
    critical_assets: list[str] = []
    incident_id: str = "INC-LIVE-001"
    account: str | None = None             # scope a campaign log to one account


def _prepare_agent_events(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize enough for the agent pipeline to share the standard input path."""
    from src.schema import coerce, validate

    events = coerce(df.copy())
    validate(events)
    for col, default in (("status", "success"), ("protocol", "")):
        if col not in events.columns:
            events[col] = default
    return events


def _resolve_use_llm(requested: bool | None) -> bool:
    """None follows the configured provider; True and False are honoured as-is.

    A caller that says False on a host with a provider configured gets the
    deterministic path, which is the only way to compare the two lanes on the
    same log.
    """
    from src.shared import llm

    if requested is None:
        return llm.chosen_provider() is not None
    return bool(requested)


def _attach_agent_pipeline(bundle: dict, agent_summary: dict) -> dict:
    """Expose 10-agent reasoning without changing the SPA's screen contracts."""
    bundle.setdefault("meta", {})["agent_pipeline"] = agent_summary
    bundle["meta"]["pipeline"] = "standard+10-agent"

    if agent_summary.get("status") != "failed":
        bundle = _map_agent_bundle(bundle, agent_summary)
    return bundle


def _run_agents_for_standard_bundle(
    df: pd.DataFrame,
    *,
    scenario: str,
    incident_id: str,
    entity_col: str = "user",
) -> dict:
    from src.agents.orchestrator import run_pipeline

    try:
        result = run_pipeline(
            _prepare_agent_events(df),
            scenario=scenario,
            incident_id=incident_id,
            entity_col=entity_col,
            # Follow the one documented switch instead of hardcoding off. This
            # was False unconditionally, so an operator who set
            # NEXTATTACK_LLM_PROVIDER, saw /api/health report the provider
            # active, and pressed Run investigation still got a template with
            # nothing saying why. With no provider configured this is False and
            # the path is byte-for-byte the offline one.
            use_llm=_resolve_use_llm(None),
        )
        summary = _agent_pipeline_summary(result)
        return summary
    except Exception as e:
        return {
            "enabled": True,
            "status": "failed",
            "incident_id": incident_id,
            "scenario": scenario,
            "error": str(e),
            "agent_traces": [],
            "ranked_chains": [],
            "chain_explanations": [],
            "predictions": [],
            "evidence_refs": [],
            "notes": ["10-agent pipeline failed; standard analysis bundle returned."],
        }


def _run_analysis(df: pd.DataFrame, critical_assets, incident_id, account=None,
                  scenario: str = "events") -> dict:
    """The standard analysis path, enriched exactly like the investigation.

    Both go through src.shared.enrich, so the Analyze tab, the Overview screen
    and the cached sample carry the same claims, four-number assessment,
    progression forecast and agent cross-check the Investigation tab does. They
    used to diverge, which meant the same log produced different answers
    depending on which button started it.
    """
    from src.shared.enrich import enrich_bundle

    try:
        bundle = analyze_events(df, critical_assets=set(critical_assets or []),
                                incident_id=incident_id, account=account)
    except ValueError as e:                # trust-boundary rejections → 422
        raise HTTPException(422, str(e))
    agent_summary = _run_agents_for_standard_bundle(
        df,
        scenario=scenario,
        incident_id=incident_id,
    )
    bundle = _attach_agent_pipeline(bundle, agent_summary)
    return enrich_bundle(bundle, df=df, scenario=scenario,
                         critical=list(critical_assets or []),
                         agent_summary=agent_summary)


@app.post("/api/analyze")
def analyze(req: AnalyzeRequest, p: dict = Depends(analyze_principal)):
    """Deliberately a plain `def`, unlike its three siblings below.

    The whole body -- pd.read_csv, the scoring pipeline, the agent lane -- is
    synchronous and takes seconds. FastAPI runs a non-async path operation in its
    own threadpool automatically, so this one never touches the event loop. The
    `async def` handlers below got no such treatment: they awaited the upload and
    then called the identical blocking pipeline *on the loop thread*, stalling
    every other request in the process until it finished. Hence the explicit
    `run_in_threadpool` there and nothing here.
    """
    _require(p, "analyze")
    _limit(p, "analyze")
    if req.scenario:
        path = SCENARIOS / f"{req.scenario}.csv"
        if not path.exists():
            raise HTTPException(404, f"unknown scenario '{req.scenario}'")
        df = pd.read_csv(path)
        crit = req.critical_assets or SCENARIO_META.get(req.scenario, {}).get("critical_default", [])
    elif req.events:
        df = pd.DataFrame(req.events)
        crit = req.critical_assets
    else:
        raise HTTPException(422, "provide either 'scenario' or 'events'")
    inc_id = req.incident_id
    if req.account and inc_id == "INC-LIVE-001":
        inc_id = f"INC-{req.account.split('@')[0]}"
    return _run_analysis(df, crit, inc_id, req.account, scenario=req.scenario or "events")


@app.post("/api/analyze/upload")
async def analyze_upload(file: UploadFile = File(...),
                         critical_assets: str = Form(""),
                         incident_id: str = Form("INC-UPLOAD-001"),
                         p: dict = Depends(analyze_principal)):
    """Analyze an uploaded CSV (rows in the common event schema)."""
    _require(p, "analyze")
    _limit(p, "analyze")
    raw = await _read_upload(file)                  # 413 before anything parses

    def work():
        try:
            df = pd.read_csv(io.BytesIO(raw))
        except Exception as e:
            raise HTTPException(422, f"could not parse CSV: {e}")
        crit = [c.strip() for c in critical_assets.split(",") if c.strip()]
        return _run_analysis(df, crit, incident_id, scenario=f"upload:{file.filename}")

    # pd.read_csv and the pipeline are seconds of pure CPU. Running them inline
    # in an `async def` froze the event loop for every other request.
    return await run_in_threadpool(work)


@app.get("/api/analyze/stream")
async def analyze_stream(scenario: str, critical_assets: str = "", delay: float = 0.15,
                         p: dict = Depends(analyze_principal)):
    """Server-Sent Events: replay a scenario's real per-event scores one at a time,
    then a final `done` event carrying the full analysis bundle. The scoring is real
    (done up front by analyze_events); the delay just paces the on-stage reveal."""
    import asyncio
    from fastapi.responses import StreamingResponse

    _require(p, "analyze")
    _limit(p, "analyze")
    path = SCENARIOS / f"{scenario}.csv"
    if not path.exists():
        raise HTTPException(404, f"unknown scenario '{scenario}'")
    crit = [c.strip() for c in critical_assets.split(",") if c.strip()] \
        or SCENARIO_META.get(scenario, {}).get("critical_default", [])

    def build():
        """All of it -- read, score, agent lane, enrich -- is blocking CPU work.

        It used to run inline in this `async def`, so the whole server stopped
        answering for the several seconds it takes, on every stream request.
        """
        try:
            df = pd.read_csv(path)
            b = analyze_events(df, critical_assets=set(crit),
                               incident_id="INC-STREAM-001")
        except ValueError as e:
            raise HTTPException(422, str(e))
        # The streaming and non-streaming paths must return the same contract. The
        # POST path attaches the agent lane; without this the `done` bundle silently
        # lacked meta.agent_pipeline and the same screen behaved differently
        # depending on which button was pressed.
        from src.shared.enrich import enrich_bundle
        _agents = _run_agents_for_standard_bundle(df, scenario=scenario,
                                                  incident_id="INC-STREAM-001")
        return enrich_bundle(_attach_agent_pipeline(b, _agents),
                             df=df, scenario=scenario, critical=list(crit),
                             agent_summary=_agents)

    bundle = await run_in_threadpool(build)
    steps = bundle["incident"]["steps"]

    async def gen():
        for i, s in enumerate(steps):
            payload = json.dumps({"i": i, "total": len(steps), "step": s})
            yield f"event: step\ndata: {payload}\n\n"
            await asyncio.sleep(max(0.0, min(delay, 1.0)))
        yield f"event: done\ndata: {json.dumps(bundle)}\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})



# --- RAG Retrieval endpoints ------------------------------------------------
# Lazy-init: vector store is optional — API works without it; returns empty
# results with a 503-like note so the frontend can show "RAG not ready".

_rag_ready: bool | None = None   # None = not yet checked

def _check_rag() -> bool:
    global _rag_ready
    if _rag_ready is not None:
        return _rag_ready
    try:
        from src.retrieval.embed import CHROMA_DIR, COLLECTION_NAME
        import chromadb
        client = chromadb.PersistentClient(path=str(CHROMA_DIR))
        client.get_collection(COLLECTION_NAME)
        _rag_ready = True
    except Exception:
        _rag_ready = False
    return _rag_ready


class RetrieveRequest(BaseModel):
    query: str = Field(max_length=4096)
    top_k: int = Field(default=10, ge=1, le=100)
    source_filter: str | None = None
    domain_filter: str | None = None
    severity_filter: str | None = None
    actor_filter: str | None = None
    family_filter: str | None = None


class IncidentRetrieveRequest(BaseModel):
    technique_ids: list[str] = Field(default_factory=list, max_length=64)
    incident_text: str = Field(default="", max_length=8192)
    top_k: int = Field(default=15, ge=1, le=100)


@app.get("/api/rag/status")
def rag_status():
    """Check if the RAG vector store is built and ready."""
    ready = _check_rag()
    return {
        "ready": ready,
        "note": "Run: python -m src.retrieval.ingest && python -m src.retrieval.embed" if not ready else "RAG vector store online.",
    }


@app.post("/api/retrieve")
def retrieve_endpoint(req: RetrieveRequest,
                      p: dict = Depends(analyze_principal)):
    """
    Semantic search over the cybersecurity knowledge corpus.
    Returns ranked chunks from ATT&CK, CISA KEV, CVEs, malware KB, etc.
    """
    _require(p, "read")
    if not _check_rag():
        raise HTTPException(status_code=503, detail={
            "error": "RAG vector store not built.",
            "fix": "python -m src.retrieval.ingest && python -m src.retrieval.embed",
        })
    from src.retrieval.query import retrieve
    results = retrieve(
        query=req.query,
        top_k=req.top_k,
        source_filter=req.source_filter,
        domain_filter=req.domain_filter,
        severity_filter=req.severity_filter,
        actor_filter=req.actor_filter,
        family_filter=req.family_filter,
    )
    return {"query": req.query, "results": results, "count": len(results)}


@app.get("/api/technique-context/{technique_id}")
def technique_context(technique_id: str):
    """
    Retrieve all RAG chunks related to a specific ATT&CK technique (e.g. T1486).
    Used by the SOC screen to show enriched context for mapped techniques.
    """
    if not _check_rag():
        return {"technique_id": technique_id, "results": [], "note": "RAG not built."}
    from src.retrieval.query import technique_lookup
    results = technique_lookup(technique_id)
    return {"technique_id": technique_id, "results": results, "count": len(results)}


@app.post("/api/retrieve/incident")
def retrieve_for_incident(req: IncidentRetrieveRequest,
                          p: dict = Depends(analyze_principal)):
    """
    Retrieve RAG context most relevant to a running incident.
    Combines technique-specific lookups with free-text semantic search.
    """
    _require(p, "read")
    if not _check_rag():
        raise HTTPException(status_code=503, detail="RAG vector store not built.")
    from src.retrieval.query import retrieve_for_incident
    results = retrieve_for_incident(
        incident_techniques=req.technique_ids,
        incident_text=req.incident_text,
        top_k=req.top_k,
    )
    return {
        "technique_ids": req.technique_ids,
        "results": results,
        "count": len(results),
    }


# --- engine3: the network-state world model --------------------------------
# This subsystem was 1,200 lines reachable only from eval scripts, while
# scoreboard.py published its measured numbers to a reviewer. Publishing metrics
# for something no user of the product can reach is the half of that pair which
# is not defensible, so it is reachable now.
#
# Honest about what it is: research-grade, one route, no screen. /api/netstate/
# status says so, and the scoreboard cards say so.
class NetStateRequest(BaseModel):
    """Flow rows in the CIC-IDS2017 column vocabulary."""
    flows: list[dict] = Field(min_length=1, max_length=200_000)
    horizon: int = Field(default=5, ge=1, le=16)


@app.get("/api/netstate/status")
def netstate_status():
    """Whether the world model can serve, and what it is and is not."""
    from src.engine3 import netstate as ns
    ready = ns.MODEL.exists()
    return {
        "ready": ready,
        "model": str(ns.MODEL.name),
        "n_states": ns.N_STATES,
        "window": ns.WINDOW,
        "state_dim": ns.STATE_DIM,
        "flow_features": list(ns.FLOW_FEATURES),
        "surface": "API only -- there is no screen for this",
        "claim": ("A discrete latent state-space model over traffic windows. "
                  "Its published numbers are research results on CIC-IDS2017, "
                  "not a claim about the log you analyse elsewhere in this "
                  "product, and it does not feed any alert, score or severity."),
        "not_ready_note": None if ready else
            "train it with python -m scripts.eval_netstate",
    }


@app.post("/api/netstate/analyze")
def netstate_analyze(req: NetStateRequest, p: dict = Depends(analyze_principal)):
    """Window the supplied flows, encode each to a latent state, forecast ahead.

    Returns the per-window latent state and the k-step forecast. It deliberately
    does NOT return a severity or an alert: this model was evaluated on
    next-window prediction, and the honest thing to hand back is the forecast it
    was measured on rather than a verdict it was not.
    """
    _require(p, "analyze")
    _limit(p, "analyze")
    from src.engine3 import netstate as ns

    if not ns.MODEL.exists():
        raise HTTPException(503, "world model artifact is not built; run "
                                 "python -m scripts.eval_netstate")

    def work():
        df = pd.DataFrame(req.flows)
        missing = [c for c in ns.FLOW_FEATURES if c not in df.columns]
        if missing:
            raise HTTPException(
                422, f"{len(missing)} of {len(ns.FLOW_FEATURES)} flow features "
                     f"missing, first few: {missing[:5]}")
        if "label" not in df.columns:
            df["label"] = 0.0            # unlabelled input is the normal case
        states, attack_rate = ns.windows(df)
        if len(states) == 0:
            raise HTTPException(
                422, f"need at least {ns.WINDOW} flows to form one window; "
                     f"got {len(df)}")
        model = ns.NetStateModel.load()
        latent = model.encode(states)
        # forecast() encodes internally, so it takes the 48-dim window states,
        # not the latent ids. Passing `latent` here broadcast (1,3) against (48,).
        fc = model.forecast(states, horizon=req.horizon)
        return {
            "windows": int(len(states)),
            "window_size": ns.WINDOW,
            "latent_state": [int(x) for x in latent],
            "forecast": fc,
            "observed_attack_rate": [round(float(a), 4) for a in attack_rate],
            "authoritative": False,
            "note": ("Research surface. This model does not feed any alert, "
                     "score or severity elsewhere in the product."),
        }

    return work()


# --- finalist surface: workflow, evidence, vulnerabilities, twin, RBAC, audit
# Registered BEFORE the SPA catch-all below, which would otherwise shadow every
# GET route it defines.
from api.finalist import router as finalist_router   # noqa: E402

app.include_router(finalist_router)


# --- 10-agent pipeline endpoint (Sarthak's architecture) --------------------
class AgentAnalysisRequest(BaseModel):
    scenario: str = "lanl_campaign_all"
    incident_id: str = "INC-001"
    entity_col: str = "user"
    # None means "follow NEXTATTACK_LLM_PROVIDER", which is the switch the rest
    # of the product obeys. True and False still force it either way, so a
    # caller can pin the deterministic path on a configured host.
    use_llm: bool | None = None


@app.post("/api/agents/analyze")
def agents_analyze(req: AgentAnalysisRequest, p: dict = Depends(analyze_principal)):
    """Run the full 10-agent pipeline on a pre-loaded scenario.

    Returns the complete PipelineResult including:
      - per-agent execution traces
      - ranked attack chains
      - Point-A chunk summaries + Point-B incident narrative
      - next-move predictions
      - all evidence references

    Plain `def` on purpose -- see the note on /api/analyze; FastAPI already runs
    this off the event loop, so the blocking pipeline below is fine as it is.
    """
    from src.agents.orchestrator import run_pipeline

    _require(p, "analyze")
    _limit(p, "agents")

    # Load scenario events (.csv or .parquet)
    csv_file = SCENARIOS / f"{req.scenario}.csv"
    parquet_file = SCENARIOS / f"{req.scenario}.parquet"
    if csv_file.exists():
        events = pd.read_csv(csv_file)
    elif parquet_file.exists():
        events = pd.read_parquet(parquet_file)
    else:
        raise HTTPException(404, f"Scenario '{req.scenario}' not found. "
                            f"Available: {list(SCENARIO_META.keys())}")

    try:
        result = run_pipeline(
            events,
            scenario=req.scenario,
            incident_id=req.incident_id,
            entity_col=req.entity_col,
            use_llm=_resolve_use_llm(req.use_llm),
        )
        return result.as_dict()
    except Exception as e:
        raise HTTPException(500, f"Pipeline error: {e}")


@app.post("/api/agents/analyze/upload")
async def agents_analyze_upload(
    file: UploadFile = File(...),
    incident_id: str = Form("INC-001"),
    entity_col: str = Form("user"),
    use_llm: bool | None = Form(None),
    p: dict = Depends(analyze_principal),
):
    """Run the 10-agent pipeline on an uploaded CSV log file.

    The CSV must have at minimum: timestamp, user, source_host, destination_host.
    Schema normalization is applied automatically.
    """
    from src.agents.orchestrator import run_pipeline
    from src.shared.normalize import normalize

    _require(p, "analyze")
    _limit(p, "agents")
    # Outside the try below on purpose: that block turns every exception into a
    # 400, which would have relabelled the 413 as a parse failure.
    contents = await _read_upload(file)

    def work():
        try:
            df_raw = pd.read_csv(io.BytesIO(contents))
        except Exception as e:
            raise HTTPException(400, f"Failed to parse uploaded CSV: {e}")

        try:
            # Attempt normalization; fall back to raw if columns already match
            try:
                events = normalize(df_raw, source="lanl")
            except Exception:
                events = df_raw
            result = run_pipeline(
                events,
                scenario=f"upload:{file.filename}",
                incident_id=incident_id,
                entity_col=entity_col,
                use_llm=_resolve_use_llm(use_llm),
            )
            return result.as_dict()
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(500, f"Pipeline error: {e}")

    # The 10-agent pipeline is tens of seconds of synchronous work. Awaiting the
    # upload and then running it inline blocked the loop for that entire time.
    return await run_in_threadpool(work)


@app.get("/api/agents/stream")
async def agents_stream(
    scenario: str,
    critical_assets: str = "",
    incident_id: str = "INC-STREAM-001",
    entity_col: str = "user",
    use_llm: bool | None = None,
    p: dict = Depends(analyze_principal),
):
    """Server-Sent Events: stream the 10-agent pipeline executing live agent by agent."""
    import asyncio
    from fastapi.responses import StreamingResponse
    from src.agents.orchestrator import iter_pipeline
    from src.shared.enrich import enrich_bundle

    _require(p, "analyze")
    _limit(p, "agents")
    path = SCENARIOS / f"{scenario}.csv"
    if not path.exists():
        raise HTTPException(404, f"unknown scenario '{scenario}'")
    crit = [c.strip() for c in critical_assets.split(",") if c.strip()] \
        or SCENARIO_META.get(scenario, {}).get("critical_default", [])

    def build():
        try:
            d = pd.read_csv(path)
            return d, analyze_events(d, critical_assets=set(crit),
                                     incident_id=incident_id)
        except Exception as e:
            raise HTTPException(422, str(e))

    df, bundle = await run_in_threadpool(build)

    async def gen():
        events_df = await run_in_threadpool(_prepare_agent_events, df)
        final_summary = None
        it = iter_pipeline(
            events_df,
            scenario=scenario,
            incident_id=incident_id,
            entity_col=entity_col,
            use_llm=_resolve_use_llm(use_llm),
        )
        while (item := await _astep(it)) is not _GEN_DONE:
            event_type, payload = item
            if event_type == "agent_progress":
                yield f"event: progress\ndata: {json.dumps(payload)}\n\n"
                await asyncio.sleep(0.05)
            elif event_type == "pipeline_complete":
                pipeline_res = payload["result"]
                final_summary = _agent_pipeline_summary(pipeline_res)

        # The `done` frame has to carry the SAME contract as the non-streaming
        # POST, or a screen behaves differently depending on which button was
        # pressed. Without enrich_bundle it was missing `analysis` entirely.
        # run_agents=False because this IS the agent run: re-entering the
        # pipeline here would double it.
        final_bundle = (_attach_agent_pipeline(bundle, final_summary)
                        if final_summary else bundle)
        final_bundle = await run_in_threadpool(
            enrich_bundle, final_bundle, df=df, scenario=scenario,
            critical=crit, agent_summary=final_summary, run_agents=False)
        yield f"event: done\ndata: {json.dumps(final_bundle)}\n\n"

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/api/agents/stream/upload")
async def agents_upload_stream(
    file: UploadFile = File(...),
    critical_assets: str = Form(""),
    incident_id: str = Form("INC-UPLOAD-001"),
    entity_col: str = Form("user"),
    use_llm: bool | None = Form(None),
    p: dict = Depends(analyze_principal),
):
    """Server-Sent Events: stream the 10-agent pipeline executing live on an uploaded log."""
    import asyncio
    from fastapi.responses import StreamingResponse
    from src.agents.orchestrator import iter_pipeline
    from src.shared.enrich import enrich_bundle
    from src.shared.normalize import normalize

    _require(p, "analyze")
    _limit(p, "agents")
    raw = await _read_upload(file)                  # 413 before anything parses
    crit = [c.strip() for c in critical_assets.split(",") if c.strip()]

    def build():
        try:
            df_raw = pd.read_csv(io.BytesIO(raw))
        except Exception as e:
            raise HTTPException(422, f"could not parse CSV: {e}")
        try:
            try:
                d = normalize(df_raw, source="lanl")
            except Exception:
                d = df_raw
            return d, analyze_events(d, critical_assets=set(crit),
                                     incident_id=incident_id)
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(422, str(e))

    df, bundle = await run_in_threadpool(build)

    async def gen():
        events_df = await run_in_threadpool(_prepare_agent_events, df)
        final_summary = None
        it = iter_pipeline(
            events_df,
            scenario=f"upload:{file.filename}",
            incident_id=incident_id,
            entity_col=entity_col,
            use_llm=_resolve_use_llm(use_llm),
        )
        while (item := await _astep(it)) is not _GEN_DONE:
            event_type, payload = item
            if event_type == "agent_progress":
                yield f"event: progress\ndata: {json.dumps(payload)}\n\n"
                await asyncio.sleep(0.05)
            elif event_type == "pipeline_complete":
                pipeline_res = payload["result"]
                final_summary = _agent_pipeline_summary(pipeline_res)

        # The `done` frame has to carry the SAME contract as the non-streaming
        # POST, or a screen behaves differently depending on which button was
        # pressed. Without enrich_bundle it was missing `analysis` entirely.
        # run_agents=False because this IS the agent run: re-entering the
        # pipeline here would double it.
        final_bundle = (_attach_agent_pipeline(bundle, final_summary)
                        if final_summary else bundle)
        final_bundle = await run_in_threadpool(
            enrich_bundle, final_bundle, df=df, scenario=f"upload:{file.filename}",
            critical=crit, agent_summary=final_summary, run_agents=False)
        yield f"event: done\ndata: {json.dumps(final_bundle)}\n\n"

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )



# --- serve the built React app (single-container deploy) -------------------
# When frontend/dist exists (production image), FastAPI serves the SPA from the
# same origin as /api — no CORS, one URL. In local dev the Vite server handles
# the UI and proxies /api here, so this block is simply inactive.
from fastapi.responses import FileResponse           # noqa: E402
from fastapi.staticfiles import StaticFiles           # noqa: E402

DIST = ROOT / "frontend" / "dist"

# The two halves of a hashed-asset build cache in OPPOSITE directions, and
# neither was being told to.
#
# Nothing set Cache-Control at all, so browsers fell back to heuristic caching:
# with a Last-Modified and no directive they keep a response for roughly a tenth
# of its age. For index.html that is the whole trap. Rebuild the frontend, and
# every open tab still holds an index naming chunk hashes that no longer exist:
# the next lazy route dies on "Failed to fetch dynamically imported module",
# which names neither the cause nor the fix, and a plain refresh can serve the
# same stale index right back.
#
# So: the index must be revalidated every time (ETag keeps that nearly free),
# and the hashed assets can be kept forever, because a changed file gets a
# changed name. That pairing makes the failure impossible rather than rare --
# a fresh index can only ever name chunks that exist.
ASSET_CACHE = "public, max-age=31536000, immutable"
INDEX_CACHE = "no-cache"           # revalidate, not "do not store"

if DIST.exists():
    class _ImmutableAssets(StaticFiles):
        """Hashed filenames, so the content behind a URL never changes."""

        def file_response(self, *args, **kwargs):       # type: ignore[override]
            resp = super().file_response(*args, **kwargs)
            resp.headers["Cache-Control"] = ASSET_CACHE
            return resp

    app.mount("/assets", _ImmutableAssets(directory=str(DIST / "assets")),
              name="assets")

    @app.get("/{full_path:path}")
    def spa(full_path: str):
        candidate = DIST / full_path
        if full_path and candidate.is_file():
            return FileResponse(str(candidate))
        # SPA deep links. Always revalidated: this file is what names every
        # other file, so a stale copy strands the whole app.
        return FileResponse(str(DIST / "index.html"),
                            headers={"Cache-Control": INDEX_CACHE})
