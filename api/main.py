"""
M5.1 — Resilience Graph AI · SOC Command Center API (FastAPI).

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
import pickle
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

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
}

FEATURES = ["is_fail", "new_dst_for_user", "new_src_for_user",
            "user_distinct_dst_sofar", "user_fail_rate_sofar", "dst_rarity", "is_ntlm"]

app = FastAPI(title="Resilience Graph AI — SOC Command Center", version="1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


# --- lazy singletons (loaded once, on first use) ---
_state: dict = {}


def _model():
    if "model" not in _state:
        _state["model"] = joblib.load(LANL_MODEL)
        _state["ref"] = json.loads((CACHE / "score_ref.json").read_text())
    return _state["model"], _state["ref"]


def _markov():
    if "markov" not in _state:
        with MARKOV.open("rb") as f:
            _state["markov"] = pickle.load(f)
        with LOOKUPS.open("rb") as f:
            lk = pickle.load(f)
        _state["names"] = lk["technique_to_name"]
        # most-frequent fallback ordering from the transition table
        from collections import Counter
        c = Counter()
        for succ in _state["markov"].values():
            for i, t in enumerate(succ):
                c[t] += len(succ) - i
        _state["fallback"] = [t for t, _ in c.most_common()]
    return _state["markov"], _state["names"], _state["fallback"]


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
    return {"ok": True, "cache_built": (CACHE / "overview.json").exists()}


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
    return {"attackers": _cached("attackers")}


@app.get("/api/threat-radar")
def threat_radar():
    """External CTI (cached at build time) mapped to ATT&CK."""
    data = _cached("threat_radar")
    data.setdefault("meta", {})["source"] = "cache"
    return data


class RadarRequest(BaseModel):
    technique_ids: list[str] = []      # the incident being investigated
    actors: list[str] = []             # its attributed actors
    refresh: bool = False              # re-fetch the feeds live?


@app.post("/api/threat-radar")
def threat_radar_scored(req: RadarRequest):
    """Radar cross-referenced against the incident you're investigating.

    Scoring runs here (one implementation, `src.shared.osint.relevance`) rather
    than in the frontend. `refresh` re-fetches the free feeds live; if no source
    responds we serve the cache — never an empty radar labelled live.
    """
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

    for item in data.get("items", []):
        item["relevance"] = relevance(item, req.technique_ids, req.actors)
    # most relevant first, then most recent
    data["items"].sort(key=lambda i: (i["relevance"]["score"], i.get("published", "")),
                       reverse=True)
    data["relevant_count"] = sum(1 for i in data["items"] if i["relevance"]["score"] > 0)
    return data


# --- LIVE endpoint 1: score an event ---
class EventFeatures(BaseModel):
    is_fail: int = 0
    new_dst_for_user: int = 0
    new_src_for_user: int = 0
    user_distinct_dst_sofar: float = 40
    user_fail_rate_sofar: float = 0.001
    dst_rarity: float = 4.0
    is_ntlm: int = 0


@app.post("/api/score-event")
def score_event(f: EventFeatures):
    bundle, ref = _model()
    x = [[getattr(f, k) for k in FEATURES]]
    raw = float(-bundle["model"].score_samples(bundle["scaler"].transform(x))[0])
    lo, hi = ref["lo"], ref["hi"]
    score = float(np.clip((raw - lo) / (hi - lo + 1e-9), 0, 1) * 100)
    return {"anomaly_score": round(score, 1), "severity": _severity(score),
            "raw": round(raw, 4)}


# --- LIVE endpoint 2: predict next technique ---
class Chain(BaseModel):
    technique_ids: list[str]
    k: int = 5


@app.post("/api/predict-next")
def predict_next(c: Chain):
    trans, names, fallback = _markov()
    last = c.technique_ids[-1] if c.technique_ids else None
    ranked = list(trans.get(last, [])) if last else []
    seen = set(ranked)
    ranked += [t for t in fallback if t not in seen]        # backoff to most-frequent
    top = ranked[: max(1, c.k)]
    return {"given": c.technique_ids,
            "predictions": [{"rank": i + 1, "technique_id": t, "name": names.get(t, t)}
                            for i, t in enumerate(top)],
            "source": "markov" if last in trans else "frequency-fallback"}


# --- LIVE endpoint 3: full pipeline analysis of an event log ---------------
# This is what makes the app WORK rather than replay one baked incident: score
# every event → correlate → graph → SOAR → attribute → predict, computed live.
from src.shared.live_analyze import analyze_events, MAX_ROWS   # noqa: E402


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


def _run_analysis(df: pd.DataFrame, critical_assets, incident_id, account=None) -> dict:
    try:
        return analyze_events(df, critical_assets=set(critical_assets or []),
                              incident_id=incident_id, account=account)
    except ValueError as e:                # trust-boundary rejections → 422
        raise HTTPException(422, str(e))


@app.post("/api/analyze")
def analyze(req: AnalyzeRequest):
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
    return _run_analysis(df, crit, inc_id, req.account)


@app.post("/api/analyze/upload")
async def analyze_upload(file: UploadFile = File(...),
                         critical_assets: str = Form(""),
                         incident_id: str = Form("INC-UPLOAD-001")):
    """Analyze an uploaded CSV (rows in the common event schema)."""
    raw = await file.read()
    try:
        df = pd.read_csv(io.BytesIO(raw))
    except Exception as e:
        raise HTTPException(422, f"could not parse CSV: {e}")
    crit = [c.strip() for c in critical_assets.split(",") if c.strip()]
    return _run_analysis(df, crit, incident_id)


@app.get("/api/analyze/stream")
async def analyze_stream(scenario: str, critical_assets: str = "", delay: float = 0.15):
    """Server-Sent Events: replay a scenario's real per-event scores one at a time,
    then a final `done` event carrying the full analysis bundle. The scoring is real
    (done up front by analyze_events); the delay just paces the on-stage reveal."""
    import asyncio
    from fastapi.responses import StreamingResponse

    path = SCENARIOS / f"{scenario}.csv"
    if not path.exists():
        raise HTTPException(404, f"unknown scenario '{scenario}'")
    crit = [c.strip() for c in critical_assets.split(",") if c.strip()] \
        or SCENARIO_META.get(scenario, {}).get("critical_default", [])
    try:
        bundle = analyze_events(pd.read_csv(path), critical_assets=set(crit),
                                incident_id="INC-STREAM-001")
    except ValueError as e:
        raise HTTPException(422, str(e))
    steps = bundle["incident"]["steps"]

    async def gen():
        for i, s in enumerate(steps):
            payload = json.dumps({"i": i, "total": len(steps), "step": s})
            yield f"event: step\ndata: {payload}\n\n"
            await asyncio.sleep(max(0.0, min(delay, 1.0)))
        yield f"event: done\ndata: {json.dumps(bundle)}\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# --- serve the built React app (single-container deploy) -------------------
# When frontend/dist exists (production image), FastAPI serves the SPA from the
# same origin as /api — no CORS, one URL. In local dev the Vite server handles
# the UI and proxies /api here, so this block is simply inactive.
from fastapi.responses import FileResponse           # noqa: E402
from fastapi.staticfiles import StaticFiles           # noqa: E402

DIST = ROOT / "frontend" / "dist"
if DIST.exists():
    app.mount("/assets", StaticFiles(directory=str(DIST / "assets")), name="assets")

    @app.get("/{full_path:path}")
    def spa(full_path: str):
        candidate = DIST / full_path
        if full_path and candidate.is_file():
            return FileResponse(str(candidate))
        return FileResponse(str(DIST / "index.html"))   # SPA deep links
