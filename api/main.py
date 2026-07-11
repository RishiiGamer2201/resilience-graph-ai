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

import json
import pickle
from pathlib import Path

import joblib
import numpy as np
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / "api" / "cache"
LANL_MODEL = ROOT / "models" / "iforest_lanl.joblib"
MARKOV = ROOT / "models" / "next_technique_markov.pkl"
LOOKUPS = ROOT / "data" / "processed" / "mitre_attack" / "attack_lookups.pkl"

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
