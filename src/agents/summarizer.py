"""
src/agents/summarizer.py — Two-tier context summarization engine.

Implements the two summarization points from Sarthak's architecture doc:

  Point A — Chunk Summarizer (after normalization, before anomaly detection):
    Template-based. No model, no LLM. Takes an EventChunk's pre-aggregated
    stats and renders a compact feature+text string. The anomaly model still
    receives numeric features; the string is attached for free and avoids
    post-hoc explanation generation.

    Example output:
      "svc_admin made 40 login attempts across 12 hosts in 6 minutes,
       all successful, 0% off-hours — abnormal fan-out pattern."

  Point B — Incident Summarizer (after graph is built, before reasoning):
    This is the ONLY place an LLM touches the pipeline. It condenses all
    Point-A summaries across the whole incident graph into one coherent
    narrative for the Reasoning Agent. Falls back to deterministic template
    concatenation if no LLM is configured (GEMINI_API_KEY env var absent).
    LLM output is ALWAYS labelled non-authoritative.

Usage:
    from src.agents.summarizer import summarize_chunk, summarize_incident
    point_a = summarize_chunk(chunk)
    point_b = summarize_incident(point_a_summaries, technique_chain)
"""
from __future__ import annotations

import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.agents.chunker import EventChunk

# ─── Point A: Chunk Summarizer ────────────────────────────────────────────────

_FANOUT_THRESHOLD = 5   # unique destinations that look like lateral movement
_BURST_RATE_PER_MIN = 8  # logins/min that looks like a burst


def _fanout_label(n_unique_dst: int) -> str:
    if n_unique_dst >= _FANOUT_THRESHOLD:
        return "abnormal fan-out pattern"
    elif n_unique_dst >= 3:
        return "moderate spread"
    return "normal destination range"


def _burst_label(n_events: int, duration_sec: int) -> str:
    rate = n_events / max(duration_sec / 60, 1)
    if rate >= _BURST_RATE_PER_MIN:
        return f"high frequency ({rate:.0f}/min)"
    return f"normal frequency ({rate:.1f}/min)"


def summarize_chunk(chunk: "EventChunk") -> dict:
    """Point A: produce a compact feature+text summary for one EventChunk.

    Returns:
        {
          "chunk_id":     str,
          "entity":       str,
          "strategy":     str,
          "t_start":      int,
          "t_end":        int,
          "n_events":     int,
          "duration_sec": int,
          "text":         str,   ← the human-readable explanation string
          "stats":        dict,  ← raw aggregated stats for anomaly model
        }
    """
    s = chunk.stats
    n = s.get("n_events", len(chunk))
    dur = chunk.duration_sec()
    entity = chunk.entity

    n_dst = s.get("destination_host_unique", 1)
    n_src = s.get("source_host_unique", 1)
    n_fail = s.get("n_failures", 0)
    n_succ = s.get("n_successes", n)
    fail_rate = s.get("failure_rate", 0.0)
    bytes_total = s.get("bytes_out_total", 0)
    bytes_avg = s.get("bytes_out_avg", 0)

    fanout = _fanout_label(n_dst)
    burst = _burst_label(n, dur)
    strategy_label = chunk.strategy.value.replace("_", "-")

    # ── Template rendering ──────────────────────────────────────────────────
    parts: list[str] = []

    # Core action
    if n_fail > 0 and n_succ == 0:
        parts.append(f"{entity} made {n} failed login attempts")
    elif n_fail > 0:
        parts.append(f"{entity} made {n} login attempts ({n_fail} failed, {n_succ} successful)")
    else:
        parts.append(f"{entity} made {n} login attempts, all successful")

    # Spread
    parts.append(f"across {n_dst} unique destination{'s' if n_dst != 1 else ''}")

    # Duration
    if dur < 120:
        parts.append(f"in {dur}s")
    elif dur < 3600:
        parts.append(f"in {dur // 60}m {dur % 60}s")
    else:
        parts.append(f"over {dur // 3600}h {(dur % 3600) // 60}m")

    # Failure callout
    if fail_rate > 0.5:
        parts.append(f"({fail_rate:.0%} failure rate)")
    elif fail_rate == 0.0:
        parts.append("0% failure rate")

    # Data volume callout
    if bytes_total > 10_000_000:
        parts.append(f"— {bytes_total / 1_048_576:.1f} MB outbound")
    elif bytes_total > 100_000:
        parts.append(f"— {bytes_total / 1024:.0f} KB outbound")

    # Pattern label
    parts.append(f"— {fanout}")

    text = ", ".join(parts[:4]) + " " + " ".join(parts[4:])

    return {
        "chunk_id": chunk.chunk_id,
        "entity": entity,
        "strategy": strategy_label,
        "t_start": chunk.t_start,
        "t_end": chunk.t_end,
        "n_events": n,
        "duration_sec": dur,
        "burst_label": burst,
        "fanout_label": fanout,
        "text": text.strip(),
        "stats": s,
    }


# ─── Point B: Incident Summarizer ─────────────────────────────────────────────

_POINT_B_SYSTEM = (
    "You are a cyber-incident analyst assistant. "
    "You receive a list of behavioral observations (Point-A summaries) from an "
    "ongoing investigation. Produce ONE concise, coherent incident narrative "
    "(3-5 sentences) that describes what happened, in chronological order, using "
    "the ATT&CK technique IDs where mentioned. "
    "Output ONLY the narrative — no headers, no bullet points. "
    "Do NOT invent facts or technique IDs not present in the input."
)

_DISCLAIMER = "[LLM-assisted narrative — non-authoritative, for analyst review only]"


def _template_fallback(summaries: list[dict], technique_chain: list[str]) -> str:
    """Deterministic fallback when no LLM is available."""
    if not summaries:
        return "No notable activity detected in this incident window."

    entities = list(dict.fromkeys(s["entity"] for s in summaries))
    total_events = sum(s["n_events"] for s in summaries)
    texts = [s["text"] for s in summaries]

    entity_str = ", ".join(entities[:3]) + ("..." if len(entities) > 3 else "")
    tchain = " → ".join(technique_chain[:6]) if technique_chain else "unknown"

    narrative = (
        f"Investigation covers {len(entities)} actor(s) ({entity_str}) "
        f"across {len(summaries)} behavioral windows totalling {total_events} events. "
        f"Observed ATT&CK chain: {tchain}. "
        f"Key observations: {' '.join(texts[:3])}"
    )
    return narrative


def _call_gemini(prompt: str) -> str | None:
    """Attempt a Gemini API call. Returns None on any failure."""
    api_key = os.getenv("GEMINI_API_KEY", "")
    if not api_key:
        return None
    try:
        import urllib.request, json as _json
        url = (
            "https://generativelanguage.googleapis.com/v1beta/models/"
            f"gemini-1.5-flash:generateContent?key={api_key}"
        )
        body = _json.dumps({
            "system_instruction": {"parts": [{"text": _POINT_B_SYSTEM}]},
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"maxOutputTokens": 300, "temperature": 0.2},
        }).encode()
        req = urllib.request.Request(url, data=body,
                                     headers={"Content-Type": "application/json"},
                                     method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = _json.loads(resp.read())
        return data["candidates"][0]["content"]["parts"][0]["text"].strip()
    except Exception:
        return None


def summarize_incident(
    chunk_summaries: list[dict],
    technique_chain: list[str],
    *,
    use_llm: bool = True,
) -> dict:
    """Point B: condense all Point-A summaries into one incident narrative.

    This is the ONLY place in the pipeline where an LLM is used.
    Falls back to template concatenation if GEMINI_API_KEY is not set.

    Args:
        chunk_summaries: list of Point-A summary dicts (from summarize_chunk).
        technique_chain: ordered list of ATT&CK technique IDs seen so far.
        use_llm:         set False to force template fallback (useful in tests).

    Returns:
        {
          "narrative":        str,   ← the coherent incident summary
          "method":           str,   ← "llm" | "template"
          "authoritative":    bool,  ← always False; LLM output is advisory only
          "disclaimer":       str,
          "technique_chain":  list[str],
          "n_chunks":         int,
        }
    """
    narrative: str
    method: str

    if use_llm:
        obs_lines = "\n".join(f"- {s['text']}" for s in chunk_summaries)
        tchain = " → ".join(technique_chain) if technique_chain else "none identified"
        prompt = (
            f"ATT&CK technique chain so far: {tchain}\n\n"
            f"Behavioral observations:\n{obs_lines}"
        )
        llm_result = _call_gemini(prompt)
        if llm_result:
            narrative = llm_result
            method = "llm"
        else:
            narrative = _template_fallback(chunk_summaries, technique_chain)
            method = "template"
    else:
        narrative = _template_fallback(chunk_summaries, technique_chain)
        method = "template"

    return {
        "narrative": narrative,
        "method": method,
        "authoritative": False,   # HARD RULE: LLM output is never authoritative
        "disclaimer": _DISCLAIMER if method == "llm" else "",
        "technique_chain": technique_chain,
        "n_chunks": len(chunk_summaries),
    }
