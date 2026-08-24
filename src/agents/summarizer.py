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
    narrative for the Reasoning Agent. Which provider, if any, is decided by
    src.shared.llm (NEXTATTACK_LLM_PROVIDER plus that provider's key); with
    none configured it falls back to deterministic template concatenation.
    LLM output is ALWAYS labelled non-authoritative.

Usage:
    from src.agents.summarizer import summarize_chunk, summarize_incident
    point_a = summarize_chunk(chunk)
    point_b = summarize_incident(point_a_summaries, technique_chain)
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from src.shared import llm
from src.shared.llm import LLMResult

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

# Written for the smallest model any provider defaults to. The first version of
# this prompt asked for "a coherent narrative" and got "Over a period of time,
# multiple users made numerous successful login attempts" -- fluent, true of
# every auth log ever written, and useless to a responder. Naming the specific
# failure modes is what a small model needs; a large one avoids them unprompted.
_POINT_B_SYSTEM = (
    "You are a cyber-incident analyst assistant. "
    "You receive a list of behavioral observations (Point-A summaries) from an "
    "ongoing investigation. Produce ONE incident narrative of 3-5 sentences "
    "describing what happened, in chronological order, using the ATT&CK "
    "technique IDs where they are given.\n"
    "\n"
    "Write it the way an analyst hands an incident to the next shift:\n"
    "- Lead with the specific account and host the activity starts from. Name "
    "them. 'A user' and 'multiple users' are failures, not summaries.\n"
    "- Give the numbers you were given: how many hosts, how many events, over "
    "what span. Never write 'over a period of time' when you were given one.\n"
    "- Say what the pattern is (fan-out, burst, off-hours), not merely that it "
    "was 'unusual' or 'abnormal'.\n"
    "- End on what an adversary would do next from here, if the observations "
    "support it. If they do not, end on what is still unknown.\n"
    "\n"
    "Hard rules:\n"
    "- Use ONLY facts present in the input. Do not invent accounts, hosts, "
    "counts, times or technique IDs, and do not round a number you were given.\n"
    "- Do not recommend an action, assign a severity, or state a probability. "
    "Those are computed elsewhere and you will be contradicting them.\n"
    "- Output ONLY the narrative: no headers, no bullet points, no preamble."
)

_DISCLAIMER = "[LLM-assisted narrative — non-authoritative, for analyst review only]"


def _technique_friendly_name(tid: str) -> str:
    """Look up friendly name for an ATT&CK technique if available."""
    try:
        from src.shared.views import _names
        names = _names()
        return names.get(tid, tid)
    except Exception:
        return tid


def _template_fallback(summaries: list[dict], technique_chain: list[str]) -> str:
    """Deterministic natural-language incident narrative synthesis."""
    if not summaries:
        return "No notable anomalous activity or lateral movement detected in this incident window."

    entities = list(dict.fromkeys(s["entity"] for s in summaries if s.get("entity")))
    total_events = sum(s.get("n_events", 1) for s in summaries)
    entity_str = ", ".join(entities[:2]) if entities else "an unidentified account"
    if len(entities) > 2:
        entity_str += f" and {len(entities) - 2} other account(s)"

    # Identify primary pattern indicators
    has_burst = any("high frequency" in s.get("burst_label", "") for s in summaries)
    has_fanout = any("fan-out" in s.get("fanout_label", "") for s in summaries)
    unique_dsts = max((s.get("stats", {}).get("destination_host_unique", 1) for s in summaries), default=1)

    # Translate technique chain into readable tactical progression
    friendly_techs = [_technique_friendly_name(t) for t in technique_chain[:4]]
    tech_flow = " followed by ".join(friendly_techs) if friendly_techs else "unusual credential activity"

    # Construct plain-language narrative paragraph
    sentences = []
    sentences.append(
        f"The intrusion initiated with anomalous authentication activity linked to {entity_str}, "
        f"generating {total_events} total events across {len(summaries)} behavioral observation windows."
    )
    if has_fanout or unique_dsts > 1:
        spread_desc = f"rapid lateral spread across {unique_dsts} unique internal endpoints" if unique_dsts > 1 else "lateral movement attempts"
        rate_desc = " in rapid succession" if has_burst else ""
        sentences.append(f"The adversary established an initial foothold and exhibited {spread_desc}{rate_desc}.")
    if friendly_techs:
        sentences.append(
            f"The attack path matches known adversary behaviors progressing through {tech_flow}, "
            f"indicating an organized attempt to escalate privileges and access central infrastructure."
        )
    else:
        sentences.append(
            "Telemetry patterns indicate coordinated unauthorized traversal across endpoints "
            "consistent with an active security breach."
        )

    sentences.append(
        "Immediate isolation of the active entry host is recommended to sever the attacker's "
        "path before critical domain assets are compromised."
    )

    return " ".join(sentences)


# Point B's remote call. It does not talk to a provider itself: src.shared.llm
# owns provider selection, the key table, retries and the egress guard, and it
# is what /api/health and /api/capabilities report on. This used to call Gemini
# directly off GEMINI_API_KEY, which meant an operator could set
# NEXTATTACK_LLM_PROVIDER=openai with a valid key, see /api/health report
# "active_provider: openai", and still get a template here -- with no error,
# because a missing GEMINI_API_KEY simply returned None. A provider that the
# product says is on must be on everywhere, or the status is a lie.
def _call_llm(prompt: str, untrusted: str = "") -> LLMResult:
    """Ask the configured provider to word the Point-B narrative.

    Returns an LLMResult in every case, including "no provider configured".
    The caller falls back to the deterministic template on anything but ok.
    """
    # No max_tokens here on purpose: complete() forwards it to groq only, so
    # passing one would read as a budget that openai and gemini quietly ignore.
    # Length is the system prompt's job ("3-5 sentences") and llm.MAX_OUTPUT_TOKENS'.
    return llm.complete(_POINT_B_SYSTEM, prompt, untrusted_seen=untrusted)


def summarize_incident(
    chunk_summaries: list[dict],
    technique_chain: list[str],
    *,
    use_llm: bool = True,
) -> dict:
    """Point B: condense all Point-A summaries into one incident narrative.

    This is the ONLY place in the pipeline where an LLM is used.
    Falls back to template concatenation when src.shared.llm has no provider
    configured, or when the one configured fails to answer.

    Args:
        chunk_summaries: list of Point-A summary dicts (from summarize_chunk).
        technique_chain: ordered list of ATT&CK technique IDs seen so far.
        use_llm:         set False to force template fallback (useful in tests).

    Returns:
        {
          "narrative":        str,   ← the coherent incident summary
          "method":           str,   ← provider name ("openai") | "template"
          "provider":         str,   ← who answered; "none" if none configured
          "model":            str,
          "llm_error":        str,   ← why a configured provider produced nothing
          "injection_flagged": bool, ← instruction-like text in the log fields
          "authoritative":    bool,  ← always False; LLM output is advisory only
          "disclaimer":       str,
          "technique_chain":  list[str],
          "n_chunks":         int,
        }
    """
    narrative: str
    method: str

    provider = model = ""
    llm_error = ""
    injection_flagged = False

    if use_llm:
        obs_lines = "\n".join(f"- {s['text']}" for s in chunk_summaries)
        tchain = " → ".join(technique_chain) if technique_chain else "none identified"
        # The technique chain is ours, off the ATT&CK table. The observation
        # lines carry account and host names lifted out of the customer's log,
        # so they are third-party text and belong in the fenced half -- an
        # attacker who can name a machine could otherwise write into this prompt.
        prompt = llm.render(_POINT_B_SYSTEM,
                            context=f"ATT&CK technique chain so far: {tchain}",
                            untrusted=f"Behavioral observations:\n{obs_lines}")
        res = _call_llm(prompt, untrusted=obs_lines)
        provider, model = res.provider, res.model
        llm_error = res.error
        injection_flagged = res.injection_flagged
        if res.ok and res.text.strip():
            narrative = res.text.strip()
            # The provider name, not a bare "llm". The UI prints this verbatim
            # beside the narrative, and "openai" tells a reader where their
            # incident text went; "llm" does not.
            method = provider
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
        "disclaimer": _DISCLAIMER if method != "template" else "",
        "provider": provider,
        "model": model,
        # Empty when no provider was asked for. Non-empty means one WAS asked
        # for and did not answer -- an operational fact, not the default.
        "llm_error": llm_error,
        "injection_flagged": injection_flagged,
        "technique_chain": technique_chain,
        "n_chunks": len(chunk_summaries),
    }
