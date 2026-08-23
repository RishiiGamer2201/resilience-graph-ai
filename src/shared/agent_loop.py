"""A real multi-agent lane, bounded so it cannot decide anything.

WHAT THIS IS. Two agents over a fixed tool surface: an Investigator that gathers
evidence from the attack graph and writes a hypothesis, and a Critic that is
given the same tools and told to REFUTE it. Both run on whatever provider is
configured; both degrade to a deterministic template when none is.

WHY IT SITS HERE AND NOT UPSTREAM. The economics decide the placement, not taste.
At roughly a million events a day, an LLM on events costs about 200M tokens a day
and cascades one bad routing decision through everything downstream. On incidents
it is 10 to 50 items and a couple of million tokens. So: deterministic below the
choke point -- normalise, score, correlate, graph -- and agentic only above it,
where the input is already reduced to a handful of stories.

WHAT IT MAY NOT DO, enforced here rather than requested in a prompt:
  * it cannot run a query, fetch a URL, or read a file. Seven named tools, typed
    arguments, each a wrapper over a tested deterministic function;
  * a claim citing an evidence id it was never shown is REJECTED in code. A model
    cannot be trusted to police its own citations, so it is not asked to;
  * it never scores, ranks, gates or approves. The policy engine and the detector
    are untouched by it. Its output is advisory and labelled as such.

WHY A CRITIC. Published work on multi-agent alert triage (CORTEX) puts the
false-positive rate on non-actionable predictions at 24.9% single-agent against
14.2% with a refuting second agent, at roughly 5.7x the tokens. The refutation is
the part that buys the accuracy, so it is the part implemented. The Critic
defaults to `refuted` under uncertainty, because a security tool that resolves
ambiguity in favour of alarming is the failure mode this repo exists to avoid.

    from src.shared.agent_loop import investigate_with_agents
    out = investigate_with_agents(bundle)
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from src.shared import agent_tools, llm


# Decoder-level schemas. The prompt asks; these CONSTRAIN. Handed only a prompt,
# the model returned a different shape entirely and invented six alerts that were
# in no tool output, which the citation check caught and which is exactly the
# failure this closes at the source.
HYPOTHESIS_SCHEMA = {
    "type": "object",
    "properties": {
        "hypothesis": {"type": "string"},
        "techniques": {"type": "array", "items": {"type": "string"}},
        "confidence": {"type": "number"},
        "evidence_ids": {"type": "array", "items": {"type": "string"}},
        "missing": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["hypothesis", "techniques", "confidence", "evidence_ids", "missing"],
    "additionalProperties": False,
}
VERDICT_SCHEMA = {
    "type": "object",
    "properties": {
        "refuted": {"type": "boolean"},
        "reasons": {"type": "array", "items": {"type": "string"}},
        "missing_evidence": {"type": "array", "items": {"type": "string"}},
        "alternative": {"type": "string"},
    },
    "required": ["refuted", "reasons", "missing_evidence", "alternative"],
    "additionalProperties": False,
}
# Strict mode rejects `additionalProperties: true` anywhere in the schema, so the
# arguments cannot be a free-form object. They are a fixed pair instead, and the
# only two arguments any tool takes: `host` for the containment counterfactual,
# `limit` for the two list tools. Empty string and 0 mean "not supplied", which
# is how a strict schema expresses optional.
TOOL_SCHEMA = {
    "type": "object",
    "properties": {
        "tool": {"type": "string"},
        "host": {"type": "string"},
        "limit": {"type": "integer"},
        "done": {"type": "boolean"},
    },
    "required": ["tool", "host", "limit", "done"],
    "additionalProperties": False,
}


def _args_from(reply: dict, name: str) -> dict:
    """Flatten the strict-schema fields back into real kwargs for ONE tool.

    Strict mode requires every declared key, so the model dutifully sends
    `host` and `limit` to all seven tools -- including the five that take
    neither. Filtering against the tool's own signature is what stops that
    becoming "bad arguments for graph_summary" seven times in a row.
    """
    ok = agent_tools.accepts(name)
    out: dict = {}
    host = (reply.get("host") or "").strip()
    if host and "host" in ok:
        out["host"] = host
    try:
        limit = int(reply.get("limit") or 0)
    except (TypeError, ValueError):
        limit = 0
    if limit > 0 and "limit" in ok:
        out["limit"] = min(limit, 50)
    return out


# These models reason before answering, so a small budget is spent thinking and
# the request fails with "max completion tokens reached before generating a valid
# document". Measured against the shipped default, not guessed.
AGENT_MAX_TOKENS = 2600

MAX_TOOL_CALLS = 6          # bounded by construction; there is no loop to run away
MAX_CRITIC_ROUNDS = 1

_INVESTIGATOR = """You are a SOC analyst examining ONE already-correlated incident.

You have these tools. Call them to gather evidence before concluding anything:
{tools}

Reply with JSON only, no prose outside it:
{{"tool": "<name>", "args": {{}}}}            to call a tool, or
{{"hypothesis": "...", "techniques": ["T1234"], "confidence": 0.0-1.0,
  "evidence_ids": ["alert-000"], "missing": ["what would settle this"]}}

Rules you will be checked against:
- Cite ONLY evidence_id values that appeared in tool output you received.
- A claim marked `inferred` is weaker than one marked `observed`. Say which.
- If the calibration tool says the scores are ranked within this log, do not
  describe a score as a severity or compare it to another log.
- You do not decide containment. Describe what happened, not what to do."""

_CRITIC = """You are reviewing another analyst's incident hypothesis. Your job is
to REFUTE it, not to agree with it. You have the same tools:
{tools}

The hypothesis:
{hypothesis}

Reply with JSON only:
{{"tool": "<name>", "args": {{}}}}            to check something first, or
{{"refuted": true|false, "reasons": ["..."], "missing_evidence": ["..."],
  "alternative": "a benign or different explanation that fits the same evidence"}}

Set refuted=true if the evidence does not clearly support the hypothesis.
Default to refuted=true when uncertain: an unsupported alarm costs more than a
withheld one. An anomaly means unusual, never adversarial."""


@dataclass
class AgentRun:
    """One agent lane, with everything needed to audit it after the fact."""
    provider: str = "template"
    # Which path produced this. `provider` alone is ambiguous: a run that called
    # groq, was rate limited, and fell back to the template still reports
    # provider="groq", which read on screen as though a model had answered.
    method: str = "template"             # "agents" | "template"
    hypothesis: str = ""
    techniques: list[str] = field(default_factory=list)
    confidence: float = 0.0
    evidence_ids: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    refuted: bool | None = None
    critic_reasons: list[str] = field(default_factory=list)
    alternative: str = ""
    tool_calls: list[dict] = field(default_factory=list)
    rejected_citations: list[str] = field(default_factory=list)
    authoritative: bool = False          # never true. Kept explicit, not implied.
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {**self.__dict__, "authoritative": False}


def _json(text: str) -> dict | None:
    """Pull the first JSON object out of a reply. Models add prose regardless."""
    if not text:
        return None
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except json.JSONDecodeError:
        return None


def _ask(system: str, prompt: str, schema: dict | None = None) -> tuple[dict | None, str]:
    res = llm.complete(system, prompt, schema=schema, max_tokens=AGENT_MAX_TOKENS)
    return (_json(res.text) if res.ok else None), (res.provider if res.ok else "")


def _run_agent(system: str, opening: str, bundle: dict, run: AgentRun,
               conclude_hint: str, final_schema: dict, who: str = 'agent') -> tuple[dict | None, list[dict]]:
    """Gather with tools, then conclude. Two phases, because one does not work.

    Each provider call is stateless, so the transcript carries the state. Told
    only to "continue", a model keeps calling tools -- it repeated one forever
    until the transcript said which had already been called, and then kept
    gathering rather than committing. Offering the tool option at all, in the
    same breath as the conclusion schema, is what makes it keep taking it.

    So the final call is a DIFFERENT call, whose schema has no `tool` key to pick.
    """
    seen: list[dict] = []
    called: list[str] = []
    transcript = opening

    # phase 1: gather
    for _ in range(MAX_TOOL_CALLS):
        prompt = transcript
        if called:
            prompt += (f"\n\nAlready called: {', '.join(called)}. "
                       "Call a DIFFERENT tool, or reply {\"done\": true}.")
        reply, provider = _ask(system, prompt, TOOL_SCHEMA)
        if provider:
            run.provider = provider
        if reply is None or reply.get("done") or not reply.get("tool"):
            break
        name = str(reply.get("tool"))
        if name in called:
            transcript += f"\n\n{name} was already called."
            continue
        args = _args_from(reply, name)
        result = agent_tools.call(name, bundle, **args)
        seen.append(result)
        called.append(name)
        # labelled, because the Investigator and the Critic share this list and
        # the same tool legitimately appears twice for different reasons
        run.tool_calls.append({"agent": who, "tool": name, "args": args,
                               "rows": len(result.get("rows", [])),
                               "error": result.get("error")})
        transcript += (f"\n\nYou called {name}({args}). Result:\n"
                       f"{json.dumps(result)[:1800]}")

    # phase 2: conclude, with the tool option removed from the schema
    final, provider = _ask(system + "\n\n" + conclude_hint,
                           transcript + "\n\nNow give ONLY the final JSON object.",
                           final_schema)
    if provider:
        run.provider = provider
    return final, seen


def _template(bundle: dict) -> AgentRun:
    """The deterministic path. Not a degraded mode: the DEFAULT one.

    With no provider configured this is what runs, and it must produce the same
    shape so nothing downstream can tell the difference structurally. It states
    the graph facts and refuses to interpret them, which is the honest thing a
    non-model can do.
    """
    g = bundle.get("graph") or {}
    inc = bundle.get("incident") or {}
    techs = inc.get("technique_ids", [])[:6]
    pivot = g.get("recommended_isolation") or g.get("entry_host") or "unknown"
    run = AgentRun(provider="template")
    run.hypothesis = (
        f"{inc.get('alert_count', 0)} alerts across {g.get('n_nodes', 0)} hosts, "
        f"clustered into {inc.get('incident_count', 1)} incident(s). The busiest "
        f"origin is {pivot}; isolating it severs {g.get('isolation_cuts', 0)} hosts "
        f"of reachability. Techniques observed: {', '.join(techs) or 'none mapped'}.")
    run.techniques = techs
    run.confidence = 0.0
    # Which of the two reasons applies is not cosmetic. "No provider" is the
    # designed default; "the provider failed" is an operational fact someone
    # needs to see. Printing the first for both made a live 429 look like a
    # deliberate configuration.
    if llm.chosen_provider():
        run.notes.append("the language model did not produce a usable answer, so "
                         "this is the deterministic summary: it states graph facts "
                         "and does not interpret them")
    else:
        run.notes.append("no language model configured: this is the deterministic "
                         "summary, which states graph facts and does not interpret them")
    return run


def investigate_with_agents(bundle: dict) -> dict:
    """Investigator, then Critic. Advisory output, never authoritative."""
    if not llm.chosen_provider():
        return _template(bundle).as_dict()

    run = AgentRun()
    tools = agent_tools.describe()

    opening = ("Incident under review. Start by calling a tool.\n"
               f"Alerts: {bundle.get('incident', {}).get('alert_count')}, "
               f"hosts in graph: {(bundle.get('graph') or {}).get('n_nodes')}.")
    final, seen = _run_agent(
        _INVESTIGATOR.format(tools=tools), opening, bundle, run,
        'FINAL ANSWER ONLY. Reply with exactly this shape and nothing else:\n'
        '{"hypothesis": "...", "techniques": ["T1234"], "confidence": 0.5, '
        '"evidence_ids": ["alert-000"], "missing": ["..."]}\n'
        'There is no "tool" key in this reply.', HYPOTHESIS_SCHEMA, 'investigator')

    if not final or "hypothesis" not in final:
        out = _template(bundle)
        out.provider = run.provider or "template"
        out.tool_calls = run.tool_calls   # _template already names the reason
        return out.as_dict()

    run.method = "agents"
    run.hypothesis = str(final.get("hypothesis", ""))[:1200]
    run.techniques = [t for t in (final.get("techniques") or []) if isinstance(t, str)][:12]
    try:
        run.confidence = max(0.0, min(1.0, float(final.get("confidence", 0))))
    except (TypeError, ValueError):
        run.confidence = 0.0
    run.missing = [str(m)[:200] for m in (final.get("missing") or [])][:6]

    # Citations are checked, not requested. Anything the agent did not actually
    # see is dropped and recorded, and losing all of them costs it its confidence.
    shown = agent_tools.evidence_ids(seen)
    cited = [str(e) for e in (final.get("evidence_ids") or [])]
    run.evidence_ids = [e for e in cited if e in shown]
    run.rejected_citations = [e for e in cited if e not in shown]
    if run.rejected_citations:
        run.notes.append(
            f"{len(run.rejected_citations)} citation(s) rejected: not in any tool "
            "output this agent received")
    if not run.evidence_ids:
        run.confidence = 0.0
        run.notes.append("no surviving citations, so confidence is reported as zero")

    critic, _ = _run_agent(
        _CRITIC.format(tools=tools, hypothesis=run.hypothesis),
        "Review the hypothesis. Call a tool to check it, or reply {\"done\": true}.",
        bundle, run,
        'FINAL ANSWER ONLY. Reply with exactly this shape and nothing else:\n'
        '{"refuted": true, "reasons": ["..."], "missing_evidence": ["..."], '
        '"alternative": "..."}\n'
        'There is no "tool" key in this reply.', VERDICT_SCHEMA, 'critic')
    if critic and "refuted" in critic:
        run.refuted = bool(critic.get("refuted"))
        run.critic_reasons = [str(r)[:240] for r in (critic.get("reasons") or [])][:5]
        run.alternative = str(critic.get("alternative", ""))[:400]
    else:
        # No verdict is not agreement. Uncertainty resolves against the alarm.
        run.refuted = True
        run.notes.append("the critic returned no usable verdict, which is recorded "
                         "as refuted: an unreviewed hypothesis is not a corroborated one")
    if run.refuted:
        run.confidence = min(run.confidence, 0.3)
        run.notes.append("confidence capped because the review did not stand it up")
    return run.as_dict()


def demo() -> None:
    """Self-check. Runs offline: asserts the template path and the guards."""
    bundle = {
        "incident": {"alert_count": 26, "incident_count": 2,
                     "technique_ids": ["T1110", "T1078"], "steps": []},
        "graph": {"n_nodes": 25, "n_edges": 23, "recommended_isolation": "WARD-PC-013",
                  "isolation_cuts": 22},
        "meta": {"calibration": {"basis": "ranked-within-this-log"}},
    }
    out = investigate_with_agents(bundle)
    assert out["authoritative"] is False, "agent output must never be authoritative"
    assert "WARD-PC-013" in out["hypothesis"]

    # citation filtering: an id never shown must not survive
    run = AgentRun()
    shown = agent_tools.evidence_ids([{"rows": [{"evidence_id": "alert-000"}]}])
    cited = ["alert-000", "alert-999"]
    kept = [c for c in cited if c in shown]
    assert kept == ["alert-000"], kept

    assert _json('noise {"a": 1} tail') == {"a": 1}
    assert _json("no json here") is None
    print(f"agent loop ok: provider={out['provider']}, "
          f"authoritative={out['authoritative']}, "
          f"bounded at {MAX_TOOL_CALLS} tool calls")


if __name__ == "__main__":
    demo()
