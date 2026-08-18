# ADR 0002 — A hand-rolled bounded state graph, not LangGraph

- **Status:** accepted
- **Date:** 2026-08-18

## Context

PS7 asks for a visible, inspectable reasoning process: Understand → Plan → Evidence
→ Signals → Replan → Impact → Action. The proposed stack named LangGraph. We had to
decide whether to adopt it or express the same graph in plain Python.

What the workflow actually is, once written down:

- seven nodes in a **fixed order**;
- **one** conditional edge (`replan` may re-run `evidence`), bounded to a single
  retry by construction — there is no loop in the code to run away;
- every node is a call into a domain function that already exists in `src/shared/`
  and is already tested;
- no tool selection by a model, no dynamic routing, no agent deciding what to do
  next. The plan node *records* which deterministic tools this case needs; it does
  not invent them.

## Decision

**Implement the graph as `src/shared/workflow.py`: typed `NodeResult`s, a `Trace`
that times every node, and an orchestrator with one bounded retry.** Do not add
LangGraph.

## Why

**The framework's value is in the parts we do not use.** LangGraph earns its keep on
cyclic agent graphs, persistence/checkpointing, human-in-the-loop interrupts across
process restarts, and streaming multi-agent state. Our graph is a straight line with
one retry, executed inside one request in about 50 ms. We would import an
orchestration framework to run a `for` loop.

**Its advisory history sits on our exact risk surface.** Eight published advisories
between Oct 2025 and Jul 2026 (`docs/research/free-tier-and-stack.md`), and the
recurring themes are unsafe deserialization of checkpoints (`JsonPlusSerializer`
RCE, msgpack, JSON, `BaseCache`) and injection through filter keys. A cyber-defence
product whose orchestration layer historically deserializes untrusted state is a bad
trade for syntax sugar. Patched versions exist; the point is that we would be taking
on a class of risk to gain nothing.

**Deploy weight matters here.** `requirements-deploy.txt` is nine packages and the
container boots in seconds on a free host that spins down every 15 minutes. Adding
LangChain-adjacent dependencies to that image lengthens the cold start we already
warn judges about.

**Boundedness is easier to prove than to configure.** `MAX_REPLANS = 1` and a test
asserting `nodes.count("evidence") <= 2` is a claim a judge can check in ten seconds.
"We configured a recursion limit" is not.

## Consequences

- `workflow.py` owns orchestration only. Every node delegates: `_n_signals` calls
  `live_analyze.analyze_events`, `_n_impact` calls `twin` and `vuln`, `_n_action`
  calls `soar` and `rbac`. No analysis logic is duplicated — that was the
  precondition for building it at all.
- Node failure is typed, not fatal: a node returns `status: "degraded"` and the
  investigation continues. Only `signals` is `required=True`.
  `tests/test_workflow.py::test_a_broken_optional_stage_degrades_rather_than_erasing_the_case`
  breaks the evidence retriever and asserts the detection and the response survive.
- The trace is a plain dict, so `/api/investigate` returns it and the UI renders real
  per-node timings rather than a decorative progress bar.
- We give up: durable checkpoints across restarts, resumable human-in-the-loop
  interrupts, and a visual graph editor. We need none of them; the approval gate is
  a separate HTTP call against a session-scoped audit chain.

## What would change our mind

- Genuinely cyclic reasoning where the number of iterations is data-dependent and
  cannot be bounded at design time.
- A need to suspend an investigation mid-graph and resume it in a **different
  process** — which would mean durable persistence, which we have deliberately
  avoided (ADR 0001).
- More than roughly a dozen nodes with non-trivial conditional routing, at which
  point hand-rolled orchestration stops being the smaller thing.
