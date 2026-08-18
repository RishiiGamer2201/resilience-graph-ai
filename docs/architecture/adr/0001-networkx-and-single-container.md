# ADR 0001 — Keep NetworkX in-process and one container

- **Status:** accepted
- **Date:** 2026-08-18
- **Deciders:** finalist hardening pass
- **Supersedes:** nothing. This records a decision the repo already embodied but
  never wrote down, because the team proposed replacing it.

## Context

The proposed finalist stack included Neo4j AuraDB for the attack graph and a split
frontend/backend deployment (Vercel for the SPA, Render/Railway for the API). The
repo today runs NetworkX in the API process and ships one Docker image in which
FastAPI serves the built SPA from the same origin.

The graph work this product does is: reachability from every attacker pivot,
shortest path to each crown jewel, betweenness centrality for choke points, and —
new in this pass — a counterfactual that clones the graph, removes a node and
recomputes all of the above.

## Decision

**Keep NetworkX as the required, default and only graph engine. Keep the
single-container deployment.** A Neo4j adapter may be added later behind a
repository boundary, but it must never be required for local development, the test
suite, or the demo.

## Why

**The workload is small and the library is not the bottleneck.** The full LANL
red-team campaign produces a 473-node, 484-edge graph. Neo4j Aura Free tops out at
200,000 nodes — we are three orders of magnitude inside it. A graph database solves
a problem we do not have.

**Free-tier graph hosting fails exactly when a demo needs it.** AuraDB Free pauses
after 72 hours of inactivity and needs a manual console resume
(`docs/research/free-tier-and-stack.md`). The gap between building the demo and
presenting it is usually longer than 72 hours. A dependency that has to be
hand-woken before it works is a worse demo than no dependency.

**Credentials are a demo failure mode.** The required path must run from a fresh
clone with no account. Every managed service added is another thing that can be
down, expired, rate-limited or misconfigured on the one morning it matters.

**The counterfactual is cheaper in-process.** The digital twin clones the graph and
recomputes reachability for every candidate host. In-process that is a dict copy and
a BFS. Against a remote database it is N round trips per candidate — and we
measured this shape of cost already: recomputing betweenness centrality per
candidate took 5.9 s until we removed it. Network latency would have been worse and
harder to fix.

**One origin removes a class of bugs.** FastAPI serving `frontend/dist` means no
CORS configuration, one URL to warm up, one thing to deploy, one place where a
version skew between API and SPA cannot happen.

## Consequences

- Graph state lives in the request. The API is stateless: the client posts the graph
  back for a twin simulation, so the twin always operates on the incident on screen.
- Scale is bounded and documented: comfortable to about 50,000 events per analysis
  (measured, `reports/scaling_measurements.json`); beyond that we shard or move to a
  graph database.
- `src/shared/twin.py::graph_from_view` is the seam. It rebuilds a `DiGraph` from the
  JSON payload; a Neo4j adapter would implement the same contract.

## What would change our mind

- A single analysis routinely exceeding ~50,000 events, or a graph beyond ~100k
  nodes, where in-memory betweenness stops being interactive.
- A requirement for the graph to **persist and be queried across sessions** by more
  than one user — the point at which "stateless per request" stops being honest.
- Multi-hop Cypher queries that are genuinely awkward in NetworkX. We have not hit
  one; every question so far is reachability, shortest path or centrality.
