# Free-tier and stack research

Primary sources only, each with the URL and the date we read it. **Nothing here says
"free forever."** Every provider can change terms; re-check before the finale and
update the `as_of` date.

`as_of: 2026-08-18`

---

## Render — our default demo host

Source: <https://render.com/docs/free> (read 2026-08-18)

| Fact | Value |
|---|---|
| Web-service spin-down | Spins down after **15 minutes** with no inbound traffic |
| Cold start | Reactivation takes **about one minute**, showing a loading page |
| Free instance hours | **750 per workspace per calendar month**, no rollover; exceeding it suspends all free web services until the next month |
| Filesystem | **Ephemeral.** Anything written is lost on redeploy, restart or spin-down |
| Outbound bandwidth | Counted against a monthly included amount; exceeding it suspends the service (or bills, if a card is on file) |
| Free Postgres | **Expires 30 days after creation**, then a 14-day grace period before deletion. 1 GB storage, one instance per workspace |
| Free Key Value | In-memory only; all data lost on restart |

**What this forces in the product**

- The audit chain is **session-scoped and exportable**, not persisted. An ephemeral
  filesystem means a "saved" record is a lie waiting to be discovered on stage.
- `/api/readiness` exists and preloads small artifacts, so the one-minute wake-up is
  a known state rather than a mystery.
- We do **not** add keep-alive pings. That is exactly the behaviour the 750-hour
  budget is designed to price, and gaming it is against the spirit of the tier.
  Instead: a manual pre-demo warm-up (see `docs/operations/runbook.md`) and a
  recorded backup.
- Free Postgres expiring at 30 days is on its own enough to keep the demo path
  database-free.

---

## Supabase — optional durable persistence, not adopted

Source: <https://supabase.com/pricing> (read 2026-08-18)

| Fact | Value |
|---|---|
| Database size | 500 MB per project (shared CPU, 500 MB RAM) |
| Egress | 5 GB, plus 5 GB cached egress |
| Active projects | Up to 2 concurrent active free projects |
| Inactivity | Projects **pause after 1 week of inactivity** and need manual reactivation |

**Verdict: optional, behind an interface, off by default.** A finalist demo that can
be paused by a week of not touching it is a demo that fails on the morning it
matters. pgvector is available on Supabase, but see ADR 0003 — we do not need a
vector store for a 1,545-chunk corpus.

---

## Neo4j AuraDB Free — optional graph backend, not adopted

Sources: <https://neo4j.com/cloud/platform/aura-graph-database/faq/>,
<https://support.neo4j.com/s/article/4406830696083-Why-is-my-AuraDB-Free-Instance-Paused>
(read 2026-08-18)

| Fact | Value |
|---|---|
| Capacity | 200,000 nodes / 400,000 relationships |
| Instances | One free instance |
| Auto-pause | Paused automatically after **72 hours of inactivity** |
| Deletion | Deleted permanently after **90 days** paused |
| SLA | None on the free tier |

Capacity is not our constraint — the full LANL campaign graph is 473 nodes and 484
edges, three orders of magnitude inside the limit. The 72-hour auto-pause is the
constraint: a demo that has to be woken by hand in a console before it works is
worse than one that needs no account at all. See ADR 0001.

---

## Vercel Hobby — optional static mirror, not adopted

Source: <https://vercel.com/docs/plans/hobby> (read 2026-08-18)

| Fact | Value |
|---|---|
| Cost | Free |
| Eligibility | Fair-use guidelines **restrict Hobby to non-commercial, personal use only** |
| Included | 1,000,000 function invocations, 4 CPU-hrs active CPU, 1,000,000 edge requests, 100 deployments/day |
| Over-limit | In most cases the feature is unavailable until 30 days have passed |

**Verdict: not adopted.** Splitting the SPA off the API would add a CORS surface and
a second thing to warm up, in exchange for nothing the single container does not
already do. The non-commercial restriction is also worth flagging to the team before
anyone points a hackathon submission at it long-term.

---

## LangGraph — orchestration framework, not adopted

Source: <https://github.com/langchain-ai/langgraph/security> (read 2026-08-18)

Published advisories, most recent first:

| Advisory | Date | Severity | Summary |
|---|---|---|---|
| GHSA-47pj-3jcm-6whg | 2026-07-30 | Moderate | Namespace prefix matching crosses segment boundaries in Postgres/SQLite stores |
| GHSA-w39p-vh2g-g8g5 | 2026-05-22 | Moderate | Unsafe URL path construction in the SDK |
| GHSA-fjqc-hq36-qh5p | 2026-05-22 | Moderate | Unsafe JSON deserialization in checkpoint loading |
| GHSA-g48c-2wqr-h844 | 2026-03-05 | Moderate | Unsafe msgpack deserialization in checkpoint loading |
| GHSA-mhr3-j7m5-c7c9 | 2026-02-23 | Moderate | RCE in `BaseCache` deserialization |
| GHSA-9rwj-6rc7-p77c | 2025-12-09 | High | SQL injection via metadata filter key (SQLite checkpointer) |
| GHSA-wwqv-p2pp-99h5 | 2025-11-05 | High | RCE in `json` mode of `JsonPlusSerializer` |
| GHSA-7p73-8jqx-23r8 | 2025-10-29 | High | SQL injection via SQLite filter key |

Licence: MIT (open source, no LangSmith requirement for the core).

**Verdict: not adopted for this build.** See ADR 0002. The advisory pattern —
deserialization of checkpoints and injection through filter keys — sits precisely on
the two things a security product must not get wrong, and none of it buys us anything
for a seven-node graph with one bounded retry. Patched releases exist for each
advisory; if we ever adopt it we pin a current version and use neither untrusted
checkpointers nor caller-supplied filter keys.

---

## Ollama — optional local explanation provider, not required

Source: <https://docs.ollama.com/api/introduction> (read 2026-08-18)

Local HTTP API, no key, no account. Suitable as an **optional** wording layer behind
`ExplanationProvider`. Not wired into the hosted deployment: it would add a model
download and a second process to a container that currently boots in seconds, for
text that is explicitly non-authoritative. The deterministic template is the product.

---

## MITRE ATT&CK, CISA KEV, CERT-In — the evidence corpus

| Source | URL | Terms |
|---|---|---|
| MITRE ATT&CK STIX | <https://github.com/mitre-attack/attack-stix-data> | Apache 2.0; attribution required — see the notice at the foot of `README.md` |
| CISA KEV | <https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json> | US Government work, public domain; no key, no rate limit published |
| NVD / CVE detail pages | <https://nvd.nist.gov/vuln/detail/{CVE}> | Linked, not scraped. The NVD **API** is rate-limited and needs a key for volume, which is why CVSS enrichment is optional and CVSS shows as `unknown` by default |
| CERT-In advisories | <https://www.cert-in.org.in/> | **No working machine-readable feed.** Their RSS URLs return HTTP 200 with an HTML "URL not found" body. The four advisories we cite were read and transcribed by a teammate and are marked `verified: true` in `data/manual/cert_in_sequences.json` |

---

## What we did not verify, and therefore do not claim

- **Railway** and other hosts: not re-checked in this pass. Do not describe any of
  them as free in a pitch without re-reading their current terms and recording the
  date here.
- **NVD API throughput** under a key: not measured, because we do not depend on it.
- **Render bandwidth ceiling** in GB: the docs describe an included amount without
  a number on that page; we did not chase it because the demo transfers a few MB.
