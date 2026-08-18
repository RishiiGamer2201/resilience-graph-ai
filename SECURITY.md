# Security

## What this is

nextATT&CKs is a hackathon demonstration of AI-driven cyber resilience. It is
**not** a production security product, and it is not deployed in front of anyone's
real infrastructure.

The full analysis — assets, trust boundaries, nine threats with the control, the test
that proves it, and the honest residual risk — is in
[`docs/security/threat-model.md`](docs/security/threat-model.md).

## Reporting a vulnerability

Open a GitHub issue for anything in a public demo, or contact the repository owner
directly for something you would rather not post. There is no bounty and no SLA; this
is a hackathon project and we will say so rather than imply a process we do not run.

Please include the endpoint or file, what you did, and what happened.

## Design guarantees we do make

- **No action is ever executed against a real system.** Every response is simulated.
  A card on the scoreboard reports the measured count of executed actions: zero.
- **Authorisation is enforced server-side** on every mutating endpoint. Hiding a
  button in the UI is not access control, and there are tests for the refusals.
- **All outbound HTTP is allowlisted and SSRF-guarded** — scheme check, host
  allowlist, resolved-address check against private ranges, re-validated redirects,
  timeouts and size caps. One function, `src/shared/nethttp.fetch_url`, with a test
  that fails if any caller bypasses it.
- **No secrets are required and none are stored.** The product runs with zero
  credentials. Optional keys (OTX, ThreatFox, role tokens) are read from the
  environment and never returned by an endpoint or exposed to the browser.
- **Uploaded data is never persisted.** Analysis is in memory; nothing is written to
  disk; nothing is transmitted anywhere.
- **Retrieved document text is evidence, never instruction.** There is no LLM in any
  decision path to inject into, and displayed excerpts are sanitised.
- **Model artifacts are trusted build outputs**, committed to the repository and
  copied by the Dockerfile. No user-supplied path reaches a pickle loader; there is no
  "upload a model" feature. Artifact hashes are stamped into every audit record.

## Limitations we state rather than hide

- **The default is authorisation without authentication.** The caller declares a role
  in `X-Role`, deliberately, so a judge can switch roles and watch the server refuse
  with no signup. `/api/capabilities` reports `auth_mode: "demo-headers"` in plain
  words. Setting `NEXTATTACK_ROLE_TOKENS` switches to bearer tokens compared in
  constant time. Neither is an identity provider.
- **The audit chain is tamper-evident, not tamper-proof**, and it is not a blockchain.
  Its own export says so. It is session-scoped and held in memory, because the free
  host has an ephemeral filesystem and we will not imply durability we do not have.
- **There is no rate limiting.** A public deployment could be exhausted by a flood.
  Acceptable for a demo; a limiter at the edge is required for anything more.
- **Single-tenant assumption.** Any caller with the `read` permission can see the
  in-memory audit chain for the lifetime of the process.

## Scope for a report

In scope: SSRF or allowlist bypass, authorisation bypass, audit-chain forgery that
verification misses, deserialization or path traversal, injection through an uploaded
log, and anything that causes the product to state a number or a citation it cannot
support.

Out of scope: the absence of authentication and rate limiting (documented above),
denial of service by volume, and issues that require repository write access.
