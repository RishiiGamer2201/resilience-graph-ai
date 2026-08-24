# ADR 0008 — TypeScript, Tailwind and a design contract; supersedes 0004

- **Status:** accepted
- **Date:** 2026-08-23
- **Supersedes:** [ADR 0004 — the frontend stays as it is](0004-frontend-stays-as-is.md)

## Context

ADR 0004 argued against a TypeScript migration, Tailwind and shadcn on the
grounds that they were cost without benefit for a hackathon frontend: the app
worked, the CSS custom-property token system was disciplined, and
`tests/test_ui_contract.py` already policed the one boundary where types would
have paid — the API payload the SPA dereferences.

That reasoning was sound and it is not what changed. What changed is that the
project owner asked for the stack directly, and for a redesign substantial
enough that the old argument no longer covers the same decision. Rewriting
fourteen screens is the moment to migrate if you are ever going to; doing it
later means doing it twice.

Two further things had accumulated since 0004 that make the trade better than it
was:

- The frontend had reached 6,698 lines across 44 files with no type checking
  across component boundaries, only across the API one.
- The last three features (the analysis layer, the LLM provenance line, the
  crosscheck panel) all added *honesty affordances* to the UI — components whose
  entire job is to stop the interface overstating. Those need to be
  unmissable primitives, not conventions each screen re-implements.

## Decision

**Migrate to React 19 + TypeScript strict + Tailwind v4 + Radix/shadcn
primitives, with Framer Motion and Lenis for motion, behind a written design
contract.**

The contract, `frontend/DESIGN.md`, is the load-bearing part of this ADR. A
redesign split across four parallel workers fails in one predictable way: each
worker invents its own spacing scale, its own radius, its own blue and its own
easing curve, and the result reads as generated rather than designed. The
contract fixes tokens, motion durations, an explicit never-do list, and — most
importantly — restates the product's data-honesty rules as UI requirements.

`frontend/src/screens/Overview.tsx` is the exemplar every other screen is ported
against. A worked example is harder to misread than a rule, and it was cheaper
to write one screen properly than to specify one in prose.

## The honesty rules are now components

This is the part of the migration that is not cosmetic. These were conventions;
they are now primitives a screen has to actively work around to break:

| Guarantee | Primitive |
|---|---|
| A missing metric says so, never renders as `0` | `NotMeasured`, `MeasuredValue` |
| An inferred finding never looks like an observed one | `ClaimStatus` |
| Model-written text is labelled as such | `ProvenanceLine` |
| Severity carries a word, not only a hue | `SeverityBadge` |
| A failed fetch shows the backend's own refusal | `ErrorState` |
| Empty data is empty, never a fabricated example row | `EmptyState` |

## Two fabrications removed in the port

`src/api.js` carried two fallbacks that produced plausible values with nothing
behind them. Both are gone from `src/lib/api.ts`:

- `predictNext` returned five hardcoded ATT&CK techniques when the backend was
  unreachable, flagged `live: false`. The flag did not help: "T1021 Remote
  Services" rendered identically on screen whether the interpolated Markov model
  produced it or a constant did.
- `scoreEvent` fell back to a hand-tuned arithmetic formula standing in for the
  trained autoencoder.

Both now propagate the failure. A screen that cannot reach the detector says so.

## Consequences

- **`tests/test_ui_contract.py` remains the authority on the API boundary.**
  TypeScript types in `src/types/api.ts` are derived from real payloads and are
  a convenience; where a type and that test disagree, the test is right. The
  types do not replace it, because a type only constrains what the client
  believes and the test constrains what the server actually sends.
- **Bundle grows, and is split to compensate.** three.js, the force graph and
  recharts are manual chunks loaded only on the routes that use them. Vite 8
  runs rolldown, which takes `manualChunks` as a function rather than a map.
- **The deployed image is unaffected at runtime.** The Docker build already
  compiled the SPA in a Node stage and copied `dist`; that is unchanged. No new
  runtime dependency reaches the Python container.
- **Dark is now the default theme.** It is the design target; light remains
  supported and must stay legible.
- **Motion is a stated budget, not a free-for-all.** Durations, easing and
  stagger live in `src/lib/motion.ts` and mirror the CSS custom properties so
  the two cannot drift. Everything respects `prefers-reduced-motion`, enforced
  once in the base layer rather than remembered per component.

## What would change our mind

- **If the contract is not followed.** A design system nobody imports is just
  another folder. If screens start inlining one-off styled `div`s that duplicate
  a primitive, the migration has failed at the thing it was for and the right
  response is to fix the screens, not to loosen the contract.
- **If the 3D costs more than it earns.** The login scene and the 3D attack
  graph are the two places three.js appears. The graph must render real
  reachability data — nodes, pivots, crown jewels, choke points — or it is
  decoration and should go back to 2D. The login scene must degrade to a static
  background with no WebGL and under reduced motion.
