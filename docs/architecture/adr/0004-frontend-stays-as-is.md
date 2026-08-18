# ADR 0004 — Keep JSX and CSS tokens; no TypeScript migration, no Tailwind, no map

- **Status:** accepted
- **Date:** 2026-08-18

## Context

The proposed finalist stack named React + TypeScript + Tailwind + shadcn/ui, and
MapLibre or Leaflet for geospatial views. The repo has React 19 + Vite 8 in JSX, a
CSS custom-property token system (`frontend/src/theme.css`), Recharts, Lucide and
`react-force-graph-2d`, all working and all building clean.

## Decision

Keep JSX. Keep the token system. Add no Tailwind, no shadcn, no map. New surfaces
(`Investigate`, `Scoreboard`, and the evidence/twin/action/audit panels) are written
in the same idiom, with a new `finalist.css` that defines classes using the existing
tokens and nothing else.

## Why

**A wholesale JSX→TSX migration during finalist hardening is the highest-risk,
lowest-visibility change available.** It touches every file, is invisible to a judge,
and its benefit — catching contract drift — is better served here by the thing that
actually caused our only real drift bug: hard-coded numbers. We fixed that by making
`views.SCORECARD` read `reports/metrics.json` and adding a test that fails if it
drifts again. TypeScript would not have caught it; a wrong constant is a valid
`number`.

**Two design systems is worse than one.** Tailwind's utility classes and our token
classes would coexist for the rest of the project's life, and every new component
would have to pick. The token system already delivers light/dark, `prefers-reduced-motion`,
severity colours and a consistent card/table language. shadcn would bring Radix and
a component library to a nine-screen app with no dialogs, no comboboxes and no date
pickers.

**A map would be decoration.** MapLibre or Leaflet earns its place when a location
changes a decision. Nothing in PS7's loop is geographic: the attack graph is a
host/account topology, and the India-first threat radar filters CTI by *relevance*,
not coordinates. Putting anonymised LANL hosts or synthetic AIIMS servers on a map
of India would be inventing geography we do not have — precisely the kind of
plausible fabrication the rest of this product refuses.

**Pint is not applicable.** It solves dimensional-unit correctness. Our numbers are
dimensionless scores (0–100), counts (hosts, alerts), seconds and probabilities. The
one conversion in the codebase is seconds→human string, and it is four `if`s.

## Consequences

- Contract safety comes from the backend and the tests instead of the type system:
  Pydantic request models, `src/schema.py` coercion at the trust boundary, and 134
  Python tests including the scoreboard-drift guard.
- The new screens inherit accessibility for free — focus rings, reduced-motion,
  `sr-only` captions on every data table, `scope` on header cells, and labelled
  controls — because they use the same primitives.
- Bundle stays modest: 106 KB gzipped for the main chunk, with the force graph and
  Recharts still code-split.
- If TypeScript is wanted later, Vite compiles `.tsx` alongside `.jsx` with no config
  change. The migration can be incremental, file by file, starting with `api.js`
  where the payload contracts live. It does not have to happen now, and it should
  not happen this week.

## What would change our mind

- A second team joining the frontend, where types are a communication tool rather
  than a refactor.
- A real geospatial input — for example a CNI asset inventory that carries site
  coordinates and an operator decision that depends on them.
- A component need the token system genuinely cannot serve (complex overlays,
  virtualised grids, accessible combobox behaviour), where Radix primitives would be
  less code than doing it properly ourselves.
