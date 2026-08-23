# Screen port brief — read this, then `frontend/DESIGN.md`, then start

You are porting screens of a working security product from JSX to TypeScript +
Tailwind. **This is a redesign, not a rewrite of behaviour.** Every API call,
every field, every honesty affordance in the old screen survives the port.

## Before you write anything

1. Read `frontend/DESIGN.md` end to end. It is binding.
2. Read `frontend/src/screens/Overview.tsx`. **It is the exemplar.** Match its
   structure, its density, its use of primitives, its handling of loading,
   error and empty. If you find yourself writing something it does not do, ask
   whether the exemplar is wrong or you are.
3. Read the corresponding pre-redesign screen from commit `d9365a1^` when you
   need the behavioural history: which endpoint, which fields, which states.

## Hard rules

- **TypeScript, strict, no `any`.** Types live in `@/types/api`. If a type is
  missing a field the API really returns, add it there.
- **No hardcoded data. None.** No sample arrays, no placeholder hostnames, no
  lorem, no invented numbers, no "example" fallbacks. Every value on screen
  comes from `@/lib/api`. If the API does not provide it, render `NotMeasured`
  or an `EmptyState` and say so.
- **Import the primitives, do not reinvent them:**
  `@/components/ui/{button,card,badge,table,tabs,tooltip,skeleton}` and
  `@/components/primitives` (`SeverityBadge` `ClaimStatus` `NotMeasured`
  `MeasuredValue` `MetricCard` `StatRow` `SectionLabel` `Reveal` `RevealList`
  `AnimatedNumber` `EmptyState` `ErrorState` `ProvenanceLine`).
- **`useFetch` from `@/hooks/useFetch`** for loading and error. Loading renders
  `Skeleton`; failure renders `ErrorState` with the backend's own message.
- **Motion comes from `@/lib/motion`.** Do not invent durations or easings. Do
  not animate anything that is not communicating a state change.
- **Keep the honesty affordances.** Claim status visible. `Not measured` as
  words. Provenance lines kept. Lane disagreement shown. Confidence and
  probability separate. Actions read as proposals awaiting approval.
- Keep the source tree TypeScript-only. The build-integrity check rejects a
  `.js`/`.jsx` module beside its `.ts`/`.tsx` replacement.

## Definition of done

`npx tsc --noEmit` clean, `npm run build` clean, no `any`, no hardcoded values,
loading + error + empty states present, keyboard reachable, reduced motion
respected.

## Report back

List: files written, endpoints used, any field the API does not provide that the
screen needed, and anything in DESIGN.md you had to work around.
