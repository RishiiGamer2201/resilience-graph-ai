# nextATT&CKs — frontend design contract

**Every agent and every commit that touches `frontend/src` follows this file.**
It exists because a redesign split across parallel workers fails in one specific
way: each worker invents its own spacing, its own radius, its own blue, its own
easing, and the result reads as generated rather than designed. The contract is
the fix. When this file and a component disagree, the component is wrong.

---

## 1. What we are building

A **dense operator console**. The reference points are Linear, Vercel's
dashboard, Datadog and Chronicle — not a marketing site. An analyst should be
able to read severity, technique chain, confidence and the recommended action
without scrolling, and every number on screen should be one they could defend in
a review.

The product's whole thesis is that it does not overstate. The interface has to
carry that: a hedge is not a footnote to hide, it is the feature.

---

## 2. The never-do list

These are the specific tells of machine-generated design. None of them appears
in this codebase.

- **No purple or indigo gradients.** No `from-purple-500 to-pink-500`, no
  `bg-gradient-to-r` as a decorative default. Gradient is allowed only where it
  encodes data (a severity ramp, a heat scale).
- **No glassmorphism.** No `backdrop-blur` on cards, no translucent panels
  stacked over a blurred photo.
- **No glow.** No `shadow-[0_0_40px_rgba(...)]` halos, no neon borders, no
  pulsing accent rings.
- **No emoji** in headings, labels, buttons or empty states. Icons come from
  `lucide-react`.
- **No `rounded-3xl`, no `rounded-full` on containers.** Radius is 6px or 10px.
  Pills for badges only.
- **No decorative motion.** Nothing floats, bobs, breathes, or animates on an
  infinite loop. If an animation is not communicating a state change, delete it.
- **No hero numbers without units or context.** "94" is slop. "94% TPR at 1% FPR
  · LANL red-team" is information.
- **No centred single-column layouts** for data screens. Dense means dense.
- **No `text-transparent bg-clip-text`** gradient headings.
- **No stock illustrations, no 3D blobs, no floating cubes.** The only 3D in the
  product renders real data or is the login scene.

---

## 3. Tokens

Defined once in `src/styles/tokens.css` as CSS custom properties, exposed to
Tailwind in `src/styles/theme.css` via `@theme`. **Never hardcode a colour in a
component.** Use the Tailwind class that maps to the token.

### Colour

Dark is the default and the design target. Light is supported and must stay
legible, but it is the secondary theme.

| Role | Token | Use |
|---|---|---|
| Page ground | `bg` | The window behind everything |
| Panel | `surface` | Cards, panes, the command bar and mobile sheet |
| Raised | `surface-2` | Table header rows, inset wells, hover states |
| Line | `border` | 1px hairlines. Most separation is a hairline, not a shadow |
| Body text | `text` | |
| Secondary | `text-dim` | Labels, captions, units |
| Tertiary | `text-faint` | Metadata, timestamps, provenance lines |
| Accent | `accent` | Exactly one accent. Links, focus, the primary action |

Severity is the only other colour family and it is **semantic, never
decorative**: `sev-critical`, `sev-high`, `sev-medium`, `sev-low`, `sev-normal`.
A red border means critical. It never means "this card is important".

### Spacing

4px base. Only these steps: `1 2 3 4 6 8 12 16` (4–64px). Card padding is `4`
(16px) or `6` (24px). Gap between cards is `4`. Nothing gets an arbitrary
`p-[13px]`.

### Type

- Sans: system stack, via `font-sans`.
- **Mono: `font-mono` for every piece of machine data** — host names, account
  names, technique IDs, hashes, scores, counts, timestamps, durations. This is
  the single strongest signal that the product is an instrument and not a
  brochure. Mono numerics are tabular so columns align.
- Sizes: `text-xs` (11px) metadata · `text-sm` (13px) body and tables ·
  `text-base` (15px) emphasis · `text-lg` (18px) card titles · `text-2xl` (24px)
  page titles. Nothing larger except a deliberate hero figure.
- Weight: 400 body, 500 labels, 600 headings. No 800/900.
- **Section labels are uppercase, 11px, `tracking-wider`, `text-text-faint`.**
  This is the console idiom and it carries a lot of the character.

### Radius and elevation

`rounded-md` (6px) for controls, `rounded-lg` (10px) for panels. Shadows are for
things that genuinely float — dialogs, popovers, dropdowns. A card on a page
gets a border, not a shadow.

---

## 4. Motion

Framer Motion (`motion/react`) for component motion. Lenis for page scroll.

**Motion communicates state, never decorates.** Legitimate uses:

1. Data arriving (skeleton → content).
2. A stage advancing (the agent pipeline, the workflow rail).
3. A value changing (a score counting to its new figure).
4. Layout change (a panel opening, a row expanding).
5. Entering a route.

### Durations and easing — use these, do not invent

```
--motion-fast:    120ms   hover, focus, colour
--motion-base:    200ms   most transitions
--motion-slow:    320ms   panels, route changes
--motion-ease:    cubic-bezier(0.32, 0.72, 0, 1)     the house curve
--motion-spring:  { type: 'spring', stiffness: 380, damping: 32 }
```

Stagger for lists is **30ms**, capped at 8 items. A twenty-row table does not
cascade for six hundred milliseconds.

### Reduced motion is not optional

Every animated component respects `prefers-reduced-motion`. Use the
`useReducedMotion()` hook from `motion/react`, or the `<Reveal>` primitive which
already handles it. A reviewer with vestibular sensitivity must get a usable app,
and a judge who turns it on and sees the app still work notices.

---

## 5. Data honesty in the UI

These are product requirements, not styling preferences. **An agent that
"cleans up" any of these has broken the product.**

- **`Not measured` is rendered as those words**, in `text-faint`, with the reason
  on hover. It is never a `0`, never `—`, never an empty cell, never hidden.
- **Claim status is always visible.** `observed` / `inferred` / `predicted` /
  `confirmed` / `disputed`. Use the `ClaimStatus` primitive. An inferred finding
  never renders identically to an observed one.
- **Provenance stays on screen.** Where text came from a language model, the
  line that says so stays. Where a number came from a template, likewise.
- **Disagreement is shown, not smoothed.** The workflow lane and the agent lane
  can differ; the crosscheck panel says so and confidence drops. Never render one
  and drop the other.
- **Confidence and probability are separate numbers** and never combined into one
  bar.
- **Actions are simulated and human-gated.** A destructive-looking button must
  read as a proposal awaiting approval, not as a live control.
- **RBAC is server-enforced.** Hiding a button is a courtesy, never the
  mechanism. A forbidden action must show the server's refusal, not vanish.

---

## 6. Components

Primitives live in `src/components/ui/` (shadcn-style, Radix-backed) and domain
components in `src/components/`. **Import them. Do not rewrite them.**

`Button` `Card` `Badge` `Table` `Tabs` `Dialog` `Tooltip` `Skeleton`
`ScrollArea` `Separator` `Progress` `Input` `Select`

Domain: `SeverityBadge` `ClaimStatus` `NotMeasured` `MetricCard` `StatRow`
`SectionLabel` `Reveal` `AnimatedNumber` `EmptyState` `ProvenanceLine`

If a screen needs something that does not exist, add it to `src/components/` and
say so in the handoff — do not inline a one-off styled `div` that duplicates a
primitive.

---

## 7. TypeScript

Strict. `any` is not permitted; use `unknown` and narrow.

API response types live in `src/types/api.ts` and are derived from the **actual
payloads** the FastAPI backend returns, not invented. `tests/test_ui_contract.py`
remains the authority on that boundary — when a type and that test disagree, the
test is right.

No changes to request or response shapes. This is a redesign, not a re-spec: if
a screen needs a field the API does not return, say so in the handoff rather than
inventing a client-side default.

---

## 8. Accessibility floor

- Every interactive element is reachable by keyboard and has a visible
  `:focus-visible` ring.
- Body text meets 4.5:1 against its background in both themes; `text-faint` is
  for non-essential metadata only.
- Colour is never the sole carrier of meaning: severity has a label as well as a
  hue.
- Icon-only buttons carry an `aria-label`.
- Live regions announce analysis completion.

---

## 9. Definition of done, per screen

1. TypeScript, strict, no `any`.
2. Every value comes from the real API through `src/lib/api.ts`. No placeholder
   arrays, no lorem, no invented hostnames, no sample numbers.
3. Loading and error states use `Skeleton` and `EmptyState`; the screen never
   renders a bare spinner or a blank panel.
4. Empty data renders an honest empty state, never a fabricated example.
5. `npm run lint` and `npm run build` both clean.
6. Reduced motion respected.
7. Keyboard reachable.
