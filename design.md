# Design — SOC Command Center

Source of truth for tokens: [frontend/src/theme.css](frontend/src/theme.css). Components style **through CSS custom properties only** — never hardcode a color. Visual reference: [frontend/DESIGN_REFERENCE.html](frontend/DESIGN_REFERENCE.html).

## Principles
- Professional SOC console, not a flashy demo. Charcoal/navy dark · off-white light. Never pure black/white. No neon.
- **Red/orange reserved for genuine severity only** — decoration never borrows the severity palette.
- Light is the default theme; **present the live demo in dark** (graph + severity colors pop hardest).
- Theme toggle sets `data-theme="light|dark"` on `<html>`; respects `prefers-color-scheme` and `prefers-reduced-motion`.

## Colour and theme

| Token | Light | Dark | Use |
|---|---|---|---|
| `--bg` | `#EEF1F6` | `#0C111B` | page background |
| `--surface` | `#FFFFFF` | `#131B29` | cards |
| `--surface-2` | `#F6F8FB` | `#0F1622` | inset panels, table stripes |
| `--border` | `#DCE2EC` | `#233149` | card/input borders |
| `--text` | `#16202E` | `#E6ECF5` | primary text |
| `--text-dim` | `#5A6678` | `#8A97AC` | secondary text |
| `--text-faint` | `#8894A6` | `#5C6B82` | labels, meta |
| `--accent` | `#2F6FED` | `#4C8DFF` | brand blue: links, buttons, pivot node, sparklines |
| `--accent-soft` | `#E7EEFD` | `#16233C` | accent tint backgrounds |
| `--ok` | `#0A7D3F` | `#4ade80` | success / "live" |
| `--grid` | `#E4E9F1` | `#1B2536` | chart gridlines, idle graph edges |

### Severity palette (the semantic core)
| Severity | Light | Dark | Meaning |
|---|---|---|---|
| `--sev-critical` | `#E5484D` | `#FF5A5F` | critical alerts, crown-jewel assets |
| `--sev-high` | `#F2760C` | `#FF8A3D` | high alerts, highlighted attack path |
| `--sev-medium` | `#DFA000` | `#F5C144` | medium alerts |
| `--sev-low` | `#2F6FED` | `#4C8DFF` | low (= accent blue) |
| `--sev-normal` | `#7B8798` | `#5B6678` | benign / idle nodes |

Thresholds (mirror `api/main.py::_severity` and `lib/format.js`): score ≥90 critical · ≥70 high · ≥45 medium · else low. Helper classes: `.s-<sev>` (text) / `.bg-<sev>` (background).

## Fonts and typography

| Token | Stack | Use |
|---|---|---|
| `--sans` | `system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial` | everything |
| `--mono` | `ui-monospace, "SF Mono", "Cascadia Code", "JetBrains Mono", Consolas, Menlo` | hostnames, technique IDs, scores, timestamps (`.mono`, tabular-nums) |

- Base: 14px / line-height 1.45, antialiased. No webfont downloads — system stacks only (fast, offline-safe).
- Hierarchy: screen title in the topbar (`h1` + small subtitle) · card titles `h3` · section labels 11px uppercase letterspaced (`.section-label`) · big stat numbers in tiles (`.v`).
- Anything machine-identifier-like (C17693, T1550.002, U66@DOM1) is monospace — this is the visual signature of the app.

## Shape, depth, motion
- Radii: `--radius: 12px` (cards) · `--radius-sm: 8px` (buttons/inputs).
- Shadow: `--shadow` — soft, two-layer, theme-tuned. Cards = surface + 1px border + shadow.
- Motion: 0.2s background/color transitions on theme flip; incident replay reveals rows at 220ms/step; width transitions on MTTD bars. All disabled under `prefers-reduced-motion`.
- Focus: 2px accent outline via `:focus-visible` (keep — accessibility).

## Layout
- Shell: fixed left sidebar (brand + Operations/Evidence nav) + topbar (title, "2 detectors live" pill, IST clock, theme toggle) + card-grid content (`Layout.jsx`).
- Grids: 4-up stat tiles on Overview; `grid2` two-column for detail screens; `.stack` for vertical card stacks.
- Wide content scrolls inside its card (timeline maxHeight 620) — page never scrolls horizontally.

## Component vocabulary (reuse, don't reinvent)
`Card / CardHeader` · stat `.tile` · `Sparkline` (SVG, accent) · `LiveBadge` (● live / ○ cached) · `.tag-pill` chips · ranked lists (`.ranked`, `.actor`, `.pred`) · metric tables (`.mtable`) · toggle switches (`.sw`) in the live scorer.
