/**
 * How a host's place in the incident maps to the palette.
 *
 * Lives apart from `components/AttackGraph3D.tsx` on purpose: the legend, the
 * host list and the detail panel all need this, and importing it from the 3D
 * module would drag three.js into the entry chunk.
 *
 * Five roles, five tokens, no invented colours. `recommended_isolation` is a
 * sixth distinction and deliberately is NOT a colour — the palette holds five
 * legible severity/accent hues and `--sev-low` is the same value as `--accent`,
 * so a sixth would either repeat one or break the token contract. It is drawn
 * as a ring instead.
 */
export type NodeRole = 'crown-jewel' | 'entry' | 'pivot' | 'choke' | 'reached'

/** Highest precedence first. A host with several roles is coloured by the
 *  first one it matches; the panel beside the canvas lists all of them. */
export const ROLE_ORDER: NodeRole[] = ['crown-jewel', 'entry', 'pivot', 'choke', 'reached']

/** CSS custom property, read at paint time so the canvas follows the theme. */
export const ROLE_TOKEN: Record<NodeRole, string> = {
  'crown-jewel': '--sev-critical',
  entry: '--accent',
  pivot: '--sev-high',
  choke: '--sev-medium',
  reached: '--sev-normal',
}

/** The same colour as a Tailwind class, for the legend and the host list. */
export const ROLE_SWATCH: Record<NodeRole, string> = {
  'crown-jewel': 'bg-sev-critical',
  entry: 'bg-accent',
  pivot: 'bg-sev-high',
  choke: 'bg-sev-medium',
  reached: 'bg-sev-normal',
}

/** Colour never carries meaning alone: every role has these words beside it. */
export const ROLE_LABEL: Record<NodeRole, string> = {
  'crown-jewel': 'crown jewel at risk',
  entry: 'entry host',
  pivot: 'attacker pivot',
  choke: 'choke point',
  reached: 'reached host',
}

/** Which backend field puts a host in this role. Shown in the legend so the
 *  encoding is checkable against the API response. */
export const ROLE_SOURCE: Record<NodeRole, string> = {
  'crown-jewel': 'critical_assets_at_risk',
  entry: 'entry_host',
  pivot: 'attacker_pivots',
  choke: 'choke_points',
  reached: 'nodes',
}

export interface Graph3DNode {
  id: string
  role: NodeRole
  /** Movements touching this host. Drives sphere volume. */
  degree: number
  recommendedIsolation: boolean
  /** Every role the backend gives this host. */
  roles: NodeRole[]
}

export interface Graph3DLink {
  source: string
  target: string
  technique: string
  /** Max anomaly score across the events collapsed into this pair, 0-100. */
  score: number
  eventCount: number
  /** On one of `paths_to_critical`. */
  onPath: boolean
}
