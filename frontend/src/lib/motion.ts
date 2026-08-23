/**
 * Motion tokens. The same numbers as --motion-* in styles/theme.css, so CSS
 * transitions and Framer Motion cannot drift apart.
 *
 * Motion here communicates state: data arriving, a stage advancing, a value
 * changing, a panel opening, a route entering. Nothing floats or breathes.
 * See frontend/DESIGN.md section 4.
 */
import type { Transition, Variants } from 'motion/react'

export const DURATION = { fast: 0.12, base: 0.2, slow: 0.32 } as const

/** The house curve. Fast out of the gate, long settle. */
export const EASE = [0.32, 0.72, 0, 1] as const

export const spring: Transition = { type: 'spring', stiffness: 380, damping: 32 }
export const ease: Transition = { duration: DURATION.base, ease: EASE }
export const easeSlow: Transition = { duration: DURATION.slow, ease: EASE }

/** 30ms between items, capped at 8. A long table does not cascade. */
export const STAGGER = 0.03
export const STAGGER_MAX = 8

export const stagger = (count: number): Transition => ({
  staggerChildren: STAGGER,
  delayChildren: 0,
  ...(count > STAGGER_MAX ? { staggerChildren: 0 } : {}),
})

/** Content arriving. 6px, not 40px: a nudge, not a swoop. */
export const fadeUp: Variants = {
  hidden: { opacity: 0, y: 6 },
  show: { opacity: 1, y: 0, transition: ease },
}

export const fade: Variants = {
  hidden: { opacity: 0 },
  show: { opacity: 1, transition: ease },
}

/** Route transitions. Deliberately subtle; the layout does not move. */
export const routeVariants: Variants = {
  hidden: { opacity: 0, y: 4 },
  show: { opacity: 1, y: 0, transition: { duration: DURATION.base, ease: EASE } },
  exit: { opacity: 0, transition: { duration: DURATION.fast } },
}

/** A panel or row expanding. Height animation needs the slow token. */
export const collapse: Variants = {
  hidden: { height: 0, opacity: 0 },
  show: { height: 'auto', opacity: 1, transition: easeSlow },
}
