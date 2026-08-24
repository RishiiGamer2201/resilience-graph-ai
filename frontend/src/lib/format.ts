/**
 * Formatting and severity helpers, ported from lib/format.js.
 *
 * Only the pieces the TypeScript screens actually use. The thresholds mirror
 * `api/main.py::_severity` - if the backend's bands move, this moves with them,
 * because a label that contradicts the number it sits next to is a lie.
 */
import type { IncidentStep, Severity } from '@/types/api'

/** Backend severity bands for a 0-100 anomaly score. */
export function severityFromScore(score: number): Severity {
  if (score >= 90) return 'critical'
  if (score >= 70) return 'high'
  if (score >= 45) return 'medium'
  return 'low'
}

/**
 * Severity for one timeline step.
 *
 * An event with no mapped ATT&CK tactic reads as "normal" ONLY when its score
 * agrees. A high-scoring event is never labelled normal just because nothing
 * mapped: the number and the word must never contradict each other.
 */
export function severityFromStep(step: IncidentStep): Severity {
  const score = typeof step.anomaly_score === 'number' ? step.anomaly_score : 0
  const sev = severityFromScore(score)
  if ((!step.tactic || step.tactic === 'Normal') && sev === 'low') return 'normal'
  return sev
}

/** LANL timestamps are integer seconds from the capture start; render a clock. */
export function fmtTime(ts: number | string | undefined): string {
  const n = typeof ts === 'number' ? ts : Number(ts)
  if (!Number.isFinite(n)) return 'Not available'
  const s = ((Math.floor(n) % 86400) + 86400) % 86400
  const p = (v: number) => String(v).padStart(2, '0')
  return `${p(Math.floor(s / 3600))}:${p(Math.floor((s % 3600) / 60))}:${p(s % 60)}`
}

/** Read a live CSS custom property off <html>, so colour follows the theme
 *  instead of being hardcoded in a canvas that Tailwind cannot reach. */
export function cssVar(name: string, fallback = '#5b6678'): string {
  if (typeof document === 'undefined') return fallback
  const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim()
  return v || fallback
}
