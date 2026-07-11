// Shared formatting + severity helpers for the SOC Command Center.

// Backend severity thresholds (mirror api/main.py::_severity).
export function severityFromScore(score) {
  if (score >= 90) return 'critical'
  if (score >= 70) return 'high'
  if (score >= 45) return 'medium'
  return 'low'
}

// Severity for a timeline step: "Normal" tactic reads as normal regardless of score.
export function severityFromStep(step) {
  if (!step.tactic || step.tactic === 'Normal') return 'normal'
  return severityFromScore(step.anomaly_score)
}

export const sevClass = (sev) => `s-${sev}`
export const sevBg = (sev) => `bg-${sev}`

// LANL timestamps are integer seconds; render as a clock (seconds-of-day).
export function fmtTime(ts) {
  const s = ((Math.floor(ts) % 86400) + 86400) % 86400
  const h = Math.floor(s / 3600)
  const m = Math.floor((s % 3600) / 60)
  const sec = s % 60
  const p = (n) => String(n).padStart(2, '0')
  return `${p(h)}:${p(m)}:${p(sec)}`
}

// Read a live CSS custom property off <html> (theme-aware).
export function cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim()
}
