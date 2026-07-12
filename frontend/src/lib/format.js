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

// LANL uses opaque identifiers. Keep raw values for analysts, but present a
// plain-language description first.
export function describeAccount(account) {
  if (!account) return 'Unknown account'
  const [user, domain] = account.split('@')
  return domain ? `Account ${user} in the ${domain} domain` : `Account ${user}`
}

export function describeHost(host) {
  return host ? `computer ${host}` : 'an unknown computer'
}

export function describeStep(step) {
  const subject = describeAccount(step.user)
  const destination = describeHost(step.destination_host)
  const source = step.source_host ? ` from ${describeHost(step.source_host)}` : ''
  if (!step.technique_id || step.technique_id === '-' || step.tactic === 'Normal') {
    return `${subject} accessed ${destination}${source}. This activity matches the baseline pattern.`
  }
  return `${subject} accessed ${destination}${source}. Detected behavior: ${step.technique}.`
}

export function shortExplanation(explanation) {
  if (!explanation) return ''
  const firstSentence = explanation.replace(/\s+/g, ' ').match(/^.*?[.!?](?:\s|$)/)
  return firstSentence ? firstSentence[0].trim() : explanation
}

// Read a live CSS custom property off <html> (theme-aware).
export function cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim()
}
