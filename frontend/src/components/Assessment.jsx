import { useState } from 'react'
import { ChevronDown, ChevronRight, HelpCircle } from 'lucide-react'

// Four numbers, deliberately not collapsed into one.
//
// A single "87% attack score" hides which of the four is weak. Anomaly says the
// behaviour is unusual; likelihood says an intrusion looks under way; impact says
// what it costs if that is right; confidence says how good the evidence is. They
// routinely disagree, and the disagreement is the useful part.
const DIMENSIONS = [
  { key: 'anomaly', label: 'Anomaly', hint: 'how unlike its own baseline the behaviour is' },
  { key: 'likelihood', label: 'Likelihood', hint: 'how probable a malicious path is' },
  { key: 'impact', label: 'Impact', hint: 'what it costs if the hypothesis is right' },
  { key: 'confidence', label: 'Evidence confidence', hint: 'how good the supporting evidence is' },
]

const BAND_CLASS = {
  critical: 's-critical', high: 's-high', moderate: 's-medium',
  low: 's-low', 'very low': 's-normal', 'not measured': 's-normal',
}

export default function Assessment({ assessment, likelihood, confidence }) {
  const [open, setOpen] = useState(false)
  if (!assessment) return null
  const Chevron = open ? ChevronDown : ChevronRight
  const formulas = { likelihood, confidence }

  return (
    <section className="assessment">
      <div className="as-summary">
        <b>{assessment.summary}</b>
      </div>
      <div className="as-grid">
        {DIMENSIONS.map(({ key, label, hint }) => {
          const d = assessment[key]
          const measured = d.value !== null && d.value !== undefined
          return (
            <div key={key} className={`as-cell ${BAND_CLASS[d.band] || ''}`}>
              <div className="as-k">
                {label}
                <span className="as-hint" title={d.question || hint}>
                  <HelpCircle size={11} aria-hidden="true" />
                </span>
              </div>
              <div className="as-v mono">{measured ? d.value : '—'}</div>
              <div className="as-band">{d.band}</div>
            </div>
          )
        })}
      </div>

      {assessment.missing_evidence?.length > 0 && (
        <div className="as-missing">
          <b>Still missing:</b>{' '}
          {assessment.missing_evidence.slice(0, 3).join(' · ')}
          {assessment.missing_evidence.length > 3 &&
            ` · +${assessment.missing_evidence.length - 3} more`}
        </div>
      )}

      <button type="button" className="hl-more" onClick={() => setOpen(!open)}
        aria-expanded={open}>
        <Chevron size={12} aria-hidden="true" /> {open ? 'Hide' : 'Show'} the arithmetic
      </button>
      {open && (
        <div className="hl-formula">
          {Object.entries(formulas).map(([name, m]) => m && (
            <div key={name} className="as-formula">
              <div className="as-fname">{name}</div>
              <code className="mono">{m.formula}</code>
              <table className="hl-terms">
                <tbody>
                  {(m.terms || []).map((t) => (
                    <tr key={t.name}>
                      <td className="mono">{t.name}</td>
                      <td className="mono">×{t.weight} {t.value}</td>
                      <td>{t.detail}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ))}
          <p className="hl-note">{assessment.note}</p>
        </div>
      )}
    </section>
  )
}

const STATUS_CLASS = {
  observed: 's-low', confirmed: 's-low', inferred: 's-medium',
  predicted: 's-high', disputed: 's-critical', retracted: 's-normal',
}

// What we actually claim about each ATT&CK technique, and what would settle it.
// An anomaly means unusual; a technique means adversary behaviour. The gap
// between those two is this table.
export function ClaimsPanel({ claims }) {
  const [open, setOpen] = useState(null)
  if (!claims?.length) return null
  const actionable = claims.filter((c) => c.actionable).length

  return (
    <div className="claims">
      <p className="lede">
        {claims.length} ATT&amp;CK claim{claims.length === 1 ? '' : 's'} ·{' '}
        <b>{actionable} actionable</b> (observed or confirmed). An anomaly establishes
        that behaviour is unusual; a technique additionally asserts adversary behaviour.
        Claims that only have the detector behind them stay candidates.
      </p>
      <table className="tbl">
        <caption className="sr-only">ATT&amp;CK claims with status and confidence</caption>
        <thead>
          <tr>
            <th scope="col">Technique</th><th scope="col">Status</th>
            <th scope="col">Confidence</th><th scope="col">Independent sources</th>
            <th scope="col">Act on it?</th><th scope="col"><span className="sr-only">Detail</span></th>
          </tr>
        </thead>
        <tbody>
          {claims.map((c) => (
            <tr key={c.external_id}>
              <th scope="row" className="mono">{c.external_id}
                <span className="dim"> {c.object}</span></th>
              <td><span className={STATUS_CLASS[c.status]}>{c.status}</span></td>
              <td className="mono">{c.confidence} <span className="band">{c.confidence_band}</span></td>
              <td className="mono">{c.independent_groups}</td>
              <td>{c.actionable
                ? <span className="s-low">yes</span>
                : <span className="dim">not yet</span>}</td>
              <td>
                <button className="linkish"
                  onClick={() => setOpen(open === c.external_id ? null : c.external_id)}
                  aria-expanded={open === c.external_id}>
                  {open === c.external_id ? 'hide' : 'why'}
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {claims.filter((c) => open === c.external_id).map((c) => (
        <div key={c.external_id} className="claim-detail">
          <p>{c.note}</p>
          {c.missing_evidence?.length > 0 && (
            <div><b>Would settle it:</b>
              <ul>{c.missing_evidence.map((m) => <li key={m}>{m}</li>)}</ul>
            </div>
          )}
          {c.alternatives?.length > 0 && (
            <div><b>Benign explanations not ruled out:</b>
              <ul>{c.alternatives.map((a) => <li key={a}>{a}</li>)}</ul>
            </div>
          )}
          <p className="fineprint mono">
            evidence: {c.evidence.map((e) => `${e.kind} (${e.independence_group})`).join(' · ') || 'none'}
          </p>
        </div>
      ))}
    </div>
  )
}
