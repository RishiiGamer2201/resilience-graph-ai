import { useState } from 'react'
import { ChevronDown, ChevronRight } from 'lucide-react'

// The two numbers a judge should remember, each with its arithmetic one click
// away. A metric with no value renders "Not measured" and says why — it never
// renders 0, and it never renders a number nobody can reproduce.
function band(v) {
  if (v === null || v === undefined) return 'normal'
  return v >= 80 ? 'critical' : v >= 60 ? 'high' : v >= 35 ? 'medium' : 'low'
}

export function HeadlineMetric({ title, metric, caption }) {
  const [open, setOpen] = useState(false)
  const measured = metric && metric.value !== null && metric.value !== undefined
  const terms = metric?.terms || []
  const Chevron = open ? ChevronDown : ChevronRight

  return (
    <div className={`headline s-${band(measured ? metric.value : null)}`}>
      <div className="hl-k">{title}</div>
      <div className="hl-v mono">
        {measured ? metric.value : 'Not measured'}
        {measured && <span className="hl-u">{metric.unit === '0-100' ? ' / 100' : metric.unit}</span>}
      </div>
      <div className="hl-sub">{measured ? caption : (metric?.reason || metric?.why || '—')}</div>
      {measured && (
        <>
          <button type="button" className="hl-more" onClick={() => setOpen(!open)}
            aria-expanded={open}>
            <Chevron size={12} aria-hidden="true" /> {open ? 'Hide' : 'Show'} the arithmetic
          </button>
          {open && (
            <div className="hl-formula">
              <code className="mono">{metric.formula}</code>
              <table className="hl-terms">
                <tbody>
                  {terms.map((t, i) => (
                    <tr key={t.name || t.asset || i}>
                      <td className="mono">{t.name || t.asset}</td>
                      <td className="mono">
                        {t.weight !== undefined ? `×${t.weight}` : ''}
                        {t.value !== undefined ? ` ${t.value}` : ''}
                        {t.score !== undefined ? ` ${t.score}` : ''}
                        {t.hops !== undefined && t.hops !== null ? ` (${t.hops} hop${t.hops === 1 ? '' : 's'})` : ''}
                      </td>
                      <td>{t.detail || t.why}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {metric.note && <p className="hl-note">{metric.note}</p>}
            </div>
          )}
        </>
      )}
    </div>
  )
}

export default function Headline({ headline }) {
  const conf = headline?.attack_progression_confidence
  const exp = headline?.crown_jewel_exposure
  return (
    <div className="headline-pair">
      <HeadlineMetric
        title="Attack progression confidence"
        metric={conf}
        caption="how strongly the evidence says a real intrusion is progressing"
      />
      <HeadlineMetric
        title="Crown-jewel exposure"
        metric={exp}
        caption="how exposed the designated crown jewels are right now"
      />
    </div>
  )
}
