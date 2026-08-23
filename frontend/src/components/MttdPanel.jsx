import { CircleSlash } from 'lucide-react'
import { Card, CardHeader } from './Card.jsx'

// Two numbers that are NOT the same kind of fact, drawn side by side and
// labelled as such: what this log measured (first event -> first correlated
// alert), and a published median dwell time we cite. The old title claimed
// "weeks to minutes" as if both halves were ours; the weeks are Mandiant's.
//
// Proportional bars would make the measured value invisible next to a 10-day
// median, so the widths are fixed emphasis, not a scale -- the numbers beside
// them are the fact.
//
// Every value comes from the payload. A missing measurement renders "Not
// measured": defaulting to "< 1 min" invented the exact metric this panel is
// supposed to report.
export default function MttdPanel({ mttd }) {
  const secs = typeof mttd?.ours_seconds === 'number' ? mttd.ours_seconds : null
  const days = typeof mttd?.traditional_days === 'number' ? mttd.traditional_days : null
  const oursLabel = mttd?.value
  // detection compression vs the cited dwell median; needs both numbers, and
  // guards the immediate (0s) case
  const factor = days !== null && secs > 0 ? Math.round((days * 86400) / secs) : null

  const Row = ({ label, value, width, color }) => (
    <div style={{ display: 'grid', gridTemplateColumns: '150px 1fr 78px',
                  alignItems: 'center', gap: 12, marginBottom: 12 }}>
      <div style={{ color: 'var(--text-dim)', fontSize: 13 }}>{label}</div>
      <div style={{ height: 14, borderRadius: 7, background: 'var(--surface-2)',
                    border: '1px solid var(--border)', overflow: 'hidden' }}>
        <div style={{ height: '100%', width, background: color, borderRadius: 7,
                      transition: 'width .5s ease' }} />
      </div>
      <div className="mono" style={{ textAlign: 'right', fontWeight: 600 }}>{value}</div>
    </div>
  )

  if (!oursLabel || secs === null) {
    return (
      <Card>
        <CardHeader title="Time to first correlated alert" meta="MTTD" />
        <div className="card-b pad" style={{ display: 'flex', gap: 8, alignItems: 'center',
                                             color: 'var(--text-faint)', fontSize: 13 }}>
          <CircleSlash size={15} aria-hidden="true" />
          Not measured -- this analysis carries no detection-latency measurement.
        </div>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader title="Time to first correlated alert" meta="MTTD · measured in this log" />
      <div className="card-b pad">
        {days !== null && (
          <Row label="Industry median dwell (cited)" value={`≈ ${days} d`}
               width="100%" color="var(--sev-critical)" />
        )}
        <Row label={'nextATT&CKs (measured)'} value={oursLabel}
             width="3%" color="var(--accent)" />
        <div style={{ marginTop: 6, fontSize: 13, color: 'var(--text)' }}>
          Measured <b className="s-low">{oursLabel}</b> from the first event in this log to
          the first correlated alert.
          {factor !== null && <> That is <b className="mono s-low">{factor.toLocaleString()}×</b>{' '}
            shorter than the cited <b>{days}-day</b> median dwell -- a published figure, not
            a second measurement of ours.</>}
          {factor === null && days !== null && <> The <b>{days}-day</b> dwell bar above is a
            published median, not something we measured.</>}
          {mttd?.citation && <div style={{ marginTop: 4, fontSize: 11, color: 'var(--text-faint)' }}>
            Dwell reference: {mttd.citation}</div>}
        </div>
      </div>
    </Card>
  )
}
