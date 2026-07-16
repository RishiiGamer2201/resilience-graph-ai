import { Card, CardHeader } from './Card.jsx'

// Weeks -> minutes detection-time visual. Proportional bars would make "ours"
// invisible (21 days vs 4 min), so we use fixed emphasis widths and state the
// real compression factor in text.
export default function MttdPanel({ mttd }) {
  const days = mttd?.traditional_days ?? 10
  const secs = mttd?.ours_seconds ?? 0
  const oursLabel = mttd?.value ?? '< 1 min'
  // detection compression vs cited industry dwell; guard the immediate (0s) case
  const factor = secs > 0 ? Math.round((days * 86400) / secs) : null

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

  return (
    <Card>
      <CardHeader title="Detection time: weeks to minutes" meta="MTTD" />
      <div className="card-b pad">
        <Row label={`Industry median dwell`} value={`≈ ${days} d`}
             width="100%" color="var(--sev-critical)" />
        <Row label="Resilience Graph AI" value={oursLabel}
             width="3%" color="var(--accent)" />
        <div style={{ marginTop: 6, fontSize: 13, color: 'var(--text)' }}>
          {factor
            ? <>Detection compressed <b className="mono s-low">{factor.toLocaleString()}×</b>{' '}
                — from <b>{days} days</b> of typical dwell to <b>{oursLabel}</b>.</>
            : <>First correlated alert fired <b className="s-low">{oursLabel}</b> — on the first
                anomalous authentication, vs a <b>{days}-day</b> industry median dwell.</>}
          {mttd?.citation && <div style={{ marginTop: 4, fontSize: 11, color: 'var(--text-faint)' }}>
            Dwell reference: {mttd.citation}</div>}
        </div>
      </div>
    </Card>
  )
}
