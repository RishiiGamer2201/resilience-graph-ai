import { Card, CardHeader } from './Card.jsx'

// Weeks -> minutes detection-time visual. Proportional bars would make "ours"
// invisible (21 days vs 4 min), so we use fixed emphasis widths and state the
// real compression factor in text.
export default function MttdPanel({ mttd }) {
  const days = mttd?.traditional_days ?? 21
  const mins = mttd?.ours_minutes ?? 4
  const factor = Math.round((days * 24 * 60) / mins)

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
      <CardHeader title="Detection time — weeks to minutes" meta="MTTD" />
      <div className="card-b pad">
        <Row label="Traditional APT dwell" value={`≈ ${days} d`}
             width="100%" color="var(--sev-critical)" />
        <Row label="Resilience Graph AI" value={`≈ ${mins} min`}
             width="3%" color="var(--accent)" />
        <div style={{ marginTop: 6, fontSize: 13, color: 'var(--text)' }}>
          Detection compressed <b className="mono s-low">{factor.toLocaleString()}×</b>
          {' '}— from <b>{days} days</b> of adversary dwell to <b>{mins} minutes</b>.
        </div>
      </div>
    </Card>
  )
}
