import { useState } from 'react'
import { CircleSlash, FileText, TrendingDown, TrendingUp } from 'lucide-react'
import { Card, CardHeader, ErrorBox, Loading } from '../components/Card.jsx'
import { getScoreboard } from '../api.js'
import { useFetch } from '../lib/useFetch.js'

// The PS7 scoreboard. Every value is read from reports/metrics.json, which the
// evaluation scripts write. A metric we have not measured renders "Not measured"
// with the reason — never a zero, never a number borrowed from a slide.
function fmt(v, unit) {
  if (v === null || v === undefined) return '—'
  const n = typeof v === 'number' ? (Number.isInteger(v) ? v : Math.round(v * 1000) / 1000) : v
  return `${n}${unit || ''}`
}

function MetricCard({ card }) {
  const [open, setOpen] = useState(false)
  const measured = card.state === 'measured'
  const Trend = card.higher_is_better ? TrendingUp : TrendingDown
  const beatsBaseline = measured && card.baseline?.value !== null
    && card.baseline?.value !== undefined
    && (card.higher_is_better ? card.value > card.baseline.value : card.value <= card.baseline.value)

  return (
    <div className={`sb-card ${measured ? '' : 'unmeasured'}`}>
      <div className="sb-name">{card.name}</div>
      <div className="sb-value mono">
        {measured ? fmt(card.value, card.unit) : (
          <span className="nm"><CircleSlash size={15} aria-hidden="true" /> Not measured</span>
        )}
      </div>
      {measured && card.baseline && (
        <div className={`sb-base ${beatsBaseline ? 's-low' : ''}`}>
          <Trend size={12} aria-hidden="true" />
          {' '}vs {card.baseline.name}: {fmt(card.baseline.value, card.unit)}
          {card.lift ? <b> · {card.lift}×</b> : null}
        </div>
      )}
      {!measured && <div className="sb-why">{card.why}</div>}
      <button className="linkish sb-more" onClick={() => setOpen(!open)} aria-expanded={open}>
        {open ? 'less' : 'definition, dataset, evidence'}
      </button>
      {open && (
        <div className="sb-detail">
          <p><b>Definition.</b> {card.definition}</p>
          <p><b>Dataset.</b> {card.dataset}{card.sample ? ` — ${card.sample}` : ''}</p>
          {card.note && <p><b>Note.</b> {card.note}</p>}
          <p className="mono dim">provenance: {card.provenance}</p>
          {card.report && (
            <p>
              <FileText size={11} aria-hidden="true" />{' '}
              <span className="mono">{card.report}</span>
              {!card.report_exists && <b className="s-critical"> (missing on disk)</b>}
            </p>
          )}
        </div>
      )}
    </div>
  )
}

export default function Scoreboard() {
  const { data, error, loading } = useFetch(getScoreboard)
  if (loading) return <Loading label="Reading reports/metrics.json…" />
  if (error) return <ErrorBox error={error} />

  return (
    <>
      <div className="page-head">
        <span className="tag-pill" style={{ background: 'var(--accent-soft)', color: 'var(--accent)' }}>
          PS7 EVALUATION
        </span>
        <h2>What we measured, against what baseline</h2>
        <p className="mono">
          {data.summary.measured} measured · {data.summary.not_measured} declared not measured ·
          generated {data.generated_at}
        </p>
      </div>

      {data.summary.missing_reports.length > 0 && (
        <div className="errbox" style={{ marginBottom: 16 }}>
          Evidence files missing for: {data.summary.missing_reports.join(', ')}
        </div>
      )}

      {data.groups.map((g) => (
        <section key={g.name} className="inv-section">
          <div className="section-label">{g.name}</div>
          <div className="sb-grid">
            {g.cards.map((c) => <MetricCard key={c.id} card={c} />)}
          </div>
        </section>
      ))}

      <Card style={{ marginTop: 18 }}>
        <CardHeader title="Claims we refuse to make" meta="and why" />
        <div className="card-b pad">
          <ul className="refused">
            {Object.entries(data.refused_claims).map(([claim, why]) => (
              <li key={claim}><b>{claim}</b> — {why}</li>
            ))}
          </ul>
          <p className="fineprint">
            {data.note} Regenerate with{' '}
            {data.sources.regenerate.map((c) => <code className="mono" key={c}>{c}</code>)
              .reduce((a, b) => [a, ' and ', b])}.
          </p>
        </div>
      </Card>
    </>
  )
}
