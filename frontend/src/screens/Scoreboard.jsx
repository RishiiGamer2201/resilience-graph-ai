import { useState } from 'react'
import { CircleSlash, FileText, TrendingDown, TrendingUp } from 'lucide-react'
import { Card, CardHeader, ErrorBox, Loading } from '../components/Card.jsx'
import Answer, { Reveal } from '../components/Answer.jsx'
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
      <Answer
        headline="Every number this product shows, and what it was compared against."
        facts={[
          { k: 'measured', v: data.summary.measured, hint: 'each against a baseline' },
          { k: 'not measured', v: data.summary.not_measured, hint: 'and we say so' },
          { k: 'claims refused', v: Object.keys(data.refused_claims).length,
            hint: 'things we will not assert' },
        ]}>
        A number with nothing to beat is not evidence, so every measured figure here
        carries the simpler method it was tested against -- including the cases where
        that simpler method won. Anything we did not measure says
        {' '}<b>Not measured</b> and gives the reason, rather than showing a zero.
        Read from <span className="mono">reports/metrics.json</span>, regenerated
        {' '}{data.generated_at}.
      </Answer>

      {data.summary.missing_reports.length > 0 && (
        <div className="errbox">
          Evidence files missing for: {data.summary.missing_reports.join(', ')}
        </div>
      )}

      {/* The first group open, the rest closed. Thirty-two metric cards
          expanded at once is a spreadsheet, and a reader looking for one
          number cannot see it. */}
      {data.groups.map((g, i) => (
        <Reveal key={g.name} title={g.name} open={i === 0}
          summary={`${g.cards.filter((c) => c.state === 'measured').length} of ${g.cards.length} measured`}>
          <div className="sb-grid">
            {g.cards.map((c) => <MetricCard key={c.id} card={c} />)}
          </div>
        </Reveal>
      ))}

      <Card>
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
