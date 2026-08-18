import { useEffect, useState } from 'react'
import { Microscope } from 'lucide-react'
import { Card, CardHeader } from './Card.jsx'
import { explainStep } from '../api.js'

// "Why did you flag this one line?" — the whole computation, read back, for a
// single alert. Each stage names the module that produced it and the value it
// produced, so an analyst can disagree with a step rather than with "the AI".
export default function ExplainTrace({ scenario, criticalAssets, events }) {
  const [idx, setIdx] = useState(0)
  const [trace, setTrace] = useState(null)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (!scenario && !events) return
    let alive = true
    setBusy(true); setError(null)
    explainStep({ scenario, events, critical_assets: criticalAssets || [], step_index: idx })
      .then((t) => { if (alive) setTrace(t) })
      .catch((e) => { if (alive) setError(e.message) })
      .finally(() => { if (alive) setBusy(false) })
    return () => { alive = false }
  }, [scenario, events, criticalAssets, idx])

  if (error) return <div className="errbox small">Explainability trace unavailable: {error}</div>
  if (!trace) return <div className="loading">{busy ? 'Building the trace…' : 'No trace yet.'}</div>
  if (!trace.available) return <div className="disclosure">{trace.reason}</div>

  return (
    <Card>
      <CardHeader title="Explainability trace"
        meta={`alert ${idx + 1} of ${trace.alerts_available}`}>
        <button className="btn" disabled={idx === 0 || busy} onClick={() => setIdx(idx - 1)}>
          Previous
        </button>
        <button className="btn" disabled={idx + 1 >= trace.alerts_available || busy}
          onClick={() => setIdx(idx + 1)}>
          Next alert
        </button>
      </CardHeader>
      <div className="card-b pad">
        <div className="banner">
          <Microscope size={15} aria-hidden="true" />
          <span className="mono">
            {trace.step.user} · {trace.step.source_host} → {trace.step.destination_host} ·
            score {trace.step.anomaly_score} · {trace.step.technique_id}
          </span>
        </div>
        <ol className="trace">
          {trace.stages.map((s) => (
            <li key={s.stage}>
              <div className="t-head">
                <b>{s.stage}</b>
                <span className="mono dim">{s.produced_by}</span>
              </div>
              <pre className="mono t-val">{JSON.stringify(s.value, null, 1)}</pre>
              <p className="t-exp">{s.explanation}</p>
            </li>
          ))}
        </ol>
        <p className="fineprint">{trace.note}</p>
      </div>
    </Card>
  )
}
