import { useState } from 'react'
import { Bot, CircleCheck, CircleSlash, TriangleAlert } from 'lucide-react'
import { Card, CardHeader } from './Card.jsx'

// The ten-agent lane's own reasoning, rendered.
//
// The backend attaches this to every standard analysis. It is ADVISORY: the
// deterministic pipeline's severity, ATT&CK mapping, host topology and report
// summary are authoritative and unchanged (ADR 0007). What this panel adds is
// the agent lane's working — which agents ran, how long each took, what chains
// it ranked, and the narrative it wrote — so a reader can judge the second
// opinion instead of taking it on trust.
const STATUS_ICON = { ok: CircleCheck, degraded: TriangleAlert, failed: CircleSlash }
const STATUS_CLASS = { ok: 's-low', degraded: 's-high', failed: 's-critical' }

const CONFIRMATION_CLASS = {
  confirmed: 's-low', probable: 's-medium', unconfirmed: 's-normal',
}

export default function AgentPipeline({ pipeline }) {
  const [open, setOpen] = useState(false)
  if (!pipeline || pipeline.enabled === false) return null

  if (pipeline.status === 'failed') {
    return (
      <Card>
        <CardHeader title="10-agent lane" meta="failed" />
        <div className="card-b pad">
          <div className="disclosure">
            The agent lane failed{pipeline.error ? `: ${pipeline.error}` : '.'} The
            analysis above is unaffected — it is produced by the deterministic
            pipeline, and the agent lane is advisory.
          </div>
        </div>
      </Card>
    )
  }

  const traces = pipeline.agent_traces || []
  const degraded = traces.filter((t) => t.status !== 'ok')
  const chains = pipeline.ranked_chains || []

  return (
    <Card>
      <CardHeader title="10-agent lane"
        meta={`${traces.length} agents · ${Math.round(pipeline.total_ms || 0)} ms · advisory`} />
      <div className="card-b pad stack-sm">
        <div className="banner">
          <Bot size={15} aria-hidden="true" />
          <span>
            A second, differently-built reading of the same log. <b>Advisory</b> — the
            severity, ATT&amp;CK mapping, attack-path topology and report above come
            from the deterministic pipeline and are unchanged by anything here.
          </span>
        </div>

        <div className="ag-grid">
          {traces.map((t) => {
            const Icon = STATUS_ICON[t.status] || CircleSlash
            return (
              <div key={t.agent} className={`ag-cell ${STATUS_CLASS[t.status] || ''}`}>
                <div className="ag-name">
                  <Icon size={12} aria-hidden="true" /> {t.agent.replace(/_/g, ' ')}
                </div>
                <div className="ag-meta mono">
                  conf {t.confidence} · {Math.round(t.ms)} ms
                </div>
              </div>
            )
          })}
        </div>

        {degraded.length > 0 && (
          <div className="as-missing">
            <b>Degraded:</b> {degraded.map((d) => d.agent).join(', ')} —
            {' '}{degraded[0].notes?.[0] || 'partial output only'}
          </div>
        )}

        {chains.length > 0 && (
          <>
            <div className="section-label">Ranked chains</div>
            <table className="tbl">
              <caption className="sr-only">Attack chains ranked by the agent lane</caption>
              <thead>
                <tr>
                  <th scope="col">Entity</th><th scope="col">Techniques</th>
                  <th scope="col">Confirmation</th><th scope="col">Confidence</th>
                  <th scope="col">Score</th>
                </tr>
              </thead>
              <tbody>
                {chains.slice(0, 5).map((ch) => (
                  <tr key={ch.id || ch.entity}>
                    <th scope="row" className="mono">{ch.entity}</th>
                    <td className="mono">{(ch.techniques || ch.technique_ids || []).join(', ') || '—'}</td>
                    <td className={CONFIRMATION_CLASS[ch.confirmation] || ''}>
                      {ch.confirmation || 'unconfirmed'}
                    </td>
                    <td className="mono">{ch.confidence ?? '—'}</td>
                    <td className="mono">{ch.score ?? ch.risk_score ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}

        <button className="linkish" onClick={() => setOpen(!open)} aria-expanded={open}>
          {open ? 'Hide' : 'Show'} the agent narrative and predictions
        </button>
        {open && (
          <div className="xc-detail">
            <div className="cf-h">
              Agent narrative
              <span className="chip">
                {pipeline.point_b_method || 'template'} · non-authoritative
              </span>
            </div>
            <p className="xc-narr-p">{pipeline.incident_narrative || 'No narrative produced.'}</p>

            {(pipeline.predictions || []).length > 0 && (
              <>
                <div className="cf-h">Predicted next techniques</div>
                <ul className="cf-list mono">
                  {pipeline.predictions.slice(0, 5).map((p) => (
                    <li key={p.technique_id}>
                      {p.rank}. {p.technique_id} — {p.probability}
                      <span className="dim"> ({p.source})</span>
                    </li>
                  ))}
                </ul>
              </>
            )}
            <p className="fineprint">
              Narrative and predictions are the agent lane&apos;s. Nothing on this panel
              feeds a score, a gate, or the audit record.
            </p>
          </div>
        )}
      </div>
    </Card>
  )
}
