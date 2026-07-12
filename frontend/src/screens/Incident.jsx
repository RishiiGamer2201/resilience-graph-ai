import { useEffect, useRef, useState } from 'react'
import { Play, Zap } from 'lucide-react'
import { getIncident } from '../api.js'
import { useFetch } from '../lib/useFetch.js'
import { Card, CardHeader, Loading, ErrorBox } from '../components/Card.jsx'
import LiveScoreWidget from '../components/LiveScoreWidget.jsx'
import IncidentReport from '../components/IncidentReport.jsx'
import { severityFromStep, fmtTime, describeAccount, describeHost, describeStep, shortExplanation } from '../lib/format.js'

const SEV_LABEL = { critical: 'critical', high: 'high', medium: 'medium', low: 'low', normal: 'normal' }

function prefersReducedMotion() {
  return typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches
}

function TimelineRow({ step, animate }) {
  const sev = severityFromStep(step)
  const tid = step.technique_id && step.technique_id !== '-' ? step.technique_id : null
  return (
    <div className={`ev${animate ? ' reveal' : ''}`}>
      <span className={`stripe bg-${sev}`} />
      <div className="t">{fmtTime(step.timestamp)}</div>
      <div>
        <div className="event-sentence">{describeStep(step)}</div>
        {tid && <div className="event-detail">{shortExplanation(step.explanation)}</div>}
        <span className="tag">{step.tactic}{tid && <> · <span className="tid">{tid}</span></>}</span>
      </div>
      <div><div className={`score s-${sev}`}>{step.anomaly_score}</div><div className={`lvl s-${sev}`}>{SEV_LABEL[sev]}</div></div>
    </div>
  )
}

export default function Incident() {
  const { data, error, loading } = useFetch(getIncident)
  const [visible, setVisible] = useState(Infinity)
  const [replaying, setReplaying] = useState(false)
  const timer = useRef(null)
  const steps = data?.steps || []

  useEffect(() => () => clearInterval(timer.current), [])

  function replay() {
    clearInterval(timer.current)
    if (prefersReducedMotion()) {
      setVisible(steps.length)
      setReplaying(false)
      return
    }
    setReplaying(true)
    setVisible(0)
    let index = 0
    timer.current = setInterval(() => {
      index += 1
      setVisible(index)
      if (index >= steps.length) {
        clearInterval(timer.current)
        setReplaying(false)
      }
    }, 220)
  }

  if (loading) return <Loading />
  if (error) return <ErrorBox error={error} />
  const shown = steps.slice(0, visible === Infinity ? steps.length : visible)

  return (
    <>
      <div className="page-head">
        <span className="tag-pill" style={{ background: 'color-mix(in srgb, var(--sev-critical) 14%, transparent)', color: 'var(--sev-critical)' }}>{data.incident_id}</span>
        <h2 className="s-critical">{data.severity.toUpperCase()}</h2>
        <p>{data.alert_count} alerts from {data.event_count} events · {describeAccount(data.account)} · investigation pivot: {describeHost(data.pivot)}</p>
      </div>

      <div className="grid2">
        <Card>
          <CardHeader title="Correlated attack chain — replay" meta={`${shown.length}/${steps.length} steps`}>
            <button className="btn" onClick={replay} disabled={replaying} style={{ display: 'inline-flex', gap: 6, alignItems: 'center' }}>
              <Play size={13} aria-hidden="true" /> {replaying ? 'Replaying…' : 'Replay'}
            </button>
          </CardHeader>
          <div className="card-b" style={{ maxHeight: 620, overflowY: 'auto' }}>
            {shown.map((step, index) => <TimelineRow key={`${step.timestamp}-${index}`} step={step} animate={replaying} />)}
          </div>
        </Card>

        <div className="stack">
          <Card>
            <CardHeader title="Live event scoring" meta="POST /score-event"><Zap size={15} aria-hidden="true" style={{ color: 'var(--accent)' }} /></CardHeader>
            <LiveScoreWidget />
          </Card>
          <Card>
            <CardHeader title="What this means" />
            <div className="card-b pad" style={{ color: 'var(--text-dim)', fontSize: 13, lineHeight: 1.6 }}>
              {data.event_count} raw sign-in events collapsed into a single correlated incident. The account appears to reuse stolen authentication material from {describeHost(data.pivot)}, then attempts repeated password guesses; anomaly scores reached {data.max_anomaly_score}. The scoring panel above runs the same Isolation-Forest model live.
            </div>
          </Card>
        </div>
      </div>

      <Card>
        <CardHeader title="Technical reference" meta="Raw identifiers retained for investigation" />
        <div className="kv">
          <div className="row"><div className="k">Account</div><div className="v">{data.account}</div><div className="meaning">Synthetic account identifier used in the LANL dataset.</div></div>
          <div className="row"><div className="k">Pivot host</div><div className="v">{data.pivot}</div><div className="meaning">Computer used as the investigation pivot.</div></div>
          {(data.technique_ids || []).map((id) => {
            const sample = steps.find((step) => step.technique_id === id)
            return <div className="row" key={id}><div className="k">ATT&CK technique</div><div className="v">{id}</div><div className="meaning">{sample?.technique || 'Mapped detection technique'}.</div></div>
          })}
        </div>
      </Card>

      <IncidentReport />
    </>
  )
}
