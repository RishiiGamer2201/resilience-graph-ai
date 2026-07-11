import { useEffect, useRef, useState } from 'react'
import { Play, Zap } from 'lucide-react'
import { getIncident } from '../api.js'
import { useFetch } from '../lib/useFetch.js'
import { Card, CardHeader, Loading, ErrorBox } from '../components/Card.jsx'
import LiveScoreWidget from '../components/LiveScoreWidget.jsx'
import IncidentReport from '../components/IncidentReport.jsx'
import { severityFromStep, fmtTime } from '../lib/format.js'

const SEV_LABEL = { critical: 'critical', high: 'high', medium: 'medium', low: 'low', normal: 'normal' }

function prefersReducedMotion() {
  return typeof window !== 'undefined' &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches
}

function TimelineRow({ step, animate }) {
  const sev = severityFromStep(step)
  const tid = step.technique_id && step.technique_id !== '-' ? step.technique_id : null
  return (
    <div className={`ev${animate ? ' reveal' : ''}`}>
      <span className={`stripe bg-${sev}`} />
      <div className="t">{fmtTime(step.timestamp)}</div>
      <div>
        <div className="who">{step.user} → {step.destination_host}</div>
        <span className="tag">
          {step.tactic}{tid && <> · <span className="tid">{tid}</span></>}
        </span>
      </div>
      <div>
        <div className={`score s-${sev}`}>{step.anomaly_score}</div>
        <div className={`lvl s-${sev}`}>{SEV_LABEL[sev]}</div>
      </div>
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
    let i = 0
    timer.current = setInterval(() => {
      i += 1
      setVisible(i)
      if (i >= steps.length) {
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
        <span className="tag-pill" style={{
          background: 'color-mix(in srgb, var(--sev-critical) 14%, transparent)',
          color: 'var(--sev-critical)',
        }}>{data.incident_id}</span>
        <h2 className="s-critical">{data.severity.toUpperCase()}</h2>
        <p className="mono">{data.alert_count} alerts ← {data.event_count} events · account {data.account} · pivot {data.pivot}</p>
      </div>

      <div className="grid2">
        <Card>
          <CardHeader title="Correlated attack chain — replay"
            meta={`${shown.length}/${steps.length} steps`}>
            <button className="btn" onClick={replay} disabled={replaying}
              style={{ display: 'inline-flex', gap: 6, alignItems: 'center' }}>
              <Play size={13} aria-hidden="true" /> {replaying ? 'Replaying…' : 'Replay'}
            </button>
          </CardHeader>
          <div className="card-b" style={{ maxHeight: 620, overflowY: 'auto' }}>
            {shown.map((step, i) => (
              <TimelineRow key={`${step.timestamp}-${i}`} step={step} animate={replaying} />
            ))}
          </div>
        </Card>

        <div className="stack">
          <Card>
            <CardHeader title="Live event scoring"
              meta="POST /score-event">
              <Zap size={15} aria-hidden="true" style={{ color: 'var(--accent)' }} />
            </CardHeader>
            <LiveScoreWidget />
          </Card>

          <Card>
            <CardHeader title="What this proves" />
            <div className="card-b pad" style={{ color: 'var(--text-dim)', fontSize: 13, lineHeight: 1.6 }}>
              215 raw auth events collapsed into a single correlated incident. Pass-the-hash
              ({data.technique_ids?.[0]}) fans out from pivot <b className="mono">{data.pivot}</b>,
              escalating to brute force ({data.technique_ids?.[1]}) with anomaly scores hitting {data.max_anomaly_score}.
              The scoring panel above runs the same Isolation-Forest model live.
            </div>
          </Card>
        </div>
      </div>

      <IncidentReport />
    </>
  )
}
