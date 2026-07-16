import { useEffect, useRef, useState } from 'react'
import { Play, Zap, Radio } from 'lucide-react'
import { getIncident, streamUrl } from '../api.js'
import { useScreenData, useAnalysis } from '../lib/analysis.jsx'
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
  const { data, error, loading } = useScreenData('incident', getIncident)
  const { setBundle } = useAnalysis()
  const [visible, setVisible] = useState(Infinity)
  const [replaying, setReplaying] = useState(false)
  const [streamSteps, setStreamSteps] = useState(null)   // null = not streaming
  const [streaming, setStreaming] = useState(false)
  const timer = useRef(null)
  const esRef = useRef(null)

  const steps = data?.steps || []

  useEffect(() => () => { clearInterval(timer.current); esRef.current?.close() }, [])

  // Stream the shipped scenario's real per-event scores live (SSE), then promote
  // the finished analysis to the live bundle so every screen updates.
  function streamLive() {
    clearInterval(timer.current); setReplaying(false)
    esRef.current?.close()
    setStreamSteps([]); setStreaming(true)
    const es = new EventSource(streamUrl('lanl_redteam_u66'))
    esRef.current = es
    es.addEventListener('step', (e) => {
      const { step } = JSON.parse(e.data)
      setStreamSteps((s) => [...(s || []), step])
    })
    es.addEventListener('done', (e) => {
      es.close(); setStreaming(false)
      try { setBundle(JSON.parse(e.data)) } catch { /* ignore */ }
    })
    es.onerror = () => { es.close(); setStreaming(false) }
  }

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

  const shown = streamSteps !== null
    ? streamSteps
    : steps.slice(0, visible === Infinity ? steps.length : visible)

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
            meta={streamSteps !== null ? `${shown.length} streamed` : `${shown.length}/${steps.length} steps`}>
            <button className="btn" onClick={streamLive} disabled={streaming}
              style={{ display: 'inline-flex', gap: 6, alignItems: 'center' }}
              title="Score the shipped scenario's events live over SSE">
              <Radio size={13} aria-hidden="true" /> {streaming ? 'Streaming…' : 'Stream live'}
            </button>
            <button className="btn" onClick={replay} disabled={replaying || streaming}
              style={{ display: 'inline-flex', gap: 6, alignItems: 'center' }}>
              <Play size={13} aria-hidden="true" /> {replaying ? 'Replaying…' : 'Replay'}
            </button>
          </CardHeader>
          <div className="card-b" style={{ maxHeight: 620, overflowY: 'auto' }}>
            {shown.map((step, i) => (
              <TimelineRow key={`${step.timestamp}-${i}`} step={step} animate={replaying || streaming} />
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
              {data.event_count} raw auth events collapsed into a single correlated incident —
              {' '}{data.alert_count} of them flagged anomalous. Activity fans out from pivot
              {' '}<b className="mono">{data.pivot}</b>
              {data.technique_ids?.length > 0 && <> across techniques{' '}
                {data.technique_ids.slice(0, 3).map((t) => <span className="mono" key={t}>{t} </span>)}</>}
              with anomaly scores reaching {data.max_anomaly_score}/100.
              The scoring panel above runs the same Isolation-Forest model live.
            </div>
          </Card>
        </div>
      </div>

      <IncidentReport />
    </>
  )
}
