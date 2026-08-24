import { useEffect, useRef, useState } from 'react'
import Progression from '../components/Progression.jsx'
import { Play, Zap, Radio } from 'lucide-react'
import { getIncident, streamUrl } from '../api.js'
import { useScreenData, useAnalysis } from '../lib/analysis.jsx'
import { Card, CardHeader, Loading, ErrorBox } from '../components/Card.jsx'
import Answer, { Reveal } from '../components/Answer.jsx'
import LiveScoreWidget from '../components/LiveScoreWidget.jsx'
import IncidentReport from '../components/IncidentReport.jsx'
import CalibrationBadge, { CalibrationNote } from '../components/CalibrationBadge.jsx'
import { severityFromStep, fmtTime, describeHost, describeStep, shortExplanation, incidentCount } from '../lib/format.js'

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
  const { data, error, loading } = useScreenData('incident', getIncident)
  const { bundle, setBundle } = useAnalysis()
  const [visible, setVisible] = useState(Infinity)
  const [replaying, setReplaying] = useState(false)
  const [streamSteps, setStreamSteps] = useState(null)   // null = not streaming
  const [streaming, setStreaming] = useState(false)
  const timer = useRef(null)
  const esRef = useRef(null)

  const steps = data?.steps || []
  // The scale every score in the timeline below is on.
  const cal = bundle?.meta?.calibration
  // Same enrichment every other path gets (src/shared/enrich), so the forecast
  // shows here whether this came from a live run or the cached sample.
  const forecast = (bundle?.analysis || data?.analysis)?.progression_forecast

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

  const shown = streamSteps !== null
    ? streamSteps
    : steps.slice(0, visible === Infinity ? steps.length : visible)

  return (
    <>
      {/* The screen was 4,650 words with the story of the attack sharing equal
          billing with a scoring sandbox, a table of raw identifiers and a full
          printable report. The story is what someone came for; the rest is
          reference and now reads as reference. */}
      <Answer
        headline={`${data.event_count} sign-in events from this log, grouped into ${incidentCount(data.incident_count ?? bundle?.meta?.incident_count)}.`}
        tone={String(data.severity).toLowerCase() === 'critical' ? 'critical' : 'high'}
        facts={[
          { k: 'sign-ins flagged', v: data.alert_count, hint: `from ${data.event_count} events` },
          { k: 'worked from', v: data.pivot, hint: 'the computer the attacker used as a base' },
          { k: 'highest score', v: data.max_anomaly_score, hint: cal ? cal.basis : 'out of 100' },
        ]}
        next={{ to: '/graph', label: 'See where it can spread' }}>
        {/* `data.account` is a single id on a small scenario and a count like
            "104 accounts" on a campaign, so the sentence has to read either way. */}
        The accounts involved (<b>{data.account}</b>) appear to reuse stolen sign-in
        material from {describeHost(data.pivot)}, then try repeated password guesses.
        Each row below is one real sign-in from the log, in the order it happened.
      </Answer>

      {cal && (
        <div className="calblock">
          <CalibrationBadge />
          <CalibrationNote />
        </div>
      )}

      <Card className="incident-chain-card">
        <CardHeader title="What the attacker did, step by step"
          meta={streamSteps !== null ? `${shown.length} streamed` : `${shown.length} of ${steps.length} steps`}>
          <button className="btn" onClick={streamLive} disabled={streaming}
            style={{ display: 'inline-flex', gap: 6, alignItems: 'center' }}
            title="Score this scenario's events live, one at a time">
            <Radio size={13} aria-hidden="true" /> {streaming ? 'Streaming…' : 'Stream live'}
          </button>
          <button className="btn" onClick={replay} disabled={replaying || streaming}
            style={{ display: 'inline-flex', gap: 6, alignItems: 'center' }}>
            <Play size={13} aria-hidden="true" /> {replaying ? 'Replaying…' : 'Replay'}
          </button>
        </CardHeader>
        {/* Sits outside the scroll container, so the scale stays on screen
            next to the score column however far down the timeline you are. */}
        {cal && <div className="calstrip"><CalibrationBadge label="timeline score scale" /></div>}
        <div className="card-b incident-timeline">
          {shown.map((step, index) => <TimelineRow key={`${step.timestamp}-${index}`} step={step} animate={replaying || streaming} />)}
        </div>
      </Card>

      {forecast && (
        <Reveal title="Where this goes next"
          summary="the forecast, and how far ahead it is still worth reading">
          <Progression forecast={forecast} />
        </Reveal>
      )}

      <Reveal title="Try the detector yourself"
        summary="describe a sign-in and see the score it would get">
        <Card>
          <CardHeader title="Live event scoring" meta="nothing is saved">
            <Zap size={15} aria-hidden="true" style={{ color: 'var(--accent)' }} />
          </CardHeader>
          <LiveScoreWidget />
          <div className="note">
            This scores one made-up event on the shipped reference scale, using the
            same benign-trained autoencoder as the timeline.
            {cal?.out_of_distribution && (
              <> The timeline above is on a <b>different scale</b>
              {' '}(<span className="mono">{cal.basis}</span>), so the two numbers are
              not comparable to each other.</>
            )}
          </div>
        </Card>
      </Reveal>

      <Reveal title="Raw identifiers"
        summary="the account, host and ATT&CK codes behind the plain-language names above">
        <div className="kv">
          <div className="row"><div className="k">Account</div><div className="v">{data.account}</div><div className="meaning">Synthetic account identifier used in the LANL dataset.</div></div>
          <div className="row"><div className="k">Pivot host</div><div className="v">{data.pivot}</div><div className="meaning">The computer the attacker worked from.</div></div>
          {(data.technique_ids || []).map((id) => {
            const sample = steps.find((step) => step.technique_id === id)
            return <div className="row" key={id}><div className="k">ATT&CK technique</div><div className="v">{id}</div><div className="meaning">{sample?.technique || 'Mapped detection technique'}.</div></div>
          })}
        </div>
      </Reveal>

      <Reveal title="The full written report"
        summary="everything above as one document you can print or download">
        <IncidentReport />
      </Reveal>
    </>
  )
}
