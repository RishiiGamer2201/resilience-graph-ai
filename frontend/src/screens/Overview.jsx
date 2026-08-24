import { getOverview } from '../api.js'
import { useAnalysis, useScreenData } from '../lib/analysis.jsx'
import { Card, CardHeader, Loading, ErrorBox } from '../components/Card.jsx'
import Answer, { Reveal } from '../components/Answer.jsx'
import Sparkline from '../components/Sparkline.jsx'
import MttdPanel from '../components/MttdPanel.jsx'
import AgentPipeline from '../components/AgentPipeline.jsx'
import Assessment, { ClaimsPanel } from '../components/Assessment.jsx'
import Progression from '../components/Progression.jsx'
import CrossCheck from '../components/CrossCheck.jsx'
import CalibrationBadge, { CalibrationNote } from '../components/CalibrationBadge.jsx'
import { Term } from '../lib/glossary.jsx'

/* This screen was 3,074 pixels of eight equally weighted cards, opening with
 * four metric tiles. Somewhere inside it were the three things a reader came
 * for -- what happened, how bad it is, what to do -- and no way to tell those
 * apart from the detector's held-out ROC-AUC.
 *
 * It now answers first and argues second. One sentence, three numbers, one
 * link onward. Everything else is behind a summary line that says what is
 * inside, so opening a panel is a decision rather than a scroll.
 */

/** Plain-language lead, assembled from the analysis rather than written once. */
function lead(active, blast, alerts, mttd) {
  const sev = String(active?.severity || '').toLowerCase()
  const what = sev === 'critical' || sev === 'high'
    ? 'This log contains an attack that is still spreading.'
    : 'This log contains suspicious activity worth a look.'
  return {
    headline: what,
    tone: sev === 'critical' ? 'critical' : sev === 'high' ? 'high' : undefined,
    facts: [
      { k: 'computers now reachable', v: blast,
        hint: 'if nobody intervenes' },
      { k: 'suspicious sign-ins found', v: alerts,
        hint: 'grouped into one story' },
      { k: 'time to the first alert', v: mttd,
        hint: 'measured on this log' },
    ],
  }
}

export default function Overview() {
  const { data, error, loading } = useScreenData('overview', getOverview)
  // The 10-agent lane rides on the analysis bundle's meta, so it is only present
  // for a live analysis, not for the pre-computed sample cache.
  const { bundle } = useAnalysis()
  if (loading) return <Loading />
  if (error) return <ErrorBox error={error} />

  const { mttd, active_incident, blast_radius_contained, alerts_correlated, score_trend, scorecard } = data
  // Live analysis carries the agent lane on meta; the pre-computed sample
  // carries it inside the overview payload, so the panel shows on a cold
  // landing too instead of looking like a missing feature.
  const agentPipeline = bundle?.meta?.agent_pipeline || data.agent_pipeline
  // The analysis layer is produced by src/shared/enrich for EVERY path, so the
  // same panels render whether this came from a live run, an upload, the SSE
  // replay or the pre-computed sample.
  const analysis = bundle?.analysis || data.analysis
  // How the scores in the trend tile were calibrated. Absent on the cached
  // sample, which is why the tile falls back to its plain caption.
  const cal = bundle?.meta?.calibration
  const l = lead(active_incident, blast_radius_contained, alerts_correlated.alerts, mttd.value)

  return (
    <>
      <Answer headline={l.headline} tone={l.tone} facts={l.facts}
        next={{ to: '/incident', label: 'Read the story of the attack' }}>
        {active_incident.summary}{' '}
        The account involved is <b>{active_incident.account}</b>. Disconnecting one
        computer would cut off <b>{blast_radius_contained}</b> of the machines the
        attacker can currently reach -- which one, and what it would break, is on
        the containment screen.
      </Answer>

      {cal && (
        <div className="calblock">
          <CalibrationBadge />
          <CalibrationNote />
        </div>
      )}

      {analysis && (
        <Reveal open title="How bad, and how sure"
          summary="four separate judgements, and what is still missing">
          <Assessment assessment={analysis.assessment}
            likelihood={analysis.attack_progression_likelihood}
            confidence={analysis.evidence_confidence} />
        </Reveal>
      )}

      {analysis && (
        <Reveal title="What we are actually claiming"
          summary="each ATT&CK technique, and whether it was seen or only inferred">
          <ClaimsPanel claims={analysis.claims} />
        </Reveal>
      )}

      {analysis?.progression_forecast && (
        <Reveal title="Where this goes next"
          summary="the forecast, and how far ahead it is still worth reading">
          <Progression forecast={analysis.progression_forecast} />
        </Reveal>
      )}

      <Reveal title="How quickly it was caught"
        summary={`first alert ${mttd.value}, against a typical ${mttd.was} before anyone notices`}>
        <MttdPanel mttd={mttd} />
      </Reveal>

      <Reveal title="How accurate the detector is"
        summary="scores from held-out testing, including where a simpler method wins">
        <Card>
          <CardHeader title="Detector benchmarks" meta="fixed, not from this log" />
          <div className="card-b pad">
            <div className="metric-row">
              {scorecard.map((s) => (
                <div className="mcard" key={s.name}>
                  <div className="name">{s.name}</div>
                  <div className="val">{s.value}</div>
                  <div className="metricname">{s.metric}</div>
                  <span className="chip">{s.kind}</span>
                </div>
              ))}
            </div>
          </div>
          <div className="note">
            These describe the <b>detector</b>, measured once on held-out data, so they
            are the same whatever log you analyse. The numbers at the top of this
            page ({alerts_correlated.alerts} alerts from {alerts_correlated.events} events)
            are what changes with the data.
            {cal?.out_of_distribution && (
              <> This log is <Term k="out of distribution" as="out of distribution" /> for
              that evaluation, so its per-event scores are
              {' '}<span className="mono">{cal.basis}</span> and the benchmark&rsquo;s
              operating point does not apply to them.</>
            )}
          </div>
        </Card>
      </Reveal>

      {analysis?.crosscheck && (
        <Reveal title="A second opinion"
          summary="a differently-built analysis of the same log, and whether it agrees">
          <CrossCheck crosscheck={analysis.crosscheck} />
        </Reveal>
      )}

      {agentPipeline && (
        <Reveal title="Every stage, timed"
          summary="what each step of the pipeline concluded and how long it took">
          <AgentPipeline pipeline={agentPipeline} />
        </Reveal>
      )}

      {score_trend?.length > 1 && (
        <Reveal title="Score trend across the log"
          summary={`${alerts_correlated.alerts} alerts, ${cal ? cal.basis : 'live scores'}`}>
          <div className="card-b pad"><Sparkline points={score_trend} /></div>
        </Reveal>
      )}

      <div className="foot">
        Real data from <b>LANL red-team</b> + <b>MITRE ATT&amp;CK</b>.
        Nothing here is executed: every proposed action needs a human to approve it.
      </div>
    </>
  )
}
