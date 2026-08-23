import { getOverview } from '../api.js'
import { useAnalysis, useScreenData } from '../lib/analysis.jsx'
import { Card, CardHeader, Loading, ErrorBox } from '../components/Card.jsx'
import Sparkline from '../components/Sparkline.jsx'
import MttdPanel from '../components/MttdPanel.jsx'
import AgentPipeline from '../components/AgentPipeline.jsx'
import Assessment, { ClaimsPanel } from '../components/Assessment.jsx'
import Progression from '../components/Progression.jsx'
import CrossCheck from '../components/CrossCheck.jsx'
import CalibrationBadge, { CalibrationNote } from '../components/CalibrationBadge.jsx'
import { Card as SurfaceCard, CardHeader as SurfaceHeader } from '../components/Card.jsx'

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

  return (
    <>
      <div className="tiles">
        <div className="tile">
          <div className="k">Time to first alert</div>
          <div className="v">{mttd.value}</div>
          <div className="sub">measured from this log · vs {mttd.was} typical dwell</div>
        </div>

        <div className="tile crit">
          <div className="k">Active incident</div>
          <div className="v">{active_incident.severity.toUpperCase()}</div>
          <div className="sub">{active_incident.account} · {active_incident.summary}</div>
        </div>

        <div className="tile">
          <div className="k">Blast radius contained</div>
          <div className="v">{blast_radius_contained}</div>
          <div className="sub">hosts cut by isolating 1 node</div>
        </div>

        <div className={`tile${cal?.out_of_distribution ? ' ood' : ''}`}>
          <div className="k">Anomaly-score trend</div>
          <div className="v">{alerts_correlated.alerts}</div>
          <div className="sub">correlated alerts · {cal ? cal.basis : 'live scores'}</div>
          {score_trend?.length > 1 && <Sparkline points={score_trend} />}
        </div>
      </div>

      {cal && (
        <div className="calblock" style={{ marginTop: 16 }}>
          <CalibrationBadge />
          <CalibrationNote />
        </div>
      )}

      <MttdPanel mttd={mttd} />

      <Card>
        <CardHeader title="Detector benchmarks" meta="model performance — fixed" />
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
          These are the <b>models' benchmark scores</b> (from held-out evaluation) — they
          describe the detectors, so they're the same whatever log you analyze. The
          per-incident numbers above ({alerts_correlated.alerts} alerts ← {alerts_correlated.events} events)
          are what changes with the data.
          {cal?.out_of_distribution && (
            <> This log is out of distribution for that evaluation, so its per-event
            scores are <span className="mono">{cal.basis}</span> and the benchmark&rsquo;s
            operating point does not apply to them.</>
          )}
        </div>
      </Card>

      {analysis && (
        <>
          <Assessment assessment={analysis.assessment}
            likelihood={analysis.attack_progression_likelihood}
            confidence={analysis.evidence_confidence} />
          <div style={{ marginTop: 20 }}>
            <Progression forecast={analysis.progression_forecast} />
          </div>
          <div style={{ marginTop: 20 }}>
            <SurfaceCard>
              <SurfaceHeader title="What we actually claim"
                meta="observed · inferred · predicted" />
              <div className="card-b pad">
                <ClaimsPanel claims={analysis.claims} />
              </div>
            </SurfaceCard>
          </div>
          {analysis.crosscheck && (
            <div style={{ marginTop: 20 }}>
              <CrossCheck crosscheck={analysis.crosscheck} />
            </div>
          )}
        </>
      )}

      {agentPipeline && (
        <div style={{ marginTop: 20 }}>
          <AgentPipeline pipeline={agentPipeline} />
        </div>
      )}

      <div className="foot">
        Real data from <b>LANL red-team</b> + <b>MITRE ATT&amp;CK</b> ·
        {' '}light default, dark toggle · <b>2 live moments:</b> event scoring &amp; next-technique prediction
      </div>
    </>
  )
}
