import { getOverview } from '../api.js'
import { useScreenData } from '../lib/analysis.jsx'
import { Card, CardHeader, Loading, ErrorBox } from '../components/Card.jsx'
import Sparkline from '../components/Sparkline.jsx'
import MttdPanel from '../components/MttdPanel.jsx'

export default function Overview() {
  const { data, error, loading } = useScreenData('overview', getOverview)
  if (loading) return <Loading />
  if (error) return <ErrorBox error={error} />

  const { mttd, active_incident, blast_radius_contained, alerts_correlated, score_trend, scorecard } = data

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

        <div className="tile">
          <div className="k">Anomaly-score trend</div>
          <div className="v">{alerts_correlated.alerts}</div>
          <div className="sub">correlated alerts · live scores</div>
          {score_trend?.length > 1 && <Sparkline points={score_trend} />}
        </div>
      </div>

      <MttdPanel mttd={mttd} />

      <Card>
        <CardHeader title="Detector scorecard"
          meta={`${alerts_correlated.alerts} alerts ← ${alerts_correlated.events} events`} />
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
      </Card>

      <div className="foot">
        Real data from <b>LANL red-team</b> + <b>MITRE ATT&amp;CK</b> ·
        {' '}light default, dark toggle · <b>2 live moments:</b> event scoring &amp; next-technique prediction
      </div>
    </>
  )
}
