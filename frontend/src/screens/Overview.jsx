import { getOverview } from '../api.js'
import { useFetch } from '../lib/useFetch.js'
import { Card, CardHeader, Loading, ErrorBox } from '../components/Card.jsx'
import Sparkline from '../components/Sparkline.jsx'

const SPARKS = {
  mttd: [40, 38, 33, 30, 22, 14, 9, 4],
  roc: [82, 90, 93, 95, 97, 98.5, 98.8],
  blast: [2, 9, 25, 44, 70, 88, 93],
}

export default function Overview() {
  const { data, error, loading } = useFetch(getOverview)
  if (loading) return <Loading />
  if (error) return <ErrorBox error={error} />

  const { mttd, active_incident, blast_radius_contained, alerts_correlated, scorecard } = data
  const highlight = scorecard.find((s) => s.name?.includes('LANL')) || scorecard[0]

  return (
    <>
      <div className="tiles">
        <div className="tile">
          <div className="k">Mean time to detect</div>
          <div className="v">{mttd.value}</div>
          <div className="sub"><span className="up">▼ from {mttd.was}</span> · {mttd.note}</div>
          <Sparkline points={SPARKS.mttd} />
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
          <Sparkline points={SPARKS.blast} />
        </div>

        <div className="tile">
          <div className="k">{highlight.name}</div>
          <div className="v">{highlight.value}</div>
          <div className="sub">{highlight.metric} · {highlight.kind}</div>
          <Sparkline points={SPARKS.roc} />
        </div>
      </div>

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
