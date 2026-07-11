import { getThreatIntel } from '../api.js'
import { useFetch } from '../lib/useFetch.js'
import { Card, CardHeader, Loading, ErrorBox } from '../components/Card.jsx'
import PredictNextWidget from '../components/PredictNextWidget.jsx'

export default function ThreatIntel() {
  const { data, error, loading } = useFetch(getThreatIntel)
  if (loading) return <Loading />
  if (error) return <ErrorBox error={error} />

  const { mapping, attribution, note } = data

  return (
    <>
      <div className="grid2">
        <div className="stack">
          <Card>
            <CardHeader title="Observed techniques" meta={`${mapping.length} mapped`} />
            <div className="card-b pad" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              {mapping.map((m) => (
                <div className="tech" key={m.technique_id}>
                  <div className="th">
                    <span className="tid2">{m.technique_id}</span>
                    <span className="tname">{m.name}</span>
                  </div>
                  <div className="texp">{m.explanation}</div>
                </div>
              ))}
            </div>
          </Card>

          <Card>
            <CardHeader title="Predict next technique" meta="POST /predict-next" />
            <PredictNextWidget />
          </Card>
        </div>

        <Card>
          <CardHeader title="Actor attribution" meta="ranked by profile match" />
          <div className="card-b pad">
            <div className="ranked">
              {attribution.map((a, i) => (
                <div className={`actor${i === 0 ? ' top' : ''}`} key={a.actor}>
                  <span className="rank">#{i + 1}</span>
                  <div style={{ minWidth: 0 }}>
                    <div className="who">{a.actor}</div>
                    <div className="just">{a.justification}</div>
                    <div className="matched">
                      {a.matched.map((t) => (
                        <span className="tag-pill" key={t}
                          style={{ background: 'var(--accent-soft)', color: 'var(--accent)' }}>{t}</span>
                      ))}
                    </div>
                  </div>
                  <div className="score-col">
                    <div className="n">{a.score.toFixed(3)}</div>
                    <div className="cv">coverage {Math.round(a.coverage * 100)}%</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
          <div className="note"><b>Transparent attribution.</b> {note}</div>
        </Card>
      </div>
    </>
  )
}
