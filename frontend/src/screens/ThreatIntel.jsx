import { getThreatIntel } from '../api.js'
import { useScreenData, useAnalysis } from '../lib/analysis.jsx'
import { Card, CardHeader, Loading, ErrorBox } from '../components/Card.jsx'
import Answer, { Reveal } from '../components/Answer.jsx'
import PredictNextWidget from '../components/PredictNextWidget.jsx'

export default function ThreatIntel() {
  const { data, error, loading } = useScreenData('threat_intel', getThreatIntel)
  const { bundle } = useAnalysis()
  if (loading) return <Loading />
  if (error) return <ErrorBox error={error} />

  const { mapping, attribution, note } = data
  const narrative =
    bundle?.overview?.incident_narrative ||
    bundle?.report?.agent_narrative ||
    bundle?.meta?.agent_pipeline?.incident_narrative ||
    bundle?.incident?.summary ||
    'The intrusion initiated with anomalous authentication activity linked to compromised accounts, generating unauthorized traversal across internal network endpoints before targeting critical infrastructure.'

  return (
    <>
      {/* The answer to "who is this" is the ranked list, so the ranked list is
          not a sidebar. And the margin between first and second place is the
          part that matters: a leader nobody is close to means something, a
          leader two points ahead of four others does not. */}
      <Answer
        headline={attribution.length
          ? `This behaviour most closely matches ${attribution[0].actor}.`
          : 'No named group matches this behaviour closely enough to name one.'}
        facts={attribution.slice(0, 3).map((a, i) => ({
          k: a.actor,
          v: `#${i + 1}`,
          hint: `${Math.round(a.coverage * 100)}% of their known behaviour seen here`,
        }))}>
        {narrative}
      </Answer>

      <Reveal open title="Why these candidates, in this order"
        summary={`${attribution.length} groups, ranked by how much of their known behaviour appears in this log`}>
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
        <div className="note"><b>How this is decided.</b> {note}</div>
      </Reveal>

      <Reveal title="What we saw them do"
        summary={`${mapping.length} named attacker behaviours found in this log`}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
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
      </Reveal>

      <Reveal title="What they would probably do next"
        summary="the most likely follow-on behaviour, and how confident that is">
        <Card>
          <CardHeader title="Predict next technique" meta="from what has happened so far" />
          <PredictNextWidget />
        </Card>
      </Reveal>
    </>
  )
}
