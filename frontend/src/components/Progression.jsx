import { useState } from 'react'
import { ArrowRight, TrendingUp } from 'lucide-react'
import { Card, CardHeader } from './Card.jsx'

// Forward simulation: where the attack goes next, and how much to trust it.
//
// Two curves, deliberately not multiplied together. The bars are P(the
// trajectory has reached an impact-stage technique by step k) — monotone, it
// cannot fall. The opacity is horizon confidence, which decays fast. A step-5
// bar at 96% drawn nearly transparent is the honest picture: the model says it
// is likely, and the model is not worth much that far out.
const STAGE_CLASS = {
  'lateral movement': 's-medium',
  'privilege escalation': 's-high',
  collection: 's-high',
  exfiltration: 's-critical',
  impact: 's-critical',
  'command and control': 's-high',
}

export default function Progression({ forecast }) {
  const [open, setOpen] = useState(false)
  if (!forecast) return null

  if (!forecast.available) {
    return (
      <Card>
        <CardHeader title="Attack progression forecast" meta="not available" />
        <div className="card-b pad">
          <div className="disclosure">{forecast.reason}</div>
        </div>
      </Card>
    )
  }

  const probs = forecast.infiltration_probability || []
  const confs = forecast.horizon_confidence || []
  const maxP = Math.max(100, ...probs)

  return (
    <Card>
      <CardHeader title="Attack progression forecast"
        meta={`${forecast.k_steps} steps · reliable to step ${forecast.reliable_horizon}`} />
      <div className="card-b pad stack-sm">
        <div className="banner">
          <TrendingUp size={15} aria-hidden="true" />
          <span>{forecast.headline}</span>
        </div>

        <div className="pg-chart" role="img"
          aria-label={`Infiltration probability across ${probs.length} predicted steps`}>
          {probs.map((p, i) => {
            const step = forecast.steps[i]
            const beyond = step.step > forecast.reliable_horizon
            return (
              <div key={step.step} className="pg-col">
                <div className="pg-bar-wrap">
                  <div
                    className={`pg-bar ${beyond ? 'beyond' : ''}`}
                    style={{ height: `${(p / maxP) * 100}%`, opacity: 0.25 + confs[i] * 0.75 }}
                    title={`step ${step.step}: ${p}% at horizon confidence ${confs[i]}`}
                  />
                </div>
                <div className="pg-p mono">{p}%</div>
                <div className="pg-step mono">t+{step.step}</div>
                <div className={`pg-stage ${STAGE_CLASS[step.predictions[0]?.stage] || ''}`}>
                  {step.predictions[0]?.stage || '—'}
                </div>
                <div className="pg-conf mono" title="horizon confidence">
                  {confs[i]}
                </div>
              </div>
            )
          })}
        </div>
        <div className="pg-legend mono">
          bar height = P(reached an impact stage by this step) · bar opacity and the
          bottom row = horizon confidence · faded bars are past the reliable horizon
        </div>

        <div className="pg-path">
          <b>Most likely continuation:</b>{' '}
          {(forecast.most_likely_paths?.[0]?.predicted || []).map((t, i, arr) => (
            <span key={t + i}>
              <span className="mono">{t}</span>
              {i < arr.length - 1 && <ArrowRight size={11} aria-hidden="true" />}
            </span>
          ))}
        </div>

        <button className="linkish" onClick={() => setOpen(!open)} aria-expanded={open}>
          {open ? 'Hide' : 'Show'} per-step predictions and method
        </button>
        {open && (
          <div className="xc-detail">
            {forecast.steps.map((s) => (
              <div key={s.step} className="pg-detail-row">
                <b className="mono">t+{s.step}</b>
                <span className="dim mono"> conf {s.horizon_confidence}</span>
                <ul className="cf-list">
                  {s.predictions.map((pr) => (
                    <li key={pr.technique_id}>
                      <span className="mono">{pr.technique_id}</span> {pr.name}
                      <span className="dim"> · {pr.stage} · p={pr.probability}</span>
                      {pr.is_impact && <span className="s-critical"> · impact stage</span>}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
            <p className="fineprint">
              <b>Method.</b> {forecast.method.model}; {forecast.method.search}.{' '}
              {forecast.method.decay}
            </p>
            <p className="fineprint">{forecast.beyond_horizon_note}</p>
            <p className="fineprint">{forecast.honesty}</p>
          </div>
        )}
      </div>
    </Card>
  )
}
