/**
 * Forward simulation: where the attack goes next, and how much to trust it.
 *
 * Two curves, deliberately NOT multiplied together. The bar height is
 * P(the trajectory has reached an impact-stage technique by step k) - monotone,
 * it cannot fall. The bar opacity and the bottom row are horizon confidence,
 * which decays fast. A step-5 bar at 96% drawn nearly transparent is the honest
 * picture: the model says it is likely, and the model is not worth much that
 * far out.
 *
 * Probability and confidence are two numbers and are never combined into one.
 */
import { ArrowRight, TrendingUp } from 'lucide-react'
import { motion, useReducedMotion } from 'motion/react'
import { Card, CardBody, CardHeader, CardMeta, CardTitle } from '@/components/ui/card'
import { EmptyState, NotMeasured, SectionLabel } from '@/components/primitives'
import { Disclosure, FinePrint } from '@/components/Disclosure'
import { DURATION, EASE, STAGGER, STAGGER_MAX } from '@/lib/motion'
import type { ProgressionForecast } from '@/types/api'
import { techniqueName } from '@/lib/techniques'

const STAGE_CLASS: Record<string, string> = {
  'lateral movement': 'text-sev-medium',
  'privilege escalation': 'text-sev-high',
  collection: 'text-sev-high',
  exfiltration: 'text-sev-critical',
  impact: 'text-sev-critical',
  'command and control': 'text-sev-high',
}

export default function Progression({
  forecast,
}: {
  forecast: ProgressionForecast | null | undefined
}) {
  const reduced = useReducedMotion()
  if (!forecast) return null

  if (!forecast.available) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Attack progression forecast</CardTitle>
          <CardMeta>not available</CardMeta>
        </CardHeader>
        <EmptyState
          icon={TrendingUp}
          title="No forecast was produced"
          detail={forecast.reason ?? 'The backend gave no reason.'}
        />
      </Card>
    )
  }

  const probs = forecast.infiltration_probability ?? []
  const confs = forecast.horizon_confidence ?? []
  const steps = forecast.steps ?? []
  const maxP = Math.max(100, ...probs)
  const horizon = forecast.reliable_horizon ?? 0
  const stagger = steps.length > STAGGER_MAX ? 0 : STAGGER

  return (
    <Card>
      <CardHeader>
        <CardTitle>Attack progression forecast</CardTitle>
        <CardMeta>
          {forecast.k_steps} steps · reliable to step {horizon}
        </CardMeta>
      </CardHeader>
      <CardBody className="space-y-3">
        <div className="flex items-start gap-2 rounded-md border border-border bg-surface-2 px-3 py-2 text-xs text-dim">
          <TrendingUp className="mt-0.5 size-3.5 shrink-0" aria-hidden />
          <span>{forecast.headline ?? 'No headline was returned for this forecast.'}</span>
        </div>

        <div
          className="flex items-end gap-2"
          role="img"
          aria-label={`Infiltration probability and horizon confidence: ${steps
            .map((step, index) => `step ${step.step}, ${probs[index] != null ? `${probs[index]} percent probability` : 'probability not measured'}, ${confs[index] ?? step.horizon_confidence} confidence`)
            .join('; ')}`}
        >
          {steps.map((s, i) => {
            const p = probs[i]
            const conf = confs[i] ?? s.horizon_confidence
            const beyond = s.step > horizon
            const stage = s.predictions[0]?.stage
            return (
              <div key={s.step} className="flex min-w-0 flex-1 flex-col items-center gap-1">
                <div className="flex h-28 w-full items-end rounded-md border border-border bg-surface-2 p-1">
                  {p != null ? (
                    <motion.div
                      className={`w-full rounded-sm ${beyond ? 'bg-sev-normal' : 'bg-accent'}`}
                      style={{ opacity: 0.25 + conf * 0.75 }}
                      initial={reduced ? false : { height: 0 }}
                      animate={{ height: `${(p / maxP) * 100}%` }}
                      transition={{ duration: DURATION.slow, ease: EASE, delay: reduced ? 0 : i * stagger }}
                      title={`step ${s.step}: ${p}% at horizon confidence ${conf}`}
                    />
                  ) : null}
                </div>
                <div className="font-mono text-xs tabular-nums text-text">
                  {p != null ? `${p}%` : <NotMeasured />}
                </div>
                <div className="font-mono text-xs text-faint">t+{s.step}</div>
                <div
                  className={`truncate text-center text-xs ${STAGE_CLASS[stage ?? ''] ?? 'text-dim'}`}
                  title={stage}
                >
                  {stage ?? 'stage not predicted'}
                </div>
                <div className="font-mono text-xs text-faint" title="horizon confidence">
                  {conf}
                </div>
              </div>
            )
          })}
        </div>

        <FinePrint>
          bar height = P(reached an impact stage by this step) · bar opacity and the bottom row
          = horizon confidence · greyed bars are past the reliable horizon
        </FinePrint>

        {forecast.most_likely_paths?.[0]?.predicted?.length ? (
          <div className="flex flex-wrap items-center gap-1 text-xs text-dim">
            <span className="font-medium text-text">Most likely continuation:</span>
            {forecast.most_likely_paths[0].predicted.map((t, i, arr) => (
              <span key={`${t}-${i}`} className="inline-flex items-center gap-1">
                <span className="text-text">{techniqueName(t)}</span>
                {i < arr.length - 1 ? (
                  <ArrowRight className="size-3 text-faint" aria-hidden />
                ) : null}
              </span>
            ))}
          </div>
        ) : null}

        <Disclosure
          label="Show per-step predictions and method"
          labelOpen="Hide per-step predictions"
        >
          <div className="space-y-3">
            {steps.map((s) => (
              <div key={s.step}>
                <div className="flex items-baseline gap-2">
                  <SectionLabel>t+{s.step}</SectionLabel>
                  <span className="font-mono text-xs text-faint">
                    horizon confidence {s.horizon_confidence} · model {s.model_source}
                  </span>
                </div>
                <ul className="mt-1 space-y-0.5 text-xs text-dim">
                  {s.predictions.map((pr) => (
                    <li key={pr.technique_id}>
                      <span className="text-text">{techniqueName(pr.technique_id, pr.name)}</span>
                      <span className="text-faint">
                        {' '}
                        · {pr.stage} · p={pr.probability}
                      </span>
                      {pr.is_impact ? (
                        <span className="text-sev-critical"> · impact stage</span>
                      ) : null}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
            {forecast.method ? (
              <FinePrint>
                <span className="font-medium text-text">Method.</span> {forecast.method.model};{' '}
                {forecast.method.search}. {forecast.method.decay}
              </FinePrint>
            ) : null}
            {forecast.beyond_horizon_note ? (
              <FinePrint>{forecast.beyond_horizon_note}</FinePrint>
            ) : null}
            {forecast.honesty ? <FinePrint>{forecast.honesty}</FinePrint> : null}
          </div>
        </Disclosure>
      </CardBody>
    </Card>
  )
}
