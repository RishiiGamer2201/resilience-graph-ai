/**
 * Engine 3, printed.
 *
 * Engine 3 has no place in the analysis flow because it feeds no alert, no
 * score and no severity — and for a while that meant it had no surface at all,
 * which reads as an unfinished feature rather than a deliberate boundary.
 *
 * The boundary is the point, so this screen shows it: the model is a QUANTISED
 * state space, not a black box, and the whole reason for quantising is that a
 * state can be described. All 24 of them are here, in units of training
 * standard deviations, next to the transition matrix that connects them and the
 * evaluation that says plainly where a trivial baseline still beats us.
 *
 * Nothing here is computed in the browser. Every number comes from
 * /api/netstate/model, which reads the shipped artifact and reports/metrics.json.
 */
import { useMemo, useState } from 'react'
import { Boxes, TriangleAlert } from 'lucide-react'

import { getNetstateModel } from '@/lib/api'
import { useFetch } from '@/hooks/useFetch'
import { PageHeader } from '@/components/Layout'
import { Card, CardBody, CardHeader, CardMeta, CardTitle } from '@/components/ui/card'
import { SkeletonRows } from '@/components/ui/skeleton'
import { EmptyState, ErrorState, SectionLabel } from '@/components/primitives'
import type { NetstateComparison, NetstateModel, NetstateState } from '@/types/api'

/** The comparison strip. Order, the beaten flag and the prose are all computed
 *  server-side from the measured values -- see api.main._netstate_comparison.
 *  Nothing here decides which of our own models lost. */
const ROLE_TONE: Record<string, string> = {
  baseline: 'bg-faint',
  ours: 'bg-accent',
  ceiling: 'bg-faint/40',
}

function EvaluationStrip({ comparison }: { comparison: NetstateComparison | undefined }) {
  const rows = comparison?.rows ?? []
  if (!rows.length) {
    return <EmptyState title="The evaluation has not been run for this artifact" />
  }
  const max = Math.max(...rows.map((r) => r.value), 0.5)

  return (
    <div className="flex flex-col gap-2.5">
      {rows.map((r) => (
        <div key={r.key} className="grid grid-cols-[minmax(0,11rem)_1fr_auto] items-center gap-3">
          <div className="min-w-0">
            <div className="truncate text-sm text-text">{r.label}</div>
            <div className="truncate text-xs text-faint">{r.detail}</div>
          </div>
          <div className="h-2 overflow-hidden rounded-full bg-surface-3">
            <div
              className={`h-full rounded-full ${
                r.beaten_by_baseline ? 'bg-sev-high' : ROLE_TONE[r.role] ?? 'bg-faint'
              }`}
              style={{ width: `${((r.value / max) * 100).toFixed(1)}%` }}
            />
          </div>
          <div className="w-16 text-right font-mono text-sm tabular-nums text-text">
            {r.value.toFixed(4)}
          </div>
        </div>
      ))}
    </div>
  )
}

/** One latent state, described in training standard deviations. */
function StateCard({ s, selected, onSelect }: {
  s: NetstateState
  selected: boolean
  onSelect: () => void
}) {
  const rate = s.attack_rate ?? 0
  const tone = rate >= 0.5 ? 'text-sev-critical' : rate >= 0.2 ? 'text-sev-high' : 'text-dim'
  return (
    <button
      type="button"
      onClick={onSelect}
      aria-pressed={selected}
      className={`w-full rounded-lg border p-3 text-left transition-colors duration-[120ms] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent ${
        selected ? 'border-accent bg-accent-soft' : 'border-border bg-surface hover:bg-surface-2'
      }`}
    >
      <div className="flex items-baseline justify-between gap-2">
        <span className="font-mono text-sm font-medium text-text">State {s.state}</span>
        <span className={`font-mono text-xs tabular-nums ${tone}`}>
          {(rate * 100).toFixed(1)}% attack
        </span>
      </div>
      <div className="mt-0.5 font-mono text-[11px] text-faint">
        {s.training_windows.toLocaleString()} training windows
      </div>
      <ul className="mt-2 flex flex-col gap-1">
        {s.distinguishing_features.slice(0, 3).map((f) => (
          <li key={f.feature} className="flex items-center gap-2">
            <span className="min-w-0 flex-1 truncate text-[11px] text-dim">{f.feature}</span>
            <span
              className={`font-mono text-[11px] tabular-nums ${
                f.direction === 'high' ? 'text-accent' : 'text-warn'
              }`}
            >
              {f.z_score > 0 ? '+' : ''}
              {f.z_score.toFixed(2)}σ
            </span>
          </li>
        ))}
      </ul>
    </button>
  )
}

/** The transition matrix. Row = current state, column = next state. */
function TransitionMatrix({ transitions, selected, onSelect }: {
  transitions: number[][]
  selected: number | null
  onSelect: (i: number) => void
}) {
  const n = transitions.length
  const peak = useMemo(
    () => Math.max(...transitions.flat().filter((v) => Number.isFinite(v)), 0.01),
    [transitions],
  )
  return (
    <div className="overflow-x-auto">
      <div
        className="grid gap-px"
        style={{ gridTemplateColumns: `repeat(${n}, minmax(11px, 1fr))`, minWidth: `${n * 13}px` }}
        role="img"
        aria-label={`Transition probabilities between ${n} latent network states`}
      >
        {transitions.map((row, i) =>
          row.map((v, j) => {
            const on = selected === i
            return (
              <button
                key={`${i}-${j}`}
                type="button"
                onClick={() => onSelect(i)}
                title={`State ${i} → State ${j}: ${(v * 100).toFixed(1)}%`}
                className="aspect-square w-full rounded-[2px] transition-opacity duration-[120ms] hover:opacity-70 focus-visible:outline-1 focus-visible:outline-accent"
                style={{
                  backgroundColor: `color-mix(in srgb, var(--accent) ${Math.min(
                    100,
                    (v / peak) * 100,
                  ).toFixed(0)}%, var(--surface-3))`,
                  outline: on ? '1px solid var(--accent)' : undefined,
                }}
              />
            )
          }),
        )}
      </div>
    </div>
  )
}

export default function WorldModel() {
  const model = useFetch<NetstateModel>(getNetstateModel, [])
  const [selected, setSelected] = useState<number | null>(null)

  if (model.loading && !model.data) {
    return (
      <>
        <PageHeader eyebrow="Engine 3" title="Network world model" />
        <SkeletonRows rows={6} />
      </>
    )
  }
  if (model.error || !model.data) {
    return (
      <>
        <PageHeader eyebrow="Engine 3" title="Network world model" />
        <ErrorState error={model.error ?? new Error('the world model returned nothing')} />
      </>
    )
  }

  const d = model.data
  const m = d.evaluation?.netstate
  const chosen = selected === null ? null : d.states.find((s) => s.state === selected) ?? null

  return (
    <>
      <PageHeader
        eyebrow="Engine 3"
        title="Network world model"
        description={`${d.n_states} latent states over windows of ${d.window} flows, trained on ${d.trained_on}. This engine reasons about the state of the network itself, not about techniques.`}
      />

      {/* The boundary, stated before anything else. */}
      <div className="mb-6 flex items-start gap-2.5 rounded-lg border border-warn/40 bg-warn/5 p-3">
        <TriangleAlert className="mt-0.5 size-4 shrink-0 text-warn" aria-hidden />
        <div className="min-w-0">
          <div className="text-sm font-medium text-text">
            Research surface: this model feeds no alert, score or severity
          </div>
          <p className="mt-0.5 text-xs leading-5 text-dim">
            It was evaluated on next-window prediction. We have no measurement of its
            usefulness as an alert, so it does not produce one — the same rule that keeps
            bare accuracy off our scoreboard. The numbers below are research results on
            CIC-IDS2017, not a claim about the log analysed elsewhere in this product.
          </p>
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-[1.1fr_1fr]">
        <Card>
          <CardHeader>
            <CardTitle>Where a trivial baseline still beats us</CardTitle>
            <CardMeta>next-state top-1 · {m?.n_windows_test?.toLocaleString() ?? '—'} test windows</CardMeta>
          </CardHeader>
          <CardBody>
            <EvaluationStrip comparison={d.comparison} />
            {d.comparison?.summary ? (
              <p className="mt-4 text-xs leading-5 text-dim">{d.comparison.summary}</p>
            ) : null}
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>What it is calibrated to do</CardTitle>
            <CardMeta>measured, on the task it was built for</CardMeta>
          </CardHeader>
          <CardBody>
            <div className="flex flex-col gap-3">
              <div className="flex items-baseline justify-between gap-3 border-b border-border pb-2.5">
                <div className="min-w-0">
                  <div className="text-sm text-text">Brier score, one step</div>
                  <div className="text-xs text-faint">calibration of the next-state distribution</div>
                </div>
                <div className="text-right">
                  <div className="font-mono text-lg tabular-nums text-text">
                    {m?.brier_1step?.toFixed(5) ?? '—'}
                  </div>
                  <div className="font-mono text-[11px] tabular-nums text-faint">
                    baseline {m?.brier_1step_baseline?.toFixed(5) ?? '—'}
                  </div>
                </div>
              </div>
              <div className="flex items-baseline justify-between gap-3 border-b border-border pb-2.5">
                <div className="min-w-0">
                  <div className="text-sm text-text">Next-state top-3</div>
                  <div className="text-xs text-faint">is the true next state in our top three</div>
                </div>
                <div className="font-mono text-lg tabular-nums text-text">
                  {m?.next_state_top3 ? `${(m.next_state_top3 * 100).toFixed(1)}%` : '—'}
                </div>
              </div>
              <div>
                <SectionLabel>Deliberately not wired</SectionLabel>
                <p className="mt-1.5 text-xs leading-5 text-dim">
                  Window compromise separates at ROC-AUC{' '}
                  <span className="font-mono text-text">
                    {m?.compromise_roc_auc?.toFixed(4) ?? '—'}
                  </span>{' '}
                  on this corpus. We still do not raise an alert from it: that number is a
                  property of CIC-IDS2017 labels, and we have not evaluated what it would cost
                  an analyst on their own traffic. Measuring that is the work; asserting it
                  would be the shortcut.
                </p>
              </div>
            </div>
          </CardBody>
        </Card>
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-[1fr_1.1fr]">
        <Card>
          <CardHeader>
            <CardTitle>Transition matrix</CardTitle>
            <CardMeta>row: current state · column: next · brighter is likelier</CardMeta>
          </CardHeader>
          <CardBody>
            <TransitionMatrix
              transitions={d.transitions}
              selected={selected}
              onSelect={setSelected}
            />
            <p className="mt-3 text-xs leading-5 text-dim">
              The bright diagonal is the network staying where it is, and it is why a
              persistence baseline is hard to beat: network traffic is strongly
              autocorrelated. Click a row to inspect that state.
            </p>
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>{chosen ? `State ${chosen.state}` : 'Pick a state'}</CardTitle>
            <CardMeta>
              {chosen
                ? `${chosen.training_windows.toLocaleString()} training windows`
                : 'all 24 are printable'}
            </CardMeta>
          </CardHeader>
          <CardBody>
            {chosen ? (
              <div className="flex flex-col gap-3">
                <div className="flex items-baseline gap-2">
                  <span className="font-mono text-2xl tabular-nums text-text">
                    {(chosen.attack_rate * 100).toFixed(1)}%
                  </span>
                  <span className="text-sm text-dim">
                    of training windows in this state carried an attack
                  </span>
                </div>
                <div>
                  <SectionLabel>What makes this state different</SectionLabel>
                  <div className="mt-2 flex flex-col gap-2">
                    {chosen.distinguishing_features.map((f) => (
                      <div key={f.feature} className="flex items-center gap-3">
                        <span className="min-w-0 flex-1 truncate text-xs text-text">
                          {f.feature}
                        </span>
                        <div className="flex h-1.5 w-24 items-center justify-center">
                          <div className="relative h-1.5 w-full rounded-full bg-surface-3">
                            <div
                              className={`absolute top-0 h-1.5 rounded-full ${
                                f.direction === 'high' ? 'bg-accent left-1/2' : 'bg-warn right-1/2'
                              }`}
                              style={{ width: `${Math.min(50, Math.abs(f.z_score) * 16)}%` }}
                            />
                          </div>
                        </div>
                        <span className="w-16 text-right font-mono text-xs tabular-nums text-dim">
                          {f.z_score > 0 ? '+' : ''}
                          {f.z_score.toFixed(2)}σ
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
                <p className="text-xs leading-5 text-faint">
                  Deviations are in training standard deviations from the mean window, so they
                  are comparable across features.
                </p>
              </div>
            ) : (
              <EmptyState
                title="Select a state from the matrix or the list below"
                detail="Each one prints the features that distinguish it from an average window."
              />
            )}
          </CardBody>
        </Card>
      </div>

      <Card className="mt-4">
        <CardHeader>
          <CardTitle>All {d.n_states} states</CardTitle>
          <CardMeta>
            <Boxes className="mr-1 inline size-3" aria-hidden />
            quantised on purpose — a state can be printed, a black box cannot
          </CardMeta>
        </CardHeader>
        <CardBody>
          <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
            {d.states.map((s) => (
              <StateCard
                key={s.state}
                s={s}
                selected={selected === s.state}
                onSelect={() => setSelected(s.state)}
              />
            ))}
          </div>
        </CardBody>
      </Card>
    </>
  )
}
