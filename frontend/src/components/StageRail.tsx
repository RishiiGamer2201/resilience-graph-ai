/**
 * The seven-node investigation, as a rail.
 *
 * One node = one bounded step, carrying the status and the wall time the
 * backend actually measured. This is not a fake progress bar: a stage is
 * `pending` until the server reports it, and `replan` may re-run `evidence`
 * once, which shows as a retry count rather than being smoothed into a line.
 *
 * The moving accent underline is the one animation here, and it exists because
 * a stage advancing is a state change. Reduced motion drops it.
 */
import { Check, CircleDashed, TriangleAlert, X } from 'lucide-react'
import { motion, useReducedMotion } from 'motion/react'
import { cn } from '@/lib/utils'
import { spring } from '@/lib/motion'
import type { InvestigationResult, TraceNode } from '@/types/api'

const STAGES = [
  { node: 'understand', label: 'Understand', hint: 'validate, scope, name what is missing' },
  { node: 'plan', label: 'Plan', hint: 'choose only the tools this case needs' },
  { node: 'evidence', label: 'Evidence', hint: 'cite official MITRE / CISA / CERT-In' },
  { node: 'signals', label: 'Signals', hint: 'score, correlate, map, graph, predict' },
  { node: 'replan', label: 'Replan', hint: 'one bounded retry on an evidence gap' },
  { node: 'impact', label: 'Impact', hint: 'reachability, exposure, counterfactual' },
  { node: 'action', label: 'Action', hint: 'gated proposals + what we still need' },
] as const

type StageState = TraceNode['status'] | 'running' | 'pending'

const ICONS: Record<string, React.ComponentType<{ className?: string }>> = {
  ok: Check,
  degraded: TriangleAlert,
  failed: X,
  skipped: CircleDashed,
  running: CircleDashed,
  pending: CircleDashed,
}

const STATE_CLASS: Record<string, string> = {
  ok: 'text-text',
  degraded: 'text-sev-medium',
  failed: 'text-sev-critical',
  skipped: 'text-faint',
  running: 'text-accent',
  pending: 'text-faint',
}

/** A node that ran more than once (replan retried it) is merged, keeping the
 *  total time and the number of passes rather than showing only the last. */
function merge(nodes: TraceNode[]): Record<string, TraceNode & { passes: number }> {
  const by: Record<string, TraceNode & { passes: number }> = {}
  for (const r of nodes) {
    const prev = by[r.node]
    by[r.node] = prev
      ? { ...r, ms: prev.ms + r.ms, passes: prev.passes + 1 }
      : { ...r, passes: 1 }
  }
  return by
}

export default function StageRail({
  trace,
  running,
  onJump,
  active,
}: {
  trace: InvestigationResult['trace'] | null | undefined
  running: boolean
  onJump?: (node: string) => void
  active?: string | null
}) {
  const reduced = useReducedMotion()
  const byNode = merge(trace?.nodes ?? [])
  const done = Object.keys(byNode).length

  return (
    <div className="overflow-hidden rounded-lg border border-border bg-surface">
      <ol
        className="grid grid-cols-2 gap-px bg-border sm:grid-cols-4 lg:block lg:bg-transparent"
        aria-label="Investigation stages"
      >
        {STAGES.map((s, i) => {
          const r = byNode[s.node]
          const state: StageState = r ? r.status : running && done === i ? 'running' : 'pending'
          const Icon = ICONS[state] ?? CircleDashed
          const isActive = active === s.node
          return (
            <li key={s.node} className="bg-surface lg:border-b lg:border-border lg:last:border-b-0">
              <button
                type="button"
                onClick={() => onJump?.(s.node)}
                disabled={!r}
                aria-current={isActive ? 'step' : undefined}
                title={r ? `${r.status} · ${Math.round(r.ms)} ms - ${r.summary}` : s.hint}
                className={cn(
                  'relative flex w-full items-start gap-2 px-3 py-2.5 text-left lg:py-3',
                  'transition-colors duration-[120ms]',
                  r ? 'hover:bg-surface-2' : 'cursor-default',
                )}
              >
                <span className="mt-px font-mono text-xs text-faint tabular-nums">{i + 1}</span>
                <span className="min-w-0 flex-1">
                  <span
                    className={cn(
                      'flex items-center gap-1.5 text-xs font-medium',
                      STATE_CLASS[state] ?? 'text-faint',
                    )}
                  >
                    {s.label}
                    <Icon className="size-3" aria-hidden />
                  </span>
                  <span className="mt-0.5 block truncate font-mono text-[10px] text-faint lg:whitespace-normal">
                    {r
                      ? `${Math.round(r.ms)} ms${r.passes > 1 ? ` · ${r.passes}×` : ''}`
                      : state === 'running'
                        ? 'running'
                        : s.hint}
                  </span>
                </span>
                {isActive && !reduced ? (
                  <motion.span
                    layoutId="stage-rail-active"
                    transition={spring}
                    className="absolute inset-x-0 bottom-0 h-0.5 bg-accent lg:inset-y-0 lg:left-0 lg:right-auto lg:h-auto lg:w-0.5"
                  />
                ) : null}
                {isActive && reduced ? (
                  <span className="absolute inset-x-0 bottom-0 h-0.5 bg-accent lg:inset-y-0 lg:left-0 lg:right-auto lg:h-auto lg:w-0.5" />
                ) : null}
              </button>
            </li>
          )
        })}
      </ol>
      {trace ? (
        <div className="flex flex-wrap items-center gap-x-2 border-t border-border px-3 py-1.5 font-mono text-xs text-faint">
          <span>total {Math.round(trace.total_ms)} ms</span>
          <span aria-hidden>·</span>
          <span>{trace.bounded_by}</span>
          {trace.degraded.length ? (
            <>
              <span aria-hidden>·</span>
              <span className="text-sev-high">degraded: {trace.degraded.join(', ')}</span>
            </>
          ) : null}
        </div>
      ) : null}
    </div>
  )
}
