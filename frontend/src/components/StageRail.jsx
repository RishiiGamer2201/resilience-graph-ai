import { Check, CircleDashed, Loader, TriangleAlert, X } from 'lucide-react'

// The seven-node investigation, as a rail. One node = one bounded step, with the
// status and the wall time the backend actually measured — not a fake progress
// bar. `replan` may re-run `evidence` once; the rail shows that as a retry count
// rather than pretending the graph is strictly linear.
const STAGES = [
  { node: 'understand', label: 'Understand', hint: 'validate, scope, name what is missing' },
  { node: 'plan', label: 'Plan', hint: 'choose only the tools this case needs' },
  { node: 'evidence', label: 'Evidence', hint: 'cite official MITRE / CISA / CERT-In' },
  { node: 'signals', label: 'Signals', hint: 'score, correlate, map, graph, predict' },
  { node: 'replan', label: 'Replan', hint: 'one bounded retry on an evidence gap' },
  { node: 'impact', label: 'Impact', hint: 'reachability, exposure, counterfactual' },
  { node: 'action', label: 'Action', hint: 'gated proposals + what we still need' },
]

const ICONS = {
  ok: Check, degraded: TriangleAlert, failed: X, skipped: CircleDashed,
  running: Loader, pending: CircleDashed,
}

export default function StageRail({ trace, running, onJump, active }) {
  const runs = trace?.nodes || []
  const byNode = {}
  runs.forEach((r) => {
    byNode[r.node] = byNode[r.node]
      ? { ...r, ms: byNode[r.node].ms + r.ms, retries: (byNode[r.node].retries || 0) + 1 }
      : r
  })
  const doneCount = Object.keys(byNode).length

  return (
    <ol className="rail-stages" aria-label="Investigation stages">
      {STAGES.map((s, i) => {
        const r = byNode[s.node]
        const state = r ? r.status : (running && doneCount === i ? 'running' : 'pending')
        const Icon = ICONS[state] || CircleDashed
        return (
          <li key={s.node}>
            <button
              type="button"
              className={`stage st-${state}${active === s.node ? ' active' : ''}`}
              onClick={() => onJump?.(s.node)}
              disabled={!r}
              aria-current={active === s.node ? 'step' : undefined}
              title={r ? `${r.status} · ${r.ms} ms — ${r.summary}` : s.hint}
            >
              <span className="n">{i + 1}</span>
              <span className="body">
                <span className="lbl">
                  {s.label}
                  <Icon size={13} aria-hidden="true" className={state === 'running' ? 'spin' : ''} />
                </span>
                <span className="sub">
                  {r ? `${Math.round(r.ms)} ms${r.retries ? ` · ${r.retries + 1}×` : ''}` : s.hint}
                </span>
              </span>
            </button>
          </li>
        )
      })}
      {trace && (
        <li className="stage-total mono">
          total {Math.round(trace.total_ms)} ms · {trace.bounded_by}
          {trace.degraded?.length > 0 && (
            <span className="s-high"> · degraded: {trace.degraded.join(', ')}</span>
          )}
        </li>
      )}
    </ol>
  )
}
