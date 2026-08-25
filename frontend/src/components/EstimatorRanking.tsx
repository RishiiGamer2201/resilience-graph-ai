/**
 * Engine 3's estimators, ranked.
 *
 * Two screens show this comparison, the world model page and the performance
 * page, and they must never disagree about which estimator won. So neither of
 * them decides: the server ranks the rows and sets `beaten_by_baseline`, this
 * component renders them in the order it was given, and both screens render
 * this component.
 *
 * The one judgement made here is which colour a role gets. A row our own model
 * lost is drawn in the warning tone, and that follows the server's flag rather
 * than a hardcoded row index, so it moves when the evaluation moves.
 */
import { EmptyState } from '@/components/primitives'
import type { NetstateComparison } from '@/types/api'

const ROLE_TONE: Record<string, string> = {
  baseline: 'bg-faint',
  ours: 'bg-accent',
  ceiling: 'bg-faint/40',
}

export function EstimatorRanking({
  comparison,
  labelWidth = '11rem',
}: {
  comparison: NetstateComparison | undefined
  /** The label column. Narrower where the card is narrower. */
  labelWidth?: string
}) {
  const rows = comparison?.rows ?? []
  if (!rows.length) {
    return <EmptyState title="The evaluation has not been run for this artifact" />
  }
  const max = Math.max(...rows.map((r) => r.value), 0.5)

  return (
    <div className="flex flex-col gap-2.5">
      {rows.map((r) => (
        <div
          key={r.key}
          className="grid items-center gap-3"
          style={{ gridTemplateColumns: `minmax(0,${labelWidth}) 1fr auto` }}
        >
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

export default EstimatorRanking
