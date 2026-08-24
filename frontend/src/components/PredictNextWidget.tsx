/**
 * Next-technique ranking from the shipped interpolated Markov model.
 *
 * Ported from PredictNextWidget.jsx. Two things from the old widget are gone
 * on purpose:
 *
 *   - It seeded itself with a hardcoded chain (T1566.001, T1204.002) and
 *     offered four hardcoded "quick add" techniques. Neither was observed in
 *     anything. The chain now starts as the techniques the incident actually
 *     mapped, passed in by the screen.
 *   - It read `result.live`, a field the endpoint does not return, so the badge
 *     always said "cached". The endpoint returns `source`, which distinguishes
 *     an order-2 transition from a bare frequency fallback - a far more useful
 *     admission, so that is what is shown.
 *
 * Everything here is `predicted`, never observed, and says so.
 */
import * as React from 'react'
import { Plus, X } from 'lucide-react'
import { predictNext } from '@/lib/api'
import { useFetch } from '@/hooks/useFetch'
import { Button } from '@/components/ui/button'
import { CardBody } from '@/components/ui/card'
import { SkeletonRows } from '@/components/ui/skeleton'
import {
  ClaimStatus,
  EmptyState,
  ErrorState,
  NotMeasured,
  ProvenanceLine,
  SectionLabel,
} from '@/components/primitives'
import type { PredictNextResult } from '@/types/api'
import { techniqueName } from '@/lib/techniques'

/** What the model call actually produced. Mounted only with a non-empty chain,
 *  so the endpoint is never asked to guess from nothing. */
function Ranking({ chain }: { chain: string[] }) {
  const key = chain.join(',')
  const { data, error, loading, reload } = useFetch<PredictNextResult>(
    () => predictNext(chain),
    [key],
  )

  if (loading) return <SkeletonRows rows={3} />
  if (error || !data) return <ErrorState error={error ?? new Error('no data')} retry={reload} />

  if (!data.predictions.length) {
    return (
      <EmptyState
        title="The model projects no next move"
        detail="The observed sequence does not match any transition the model learned."
      />
    )
  }

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <SectionLabel>Predicted next techniques</SectionLabel>
        <ClaimStatus status="predicted" />
        <span className="font-mono text-xs text-faint">{data.source ?? 'source unreported'}</span>
      </div>

      <div className="divide-y divide-border rounded-md border border-border">
        {data.predictions.map((p) => (
          <div key={p.technique_id} className="flex items-baseline gap-3 px-3 py-1.5">
            <span className="w-4 shrink-0 font-mono text-xs text-faint">{p.rank}</span>
            <span className="min-w-0 flex-1 truncate text-sm text-text">{techniqueName(p.technique_id, p.name)}</span>
            <span className="shrink-0 font-mono text-xs tabular-nums text-text">
              {typeof p.score === 'number' ? (
                `${(p.score * 100).toFixed(1)}%`
              ) : (
                <NotMeasured why="The endpoint returned no transition probability for this candidate." />
              )}
            </span>
          </div>
        ))}
      </div>
      <p className="text-xs text-faint">
        Probabilities are interpolated Markov transition probabilities, not a
        statement about this attacker.
      </p>

      {data.projection_narrative ? (
        <div className="rounded-md border border-border bg-surface-2 p-3">
          <p className="whitespace-pre-wrap text-sm leading-relaxed text-text">
            {data.projection_narrative}
          </p>
          <ProvenanceLine method="template" className="mt-2" />
        </div>
      ) : null}
    </div>
  )
}

export default function PredictNextWidget({ given }: { given: string[] }) {
  const [chain, setChain] = React.useState<string[]>(given)
  const [draft, setDraft] = React.useState('')

  // The screen's observed chain is the seed; re-seed if the incident changes.
  React.useEffect(() => setChain(given), [given])

  const add = (id: string) => {
    const v = id.trim().toUpperCase()
    if (v && !chain.includes(v)) setChain((c) => [...c, v])
    setDraft('')
  }

  return (
    <CardBody className="space-y-3">
      <SectionLabel>Chain sent to the model</SectionLabel>
      <div className="flex flex-wrap items-center gap-1.5">
        {chain.map((id) => (
          <span
            key={id}
            className="inline-flex items-center gap-1 rounded-md border border-border bg-surface-2 px-2 py-0.5 font-mono text-xs text-text"
          >
            {id}
            <button
              type="button"
              onClick={() => setChain((c) => c.filter((x) => x !== id))}
              aria-label={`Remove ${id} from the chain`}
              className="text-faint hover:text-text"
            >
              <X className="size-3" />
            </button>
          </span>
        ))}

        <form
          className="flex items-center gap-1"
          onSubmit={(e) => {
            e.preventDefault()
            add(draft)
          }}
        >
          <input
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            placeholder="add a technique id"
            aria-label="Add a technique id to the chain"
            className="h-7 w-40 rounded-md border border-border bg-surface-2 px-2 font-mono text-xs text-text placeholder:text-faint"
          />
          <Button type="submit" size="sm" variant="secondary" aria-label="Add technique">
            <Plus className="size-3" />
          </Button>
        </form>
      </div>

      {chain.length ? (
        <Ranking chain={chain} />
      ) : (
        <EmptyState
          title="No technique chain to project from"
          detail={
            given.length
              ? 'Every technique was removed. Add one back to ask the model again.'
              : 'This incident mapped no ATT&CK techniques, so there is no observed sequence to continue.'
          }
        />
      )}
    </CardBody>
  )
}
