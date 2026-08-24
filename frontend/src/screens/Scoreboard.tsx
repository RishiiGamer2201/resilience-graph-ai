/**
 * PS7 scoreboard — the honesty showcase.
 *
 * Every value is read from reports/metrics.json through /api/scoreboard. The
 * rules this screen exists to enforce:
 *
 *   1. A card we have not measured renders `Not measured` with the reason, in
 *      the grid, in its group, at the same size as everything else. Never a
 *      zero, never hidden, never dropped.
 *   2. Where a card has a baseline, the comparison is shown — INCLUDING the
 *      cards where our number is worse. Two of them are on this board on
 *      purpose. A losing card is styled exactly like a winning one and says
 *      "behind baseline" in words.
 *   3. `note` and `report` carry the qualifications, so both are on the card.
 *   4. The claims we refuse to make are a panel, not a footnote.
 */
import { useState } from 'react'
import { ChevronDown, FileText, TrendingDown, TrendingUp } from 'lucide-react'
import { getScoreboard } from '@/lib/api'
import { useFetch } from '@/hooks/useFetch'
import { PageHeader } from '@/components/Layout'
import { Badge } from '@/components/ui/badge'
import { Card, CardBody, CardHeader, CardMeta, CardTitle } from '@/components/ui/card'
import { SkeletonRows } from '@/components/ui/skeleton'
import {
  EmptyState,
  ErrorState,
  NotMeasured,
  SectionLabel,
} from '@/components/primitives'
import type { ScoreCard, Scoreboard as Board } from '@/types/api'

/** Numbers keep the precision the evaluation wrote, to three decimals. */
function fmt(v: number | null | undefined, unit?: string): string | null {
  if (v == null || !Number.isFinite(v)) return null
  const n = Number.isInteger(v) ? v : Math.round(v * 1000) / 1000
  return `${n.toLocaleString()}${unit ?? ''}`
}

function Comparison({ card }: { card: ScoreCard }) {
  const base = card.baseline
  if (!base) return null

  if (base.value == null || card.value == null) {
    return (
      <div className="mt-2 border-t border-border pt-2 text-xs text-dim">
        <span className="text-faint">vs {base.name}: </span>
        <NotMeasured why="No value for this baseline in reports/metrics.json." />
      </div>
    )
  }

  const ahead = card.higher_is_better
    ? card.value > base.value
    : card.value <= base.value
  const Trend = ahead ? TrendingUp : TrendingDown

  return (
    <div className="mt-2 border-t border-border pt-2">
      <div className="flex flex-wrap items-center gap-1.5">
        {/* We publish the losses. Same weight, same layout, said in words. */}
        <Badge variant={ahead ? 'ok' : 'warn'}>
          <Trend className="size-3" aria-hidden />
          {ahead ? 'ahead of baseline' : 'behind baseline'}
        </Badge>
        {card.delta != null ? (
          <span className="font-mono text-xs text-dim">
            {card.delta > 0 ? '+' : ''}
            {fmt(card.delta, card.unit)}
          </span>
        ) : null}
        {card.lift != null ? (
          <span className="font-mono text-xs text-dim">{card.lift}× baseline</span>
        ) : null}
      </div>
      <div className="mt-1 text-xs text-faint">
        vs {base.name}:{' '}
        <span className="font-mono text-dim">{fmt(base.value, card.unit)}</span>
      </div>
    </div>
  )
}

function BoardCard({ card }: { card: ScoreCard }) {
  const [open, setOpen] = useState(false)
  const measured = card.state === 'measured'
  const value = fmt(card.value, card.unit)

  return (
    <Card className="flex flex-col">
      <CardBody className="flex flex-1 flex-col">
        <div className="text-sm font-medium text-text">{card.name}</div>

        <div className="mt-2 font-mono text-2xl tabular-nums text-text">
          {measured && value != null ? (
            value
          ) : (
            <NotMeasured
              why={card.why ?? 'The evaluation for this metric has not been run.'}
              className="text-sm"
            />
          )}
        </div>

        {/* An unmeasured card explains itself in full, not on hover alone. */}
        {!measured && card.why ? (
          <p className="mt-2 text-xs text-dim">{card.why}</p>
        ) : null}

        {measured ? <Comparison card={card} /> : null}

        {card.note ? (
          <p className="mt-2 border-t border-border pt-2 text-xs text-dim">{card.note}</p>
        ) : null}

        <div className="mt-auto pt-3">
          {card.report ? (
            <div className="flex items-start gap-1.5 text-xs">
              <FileText className="mt-0.5 size-3 shrink-0 text-faint" aria-hidden />
              <span className="font-mono break-all text-faint">{card.report}</span>
              {card.report_exists === false ? (
                <Badge variant="critical">missing on disk</Badge>
              ) : null}
            </div>
          ) : null}

          <button
            type="button"
            onClick={() => setOpen((v) => !v)}
            aria-expanded={open}
            className="mt-2 inline-flex items-center gap-1 text-xs text-accent underline-offset-4 hover:underline"
          >
            <ChevronDown
              className={`size-3 transition-transform duration-[120ms] ${open ? 'rotate-180' : ''}`}
              aria-hidden
            />
            {open ? 'less' : 'definition, dataset, provenance'}
          </button>

          {open ? (
            <div className="mt-2 space-y-1.5 border-t border-border pt-2 text-xs text-dim">
              <p>
                <span className="text-faint">Definition. </span>
                {card.definition}
              </p>
              <p>
                <span className="text-faint">Dataset. </span>
                {card.dataset}
                {card.sample ? ` — ${card.sample}` : ''}
              </p>
              {card.provenance ? (
                <p className="font-mono text-faint">provenance: {card.provenance}</p>
              ) : null}
            </div>
          ) : null}
        </div>
      </CardBody>
    </Card>
  )
}

export default function Scoreboard() {
  const { data, error, loading, reload } = useFetch<Board>(getScoreboard)

  const header = (
    <PageHeader
      eyebrow="PS7 evaluation"
      title="What we measured, against what baseline"
      description="Every figure is read from reports/metrics.json, written by the evaluation scripts. A metric we have not measured says so and explains why."
    />
  )

  if (loading) {
    return (
      <>
        {header}
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {Array.from({ length: 6 }, (_, i) => (
            <Card key={i}>
              <CardBody>
                <SkeletonRows rows={3} />
              </CardBody>
            </Card>
          ))}
        </div>
      </>
    )
  }

  if (error || !data) {
    return (
      <>
        {header}
        <Card>
          <ErrorState error={error ?? new Error('no data')} retry={reload} />
        </Card>
      </>
    )
  }

  const refused = Object.entries(data.refused_claims ?? {})
  const missing = data.summary?.missing_reports ?? []

  return (
    <>
      <PageHeader
        eyebrow="PS7 evaluation"
        title="What we measured, against what baseline"
        description="Every figure is read from reports/metrics.json, written by the evaluation scripts. A metric we have not measured says so and explains why."
        actions={
          <div className="text-right font-mono text-xs text-faint">
            <div>
              {data.summary.measured} measured · {data.summary.not_measured} declared not
              measured
            </div>
            {data.generated_at ? <div>generated {data.generated_at}</div> : null}
          </div>
        }
      />

      {missing.length ? (
        <Card className="mb-4 border-sev-high/40">
          <CardBody className="text-xs text-dim">
            <span className="text-sev-high">Evidence files missing on disk for: </span>
            <span className="font-mono">{missing.join(', ')}</span>
          </CardBody>
        </Card>
      ) : null}

      {data.groups?.length ? (
        data.groups.map((g) => (
          <section key={g.name} className="mb-6">
            <SectionLabel className="mb-2">{g.name}</SectionLabel>
            <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
              {g.cards.map((c) => (
                <BoardCard key={c.id} card={c} />
              ))}
            </div>
          </section>
        ))
      ) : (
        <Card>
          <EmptyState
            title="The scoreboard is empty"
            detail="No cards came back from /api/scoreboard. Run the evaluation scripts to write reports/metrics.json."
          />
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Claims we refuse to make</CardTitle>
          <CardMeta>{refused.length} and why</CardMeta>
        </CardHeader>
        <CardBody>
          {refused.length ? (
            <ul className="space-y-2">
              {refused.map(([claim, why]) => (
                <li key={claim} className="flex flex-col gap-0.5 sm:flex-row sm:gap-3">
                  <span className="shrink-0 font-mono text-sm text-text sm:w-48">
                    {claim}
                  </span>
                  <span className="text-xs text-dim">{why}</span>
                </li>
              ))}
            </ul>
          ) : (
            <EmptyState
              title="No refused claims returned"
              detail="The backend publishes the list it refuses to claim; this response carried none."
            />
          )}

          {data.note ? (
            <p className="mt-4 border-t border-border pt-3 text-xs text-faint">
              {data.note}
              {data.sources?.regenerate?.length ? (
                <>
                  {' '}
                  Regenerate with{' '}
                  {data.sources.regenerate.map((cmd, i) => (
                    <span key={cmd}>
                      {i > 0 ? ' and ' : ''}
                      <code className="rounded-md bg-surface-2 px-1 py-0.5 font-mono text-text">
                        {cmd}
                      </code>
                    </span>
                  ))}
                  .
                </>
              ) : null}
            </p>
          ) : null}
        </CardBody>
      </Card>
    </>
  )
}
