/**
 * "Why did you flag this one line?" — the whole computation, read back, for a
 * single alert.
 *
 * Each stage names the module that produced it and the value it produced, so an
 * analyst can disagree with a step rather than with "the AI".
 */
import { Microscope } from 'lucide-react'
import { Card, CardBody, CardHeader, CardMeta, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { SkeletonRows } from '@/components/ui/skeleton'
import { EmptyState, ErrorState, SectionLabel } from '@/components/primitives'
import { FinePrint } from '@/components/Disclosure'
import { useFetch } from '@/hooks/useFetch'
import { explainStep } from '@/lib/api'
import * as React from 'react'
import type { ExplainTraceResult } from '@/types/api'

export default function ExplainTrace({
  scenario,
  criticalAssets,
}: {
  scenario: string
  criticalAssets: string[]
}) {
  const [idx, setIdx] = React.useState(0)
  const key = criticalAssets.join(',')
  const fetcher = React.useCallback(
    () =>
      explainStep({
        scenario,
        critical_assets: criticalAssets,
        step_index: idx,
      }),
    // criticalAssets is a fresh array each render; `key` is its stable identity.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [scenario, key, idx],
  )
  const { data: trace, error, loading, reload } = useFetch<ExplainTraceResult>(fetcher, [fetcher])

  if (loading && !trace) {
    return (
      <Card>
        <CardBody>
          <SkeletonRows rows={4} />
        </CardBody>
      </Card>
    )
  }

  if (error || !trace) {
    return (
      <Card>
        <ErrorState error={error ?? new Error('no trace returned')} retry={reload} />
      </Card>
    )
  }

  if (!trace.available) {
    return (
      <Card>
        <EmptyState
          icon={Microscope}
          title="No explainability trace for this run"
          detail={trace.reason ?? 'The backend gave no reason.'}
        />
      </Card>
    )
  }

  const step = trace.step

  return (
    <Card>
      <CardHeader className="flex-wrap">
        <div className="flex min-w-0 items-baseline gap-3">
          <CardTitle>Explainability trace</CardTitle>
          <CardMeta>
            alert {idx + 1} of {trace.alerts_available}
          </CardMeta>
        </div>
        <div className="flex items-center gap-1.5">
          <Button
            size="sm"
            variant="outline"
            disabled={idx === 0 || loading}
            onClick={() => setIdx((i) => Math.max(0, i - 1))}
          >
            Previous
          </Button>
          <Button
            size="sm"
            variant="outline"
            disabled={idx + 1 >= trace.alerts_available || loading}
            onClick={() => setIdx((i) => i + 1)}
          >
            Next alert
          </Button>
        </div>
      </CardHeader>
      <CardBody className="space-y-3">
        <div className="flex items-start gap-2 rounded-md border border-border bg-surface-2 px-3 py-2 font-mono text-xs text-dim">
          <Microscope className="mt-0.5 size-3.5 shrink-0" aria-hidden />
          <span>
            {step.user} · {step.source_host} → {step.destination_host} · score{' '}
            {step.anomaly_score} · {step.technique_id}
          </span>
        </div>

        <ol className="space-y-2">
          {trace.stages.map((s) => (
            <li key={s.stage} className="rounded-md border border-border bg-surface-2 p-3">
              <div className="flex flex-wrap items-baseline justify-between gap-2">
                <SectionLabel>{s.stage}</SectionLabel>
                <span className="font-mono text-xs text-faint">{s.produced_by}</span>
              </div>
              <pre className="mt-1.5 overflow-x-auto rounded-md border border-border bg-surface px-2 py-1.5 font-mono text-xs text-dim">
                {JSON.stringify(s.value, null, 1)}
              </pre>
              <p className="mt-1.5 text-xs text-dim">{s.explanation}</p>
            </li>
          ))}
        </ol>

        <FinePrint>{trace.note}</FinePrint>
      </CardBody>
    </Card>
  )
}
