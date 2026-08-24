/**
 * Data & methodology - which datasets feed which engine, and the list of
 * things we say plainly about our own numbers.
 *
 * The honesty notes are the point of this screen. They come from the backend
 * verbatim and are not summarised, truncated or reordered here: a caveat that
 * has been tidied into a shorter sentence is no longer the caveat.
 */
import { CheckCircle2, Database } from 'lucide-react'
import { getMethodology } from '@/lib/api'
import { useFetch } from '@/hooks/useFetch'
import { PageHeader } from '@/components/Layout'
import { Card, CardBody, CardHeader, CardMeta, CardTitle } from '@/components/ui/card'
import { SkeletonRows } from '@/components/ui/skeleton'
import {
  EmptyState,
  ErrorState,
  RevealList,
  SectionLabel,
} from '@/components/primitives'
import type { MethodologyPayload } from '@/types/api'

export default function Methodology() {
  const { data, error, loading, reload } = useFetch<MethodologyPayload>(getMethodology)

  const header = (
    <PageHeader
      eyebrow="How results were made"
      title="Data, method, and limitations"
      description="Review data sources, calculations, baselines, and limits."
    />
  )

  if (loading) {
    return (
      <>
        {header}
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {Array.from({ length: 3 }, (_, i) => (
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

  const datasets = data.datasets ?? []
  const notes = data.honesty_notes ?? []

  return (
    <>
      {header}

      <SectionLabel className="mb-2">Datasets</SectionLabel>
      {datasets.length ? (
        <RevealList className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {datasets.map((d) => (
            <Card key={d.name} className="h-full">
              <CardBody>
                <div className="text-sm font-medium text-text">{d.name}</div>
                <div className="mt-1 font-mono text-xs text-dim">{d.rows}</div>
                <div className="mt-2 border-t border-border pt-2 text-xs text-faint">
                  feeds: {d.feeds}
                </div>
              </CardBody>
            </Card>
          ))}
        </RevealList>
      ) : (
        <Card>
          <EmptyState
            title="No datasets returned"
            detail="/api/methodology carried no dataset list. Rebuild the API cache to populate it."
            icon={Database}
          />
        </Card>
      )}

      <Card className="mt-6">
        <CardHeader>
          <CardTitle>Our rigor</CardTitle>
          <CardMeta>
            {notes.length} honesty note{notes.length === 1 ? '' : 's'}
          </CardMeta>
        </CardHeader>
        <CardBody>
          {notes.length ? (
            <ul className="space-y-2">
              {notes.map((n) => (
                <li key={n} className="flex gap-2">
                  <CheckCircle2 className="mt-0.5 size-3.5 shrink-0 text-ok" aria-hidden />
                  <span className="text-sm text-dim">{n}</span>
                </li>
              ))}
            </ul>
          ) : (
            <EmptyState
              title="No honesty notes returned"
              detail="This payload carried no notes. That is a gap in the cache, not a claim that there are no caveats."
            />
          )}
        </CardBody>
      </Card>
    </>
  )
}
