/**
 * The two numbers a responder acts on, each with its arithmetic one click away.
 *
 * They are deliberately two, not one. Likelihood says how far along an
 * intrusion looks; exposure says how close the attacker is to the assets that
 * matter. Beneath them sits the four-axis assessment, because collapsing
 * likelihood, impact and evidence quality into a single figure is exactly what
 * this product refuses to do.
 *
 * A metric with no value renders the words "Not measured" and the backend's own
 * reason. It never renders 0, and it never renders a figure nobody can
 * reproduce.
 */
import { Card, CardBody } from '@/components/ui/card'
import { NotMeasured, SectionLabel, SeveritySpine } from '@/components/primitives'
import { Disclosure, FinePrint } from '@/components/Disclosure'
import { Table, TBody, TD, TDMono, TR } from '@/components/ui/table'
import type { ExplainedMetric, InvestigationResult, MetricTerm } from '@/types/api'

/** Bands are the same thresholds the backend uses to word its own summary. */
const band = (v: number | null | undefined): string =>
  v == null ? 'normal' : v >= 80 ? 'critical' : v >= 60 ? 'high' : v >= 35 ? 'medium' : 'low'

/** Terms arrive in two shapes: weighted (`name`) and per-asset (`asset`). */
function termCells(t: MetricTerm): { key: string; figure: string; detail: string } {
  const key = t.name ?? t.asset ?? ''
  const figure = [
    t.weight !== undefined ? `×${t.weight}` : '',
    t.value !== undefined ? `${t.value}` : '',
    t.score !== undefined ? `${t.score}` : '',
    t.hops != null ? `${t.hops} hop${t.hops === 1 ? '' : 's'}` : '',
  ]
    .filter(Boolean)
    .join(' ')
  return { key, figure, detail: t.detail ?? t.why ?? '' }
}

export function HeadlineMetric({
  title,
  metric,
  caption,
}: {
  title: string
  metric: ExplainedMetric | null | undefined
  caption: string
}) {
  const measured = metric != null && metric.value != null
  const terms = metric?.terms ?? []
  const unit = metric?.unit === '0-100' ? '/ 100' : metric?.unit

  return (
    <Card className="relative">
      <SeveritySpine severity={measured ? band(metric?.value) : 'normal'} />
      <CardBody>
        <SectionLabel>{title}</SectionLabel>
        <div className="mt-1.5 flex items-baseline gap-1.5">
          {measured ? (
            <>
              <span className="font-mono text-2xl tabular-nums text-text">{metric?.value}</span>
              {unit ? <span className="text-sm text-dim">{unit}</span> : null}
            </>
          ) : (
            <NotMeasured why={metric?.reason ?? metric?.why ?? metric?.note} />
          )}
        </div>
        <p className="mt-1 text-xs text-dim">
          {measured ? caption : (metric?.reason ?? 'The backend gave no reason for this.')}
        </p>

        {measured ? (
          <Disclosure
            className="mt-3"
            label="Show the arithmetic"
            labelOpen="Hide the arithmetic"
          >
            <code className="block break-words rounded-md border border-border bg-surface-2 px-2 py-1.5 font-mono text-xs text-dim">
              {metric?.formula ?? 'no formula was reported with this figure'}
            </code>
            {terms.length ? (
              <Table className="mt-2">
                <TBody>
                  {terms.map((t, i) => {
                    const { key, figure, detail } = termCells(t)
                    return (
                      <TR key={`${key}-${i}`}>
                        <TDMono className="whitespace-nowrap text-text">{key}</TDMono>
                        <TDMono className="whitespace-nowrap text-dim">{figure}</TDMono>
                        <TD className="text-xs text-faint">{detail}</TD>
                      </TR>
                    )
                  })}
                </TBody>
              </Table>
            ) : (
              <FinePrint className="mt-2">
                No per-term breakdown was returned for this figure.
              </FinePrint>
            )}
            {metric?.note ? <FinePrint className="mt-2">{metric.note}</FinePrint> : null}
          </Disclosure>
        ) : null}
      </CardBody>
    </Card>
  )
}

export default function Headline({
  headline,
}: {
  headline: InvestigationResult['headline']
}) {
  return (
    <div className="grid gap-4 sm:grid-cols-2">
      <HeadlineMetric
        title="Attack progression likelihood"
        metric={headline?.attack_progression_likelihood}
        caption="How far along a real intrusion looks, from this log alone. Not a probability that an attack occurred."
      />
      <HeadlineMetric
        title="Crown-jewel exposure"
        metric={headline?.crown_jewel_exposure}
        caption="How exposed the designated crown jewels are right now, by hop distance from an attacker pivot."
      />
    </div>
  )
}
