/**
 * A second, differently-built analysis of the same log.
 *
 * The workflow governs. This lane answers a question the workflow cannot ask
 * itself: does an analysis built a different way reach the same conclusion?
 * Agreement raises evidence confidence; disagreement lowers it and is shown
 * side by side rather than averaged away. Both lanes are always rendered;
 * neither is ever suppressed.
 *
 * Crucially the two are only PARTIALLY independent - same log, same rule table
 * - so what agreement is worth is capped, and the panel says so.
 */
import { CircleAlert, GitCompareArrows, ScrollText } from 'lucide-react'
import { Card, CardBody, CardHeader, CardMeta, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { EmptyState, SectionLabel, SeverityBadge } from '@/components/primitives'
import { Disclosure, Disclosed, FinePrint } from '@/components/Disclosure'
import type { CrossCheck as CrossCheckData } from '@/types/api'
import { techniqueList } from '@/lib/techniques'

const VERDICT_CLASS: Record<string, string> = {
  corroborates: 'text-ok',
  'partially corroborates': 'text-sev-medium',
  contradicts: 'text-sev-critical',
  inconclusive: 'text-sev-normal',
  'not available': 'text-sev-normal',
}

function Lane({
  label,
  severity,
  basis,
  techniques,
}: {
  label: string
  severity: string | undefined
  basis: string | undefined
  techniques: string[]
}) {
  return (
    <div className="rounded-md border border-border bg-surface-2 p-3">
      <SectionLabel>{label}</SectionLabel>
      <div className="mt-1.5">
        <SeverityBadge severity={severity} />
      </div>
      <p className="mt-1.5 text-xs text-faint">{basis}</p>
      <p className="mt-1.5 text-xs text-dim">
        {techniques.length ? techniqueList(techniques, ' · ') : 'No attacker behavior identified'}
      </p>
    </div>
  )
}

export default function CrossCheck({
  crosscheck,
}: {
  crosscheck: CrossCheckData | null | undefined
}) {
  if (!crosscheck) return null

  if (!crosscheck.available) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Independent cross-check</CardTitle>
          <CardMeta>unavailable</CardMeta>
        </CardHeader>
        <EmptyState
          icon={GitCompareArrows}
          title="The second analysis lane did not produce a result"
          detail={`${
            crosscheck.reason ?? 'No reason was given.'
          } The investigation above is unaffected - the workflow is authoritative and the cross-check is advisory.`}
        />
      </Card>
    )
  }

  const sev = crosscheck.severity
  const tech = crosscheck.techniques
  const independence = crosscheck.partial_independence
  const conflicting = crosscheck.verdict === 'contradicts'

  return (
    <Card>
      <CardHeader>
        <CardTitle>Independent cross-check</CardTitle>
        <CardMeta>
          {crosscheck.verdict}
          {crosscheck.corroboration_strength != null
            ? ` · strength ${crosscheck.corroboration_strength}`
            : ''}
        </CardMeta>
      </CardHeader>
      <CardBody className="space-y-3">
        <div
          className={`flex items-start gap-2 rounded-md border px-3 py-2 text-xs ${
            conflicting
              ? 'border-sev-critical/40 bg-sev-critical/5 text-text'
              : 'border-border bg-surface-2 text-dim'
          }`}
        >
          {conflicting ? (
            <CircleAlert className="mt-0.5 size-3.5 shrink-0 text-sev-critical" aria-hidden />
          ) : (
            <GitCompareArrows className="mt-0.5 size-3.5 shrink-0" aria-hidden />
          )}
          <span>{crosscheck.explanation ?? 'No explanation was returned for this verdict.'}</span>
        </div>

        <div className="grid items-stretch gap-3 lg:grid-cols-[1fr_auto_1fr]">
          <Lane
            label="Workflow (authoritative)"
            severity={sev?.workflow}
            basis={sev?.basis_workflow}
            techniques={tech?.workflow ?? []}
          />
          <div className="flex flex-col items-center justify-center rounded-md border border-border px-4 py-2 text-center">
            <div
              className={`text-sm font-medium ${VERDICT_CLASS[crosscheck.verdict] ?? 'text-dim'}`}
            >
              {crosscheck.verdict}
            </div>
            <div className="mt-0.5 font-mono text-xs text-faint">
              severity {sev?.agreement ?? 'not reported'}
            </div>
          </div>
          <Lane
            label="Agent lane (advisory)"
            severity={sev?.agent_lane}
            basis={sev?.basis_agent_lane}
            techniques={tech?.agent_lane ?? []}
          />
        </div>

        {tech && (tech.workflow_only.length > 0 || tech.agent_lane_only.length > 0) ? (
          <div className="font-mono text-xs">
            {tech.shared.length ? (
              <span className="text-ok">both: {techniqueList(tech.shared, ', ')}</span>
            ) : null}
            {tech.workflow_only.length ? (
              <span className="text-dim"> · workflow only: {techniqueList(tech.workflow_only, ', ')}</span>
            ) : null}
            {tech.agent_lane_only.length ? (
              <span className="text-dim">
                {' '}
                · agent lane only: {techniqueList(tech.agent_lane_only, ', ')}
              </span>
            ) : null}
          </div>
        ) : null}

        {crosscheck.agent_lane_degraded?.length ? (
          <Disclosed>
            <span className="font-medium text-text">Agent lane degraded:</span>{' '}
            {crosscheck.agent_lane_degraded.join(', ')} - its agreement counts for less as a
            result.
          </Disclosed>
        ) : null}

        <Disclosure
          label="Show the agent narrative and why this is only partial independence"
          labelOpen="Hide the agent narrative"
        >
          <div className="space-y-3">
            <div>
              <div className="flex items-center gap-1.5">
                <ScrollText className="size-3 text-faint" aria-hidden />
                <SectionLabel>Agent-lane narrative</SectionLabel>
                <Badge variant="outline">
                  {crosscheck.narrative_method ?? 'method not reported'} · non-authoritative
                </Badge>
              </div>
              <p className="mt-1.5 text-xs leading-relaxed text-dim">
                {crosscheck.narrative || 'No narrative produced.'}
              </p>
            </div>
            {independence ? (
              <FinePrint>
                <span className="font-medium text-text">Partial independence.</span>{' '}
                {independence.note} Shared: {independence.shared_components.join(', ')}.
              </FinePrint>
            ) : null}
          </div>
        </Disclosure>
      </CardBody>
    </Card>
  )
}
