/**
 * Four numbers, deliberately not collapsed into one - and the claims table that
 * says what we actually assert.
 *
 * A single "87% attack score" hides which of the four is weak. Anomaly says the
 * behaviour is unusual; likelihood says an intrusion looks under way; impact
 * says what it costs if that is right; confidence says how good the evidence
 * is. They routinely disagree, and the disagreement is the useful part.
 *
 * ClaimsPanel keeps the gap between "unusual" and "adversary" visible: an
 * anomaly establishes that behaviour is unlike its baseline, a technique
 * additionally asserts adversary behaviour, and a claim with only the detector
 * behind it stays a candidate.
 */
import { Card, CardBody, CardHeader, CardMeta, CardTitle } from '@/components/ui/card'
import { Table, TBody, TD, TDMono, TH, THead, TR } from '@/components/ui/table'
import { InfoTip } from '@/components/ui/tooltip'
import { HelpCircle } from 'lucide-react'
import {
  ClaimStatus,
  EmptyState,
  NotMeasured,
  SectionLabel,
} from '@/components/primitives'
import { Disclosure, FinePrint } from '@/components/Disclosure'
import type {
  AssessmentAxis,
  ExplainedMetric,
  InvestigationClaim,
  WorkflowAssessment,
} from '@/types/api'

const AXES = [
  { key: 'anomaly', label: 'Anomaly', hint: 'how unlike its own baseline the behaviour is' },
  { key: 'likelihood', label: 'Likelihood', hint: 'how probable a malicious path is' },
  { key: 'impact', label: 'Impact', hint: 'what it costs if the hypothesis is right' },
  {
    key: 'confidence',
    label: 'Evidence confidence',
    hint: 'how good the supporting evidence is',
  },
] as const

/** Bands are words as well as colour: colour is never the sole carrier. */
const BAND_CLASS: Record<string, string> = {
  critical: 'text-sev-critical',
  high: 'text-sev-high',
  moderate: 'text-sev-medium',
  low: 'text-sev-low',
  'very low': 'text-sev-normal',
  'not measured': 'text-faint',
}

function Axis({ label, hint, axis }: { label: string; hint: string; axis: AssessmentAxis }) {
  return (
    <div className="rounded-md border border-border bg-surface-2 p-3">
      <div className="flex items-center gap-1">
        <SectionLabel>{label}</SectionLabel>
        <InfoTip label={axis.question || hint}>
          <HelpCircle className="size-3" />
        </InfoTip>
      </div>
      <div className="mt-1 font-mono text-lg tabular-nums text-text">
        {axis.value != null ? axis.value : <NotMeasured why={axis.question} />}
      </div>
      <div className={`text-xs ${BAND_CLASS[axis.band] ?? 'text-dim'}`}>{axis.band}</div>
    </div>
  )
}

export default function Assessment({
  assessment,
  likelihood,
  confidence,
}: {
  assessment: WorkflowAssessment | null | undefined
  likelihood: ExplainedMetric | null | undefined
  confidence: ExplainedMetric | null | undefined
}) {
  if (!assessment) return null
  const formulas: Array<[string, ExplainedMetric | null | undefined]> = [
    ['likelihood', likelihood],
    ['evidence confidence', confidence],
  ]

  return (
    <Card>
      <CardHeader>
        <CardTitle>Assessment</CardTitle>
        <CardMeta>four axes, reported separately</CardMeta>
      </CardHeader>
      <CardBody className="space-y-3">
        <p className="text-sm text-text">{assessment.summary}</p>

        <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
          {AXES.map(({ key, label, hint }) => (
            <Axis key={key} label={label} hint={hint} axis={assessment[key]} />
          ))}
        </div>

        {assessment.missing_evidence.length ? (
          <div className="rounded-md border border-warn/30 bg-warn/5 px-3 py-2 text-xs text-dim">
            <span className="font-medium text-text">Still missing: </span>
            {assessment.missing_evidence.slice(0, 3).join(' · ')}
            {assessment.missing_evidence.length > 3
              ? ` · +${assessment.missing_evidence.length - 3} more`
              : ''}
          </div>
        ) : null}

        <Disclosure label="Show the arithmetic" labelOpen="Hide the arithmetic">
          <div className="space-y-3">
            {formulas.map(([name, m]) =>
              m ? (
                <div key={name}>
                  <SectionLabel>{name}</SectionLabel>
                  <code className="mt-1 block break-words rounded-md border border-border bg-surface-2 px-2 py-1.5 font-mono text-xs text-dim">
                    {m.formula ?? 'no formula was reported with this figure'}
                  </code>
                  {m.terms?.length ? (
                    <Table className="mt-1">
                      <TBody>
                        {m.terms.map((t, i) => (
                          <TR key={`${t.name ?? t.asset ?? i}`}>
                            <TDMono className="whitespace-nowrap text-text">
                              {t.name ?? t.asset}
                            </TDMono>
                            <TDMono className="whitespace-nowrap text-dim">
                              {t.weight !== undefined ? `×${t.weight}` : ''} {t.value ?? t.score}
                            </TDMono>
                            <TD className="text-xs text-faint">{t.detail ?? t.why}</TD>
                          </TR>
                        ))}
                      </TBody>
                    </Table>
                  ) : null}
                </div>
              ) : null,
            )}
            <FinePrint>{assessment.note}</FinePrint>
          </div>
        </Disclosure>
      </CardBody>
    </Card>
  )
}

// ───────────────────────────────────────────────────────────────────────────
/** What we actually claim about each ATT&CK technique, and what would settle
 *  it. Status is always visible; an inferred claim never looks observed. */
export function ClaimsPanel({ claims }: { claims: InvestigationClaim[] | undefined }) {
  if (!claims?.length) {
    return (
      <EmptyState
        title="No ATT&CK claim was raised"
        detail="A claim is only raised where a rule matched an alerting event. Nothing is asserted to fill the table."
      />
    )
  }
  const actionable = claims.filter((c) => c.actionable).length

  return (
    <div>
      <p className="px-4 pb-3 text-xs text-dim">
        {claims.length} ATT&amp;CK claim{claims.length === 1 ? '' : 's'} ·{' '}
        <span className="font-medium text-text">{actionable} actionable</span> (observed or
        confirmed). An anomaly establishes that behaviour is unusual; a technique
        additionally asserts adversary behaviour. Claims with only the detector behind
        them stay candidates.
      </p>
      <Table>
        <THead>
          <TR>
            <TH>Technique</TH>
            <TH>Status</TH>
            <TH className="text-right">Confidence</TH>
            <TH className="text-right">Independent sources</TH>
            <TH>Act on it?</TH>
            <TH>Basis, gaps and alternatives</TH>
          </TR>
        </THead>
        <TBody>
          {claims.map((c) => (
            <TR key={c.external_id}>
              <TDMono>
                <span className="text-text">{c.external_id}</span>
                <span className="ml-2 font-sans text-dim">{c.object}</span>
              </TDMono>
              <TD>
                <ClaimStatus status={c.status} />
              </TD>
              <TDMono className="whitespace-nowrap text-right">
                {c.confidence}
                <span className="ml-1 text-faint">{c.confidence_band}</span>
              </TDMono>
              <TDMono className="text-right">{c.independent_groups}</TDMono>
              <TD className="text-xs">
                {c.actionable ? (
                  <span className="text-ok">yes</span>
                ) : (
                  <span className="text-faint">not yet</span>
                )}
              </TD>
              <TD className="max-w-md">
                <Disclosure label="why" labelOpen="hide">
                  <div className="space-y-2 text-xs text-dim">
                    <p>{c.note}</p>
                    {c.missing_evidence.length ? (
                      <div>
                        <span className="font-medium text-text">Would settle it:</span>
                        <ul className="mt-0.5 list-disc pl-4">
                          {c.missing_evidence.map((m) => (
                            <li key={m}>{m}</li>
                          ))}
                        </ul>
                      </div>
                    ) : null}
                    {c.alternatives.length ? (
                      <div>
                        <span className="font-medium text-text">
                          Benign explanations not ruled out:
                        </span>
                        <ul className="mt-0.5 list-disc pl-4">
                          {c.alternatives.map((a) => (
                            <li key={a}>{a}</li>
                          ))}
                        </ul>
                      </div>
                    ) : null}
                    <FinePrint className="font-mono">
                      evidence:{' '}
                      {c.evidence.length
                        ? c.evidence.map((e) => `${e.kind} (${e.independence_group})`).join(' · ')
                        : 'none'}
                    </FinePrint>
                  </div>
                </Disclosure>
              </TD>
            </TR>
          ))}
        </TBody>
      </Table>
    </div>
  )
}
