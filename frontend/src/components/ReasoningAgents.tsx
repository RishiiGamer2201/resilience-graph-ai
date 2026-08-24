/**
 * Two agents over the attack graph, and the guard rails around them.
 *
 * The cross-check panel above this one compares two DETERMINISTIC lanes. This
 * is the only place in the product where a language model chooses what to do
 * next: an Investigator picks which of seven read-only graph tools to call and
 * writes a hypothesis, then a Critic is handed the same tools and told to
 * refute it.
 *
 * Opt-in, because it is several model round trips and because a product that
 * quietly calls a third party on page load is not one you hand to a hospital.
 *
 * The part worth reading is the citation row. Every tool result is tagged with
 * an evidence_id, and a claim citing an id the agent never received is dropped
 * in Python before it reaches this component. On the first live run two of
 * five citations were invented. Showing the rejections is the point: an agent
 * lane that cannot be caught lying is not evidence of anything.
 */
import { useState } from 'react'
import { Bot, Gavel, Route, ShieldAlert, Sparkles } from 'lucide-react'
import { Card, CardBody, CardHeader, CardMeta, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { SectionLabel } from '@/components/primitives'
import { FinePrint } from '@/components/Disclosure'
import { reasonWithAgents } from '@/lib/api'
import type { AgentReasoning } from '@/types/api'
import { techniqueName } from '@/lib/techniques'

const WHO: Record<string, typeof Bot> = { investigator: Bot, critic: Gavel }

function ToolTrace({ calls }: { calls: AgentReasoning['tool_calls'] }) {
  if (!calls?.length) return <p className="text-xs text-faint">No tool was called.</p>
  return (
    <ol className="mt-2 flex flex-col gap-1">
      {calls.map((c, i) => {
        const Icon = WHO[c.agent] ?? Route
        return (
          <li
            key={`${c.agent}-${c.tool}-${i}`}
            className={`flex items-center gap-3 rounded-md border bg-surface-2 px-3 py-2 text-xs ${
              c.error ? 'border-sev-high/40' : 'border-border'
            }`}
          >
            <Icon size={13} aria-hidden="true" className="shrink-0 text-faint" />
            <span className="w-20 shrink-0 capitalize text-faint">{c.agent}</span>
            <span className="font-mono">{c.tool}</span>
            <span className="ml-auto text-faint">
              {c.error ? c.error : `${c.rows} row${c.rows === 1 ? '' : 's'}`}
            </span>
          </li>
        )
      })}
    </ol>
  )
}

export default function ReasoningAgents({
  scenario,
  criticalAssets = [],
  incidentId,
}: {
  scenario?: string
  criticalAssets?: string[]
  incidentId?: string
}) {
  const [run, setRun] = useState<AgentReasoning | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)

  const go = async () => {
    setBusy(true)
    setError(null)
    try {
      setRun(
        await reasonWithAgents({
          scenario,
          critical_assets: criticalAssets,
          incident_id: incidentId,
        }),
      )
    } catch (e) {
      setError(e)
    } finally {
      setBusy(false)
    }
  }

  const agreed = run?.workflow_techniques?.length
    ? run.techniques.filter((t) => run.workflow_techniques!.includes(t))
    : []

  return (
    <Card>
      <CardHeader>
        <CardTitle>Reasoning agents</CardTitle>
        <CardMeta>
          {run
            ? `${run.method === 'agents' ? run.provider : 'deterministic summary'} · advisory, not authoritative`
            : 'advisory · opt-in'}
        </CardMeta>
        <Button size="sm" variant={run ? 'ghost' : 'default'} disabled={busy} onClick={go}>
          {!run && <Sparkles size={14} aria-hidden="true" />}
          {busy ? 'Investigating…' : run ? 'Run again' : 'Run the agents'}
        </Button>
      </CardHeader>

      <CardBody className="flex flex-col gap-4">
        {!run && !error && (
          <p className="rounded-md border border-dashed border-border bg-surface-2 p-3 text-xs leading-relaxed text-dim">
            Optional second opinion from an investigator and critic. Read-only; 15 to 40 seconds.
          </p>
        )}

        {error != null && (
          <p className="flex items-start gap-2 rounded-md border border-sev-critical/40 bg-surface-2 p-3 text-xs leading-relaxed text-dim">
            <ShieldAlert size={15} aria-hidden="true" className="mt-0.5 shrink-0 text-sev-critical" />
            <span>
              The agent lane did not return: {String((error as Error)?.message ?? error)}. The
              investigation above is unaffected.
            </span>
          </p>
        )}

        {run && (
          <>
            <div className="grid gap-3 md:grid-cols-[1.4fr_1fr]">
              <div className="min-w-0 rounded-md border border-border bg-surface-2 p-3">
                <SectionLabel>Investigator</SectionLabel>
                <p className="mt-2 text-sm leading-relaxed">{run.hypothesis}</p>
                <div className="mt-3 flex flex-wrap gap-1.5">
                  {run.techniques.length ? (
                    run.techniques.map((t) => (
                      <Badge key={t} variant={agreed.includes(t) ? 'ok' : 'default'}>
                        {techniqueName(t)}
                      </Badge>
                    ))
                  ) : (
                    <span className="text-xs text-faint">no techniques named</span>
                  )}
                </div>
                <p className="mt-2 text-xs text-faint">
                  confidence {run.confidence.toFixed(2)}
                  {agreed.length > 0 &&
                    ` · ${agreed.length} of ${run.techniques.length} match the workflow`}
                </p>
              </div>

              <div
                className={`min-w-0 rounded-md border bg-surface-2 p-3 ${
                  run.refuted === true ? 'border-sev-high/40' : 'border-border'
                }`}
              >
                <SectionLabel>Critic</SectionLabel>
                {/* Three states, not two. `null` means the review never returned,
                    and showing that as "stands" would claim a corroboration
                    nobody performed. */}
                <p className="mt-2 text-lg font-medium capitalize">
                  {run.refuted === true ? 'refuted' : run.refuted === false ? 'stands' : 'not reviewed'}
                </p>
                {run.refuted === null && (
                  <p className="mt-1 text-xs leading-relaxed text-faint">
                    No verdict came back, so nothing here has been checked by a second agent.
                  </p>
                )}
                {run.critic_reasons?.length > 0 && (
                  <ul className="mt-2 list-disc pl-4 text-xs leading-relaxed text-dim">
                    {run.critic_reasons.map((r) => (
                      <li key={r} className="mb-0.5">
                        {r}
                      </li>
                    ))}
                  </ul>
                )}
                {run.alternative && (
                  <div className="mt-3">
                    <SectionLabel>Alternative explanation</SectionLabel>
                    <p className="mt-1 text-xs leading-relaxed text-dim">{run.alternative}</p>
                  </div>
                )}
              </div>
            </div>

            {/* The citation check, which is the reason this lane is allowed to
                exist. Rejections are shown, never quietly discarded. */}
            <div>
              <SectionLabel>Evidence cited</SectionLabel>
              <div className="mt-2 flex flex-wrap items-center gap-1.5">
                {run.evidence_ids.length ? (
                  run.evidence_ids.map((e) => (
                    <Badge key={e} className="font-mono">
                      {e}
                    </Badge>
                  ))
                ) : (
                  <span className="text-xs text-faint">
                    {run.method === 'agents'
                      ? 'none survived the check'
                      : 'nothing to cite: the summary states graph facts rather than claims'}
                  </span>
                )}
              </div>
              {run.rejected_citations?.length > 0 && (
                <p className="mt-2 text-xs leading-relaxed text-sev-high">
                  {run.rejected_citations.length} citation
                  {run.rejected_citations.length === 1 ? '' : 's'} rejected:{' '}
                  <span className="font-mono">{run.rejected_citations.join(' · ')}</span> were in
                  no tool output this agent received.
                </p>
              )}
            </div>

            <div>
              <SectionLabel>What the agents actually did</SectionLabel>
              <ToolTrace calls={run.tool_calls} />
            </div>

            {run.missing?.length > 0 && (
              <div className="rounded-md border border-dashed border-border bg-surface-2 p-3">
                <SectionLabel>What would settle this</SectionLabel>
                <ul className="mt-2 list-disc pl-4 text-xs leading-relaxed text-dim">
                  {run.missing.map((m) => (
                    <li key={m} className="mb-0.5">
                      {m}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {run.notes?.length > 0 && (
              <FinePrint>
                {run.notes.map((n) => (
                  <span key={n} className="block">
                    {n}
                  </span>
                ))}
              </FinePrint>
            )}
          </>
        )}
      </CardBody>
    </Card>
  )
}
