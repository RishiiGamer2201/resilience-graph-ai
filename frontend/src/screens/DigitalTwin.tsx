/**
 * Digital twin: counterfactual containment, and an advisor that restates it.
 *
 * Left: `POST /api/twin/candidates` ranks every host in the incident graph by
 * crown jewels protected, then blast-radius reduction, then LOWEST operational
 * cost. `POST /api/twin/simulate` diffs one of them on a clone. Nothing here
 * touches a real host: the backend returns `simulated: true` and its own note
 * saying so, and both are on screen.
 *
 * Right: `POST /api/twin/chat`. Every reply keeps the provenance line the API
 * sends (a template reply must never read like a model reply), and the header
 * reports the live `llm` block from the response rather than claiming the
 * advisor is grounded in retrieval whether or not anything was retrieved.
 */
import { useEffect, useRef, useState } from 'react'
import {
  ArrowRight,
  Bot,
  Cpu,
  ExternalLink,
  Scissors,
  Send,
  ShieldAlert,
  User,
} from 'lucide-react'
import {
  getGraph,
  getIncident,
  getLlm,
  twinCandidates,
  twinChat,
  twinSimulate,
} from '@/lib/api'
import { useFetch } from '@/hooks/useFetch'
import { useAnalysis } from '@/providers/analysis'
import { PageHeader } from '@/components/Layout'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Card, CardBody, CardHeader, CardMeta, CardTitle } from '@/components/ui/card'
import { SkeletonRows } from '@/components/ui/skeleton'
import { Table, TBody, TD, TDMono, TH, THead, TR } from '@/components/ui/table'
import {
  EmptyState,
  ErrorState,
  NotMeasured,
  ProvenanceLine,
  SectionLabel,
  StatRow,
} from '@/components/primitives'
import type {
  AttackGraph,
  AnalysisBundle,
  ContainmentCandidate,
  LlmStatus,
  TwinChatSource,
  TwinSimulation,
} from '@/types/api'

interface TwinBundle {
  graph: AttackGraph
  incidentId: string
  /** null when the server refused; `candidatesError` then carries its words. */
  candidates: ContainmentCandidate[] | null
  candidatesError: unknown
}

interface ChatMessage {
  role: 'user' | 'assistant'
  content: string
  sources?: TwinChatSource[]
  followUps?: string[]
  method?: string
  model?: string
  llmError?: string
  disclaimer?: string
}

/** Ranking a candidate needs the `simulate` permission. A viewer must see the
 *  server's refusal, not an empty table pretending there is nothing to rank. */
async function loadTwin(live: AnalysisBundle | null): Promise<TwinBundle> {
  const [graph, incident] = live
    ? [live.graph, live.incident]
    : await Promise.all([getGraph(), getIncident()])
  try {
    const res = await twinCandidates({ graph, limit: 6 })
    return {
      graph,
      incidentId: incident.incident_id,
      candidates: res.candidates,
      candidatesError: null,
    }
  } catch (e: unknown) {
    return { graph, incidentId: incident.incident_id, candidates: null, candidatesError: e }
  }
}

export default function DigitalTwin() {
  const { bundle, source } = useAnalysis()
  const { data, error, loading, reload } = useFetch<TwinBundle>(
    () => loadTwin(bundle),
    [bundle],
  )
  const { data: llmAtLoad } = useFetch<LlmStatus>(getLlm)

  const [sim, setSim] = useState<TwinSimulation | null>(null)
  const [simBusy, setSimBusy] = useState<string | null>(null)
  const [simError, setSimError] = useState<unknown>(null)

  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [input, setInput] = useState('')
  const [chatBusy, setChatBusy] = useState(false)
  /** The `llm` block from the most recent reply. Beats the load-time status. */
  const [llmLive, setLlmLive] = useState<LlmStatus | null>(null)
  const bottom = useRef<HTMLDivElement>(null)

  useEffect(() => {
    bottom.current?.scrollIntoView({ block: 'nearest' })
  }, [messages, chatBusy])

  async function simulate(host: string) {
    if (!data) return
    setSimBusy(host)
    setSimError(null)
    try {
      setSim(await twinSimulate({ graph: data.graph, isolate_host: host }))
    } catch (e: unknown) {
      setSimError(e)
      setSim(null)
    } finally {
      setSimBusy(null)
    }
  }

  async function send(text: string) {
    const message = text.trim()
    if (!message || chatBusy || !data) return
    const history = [...messages, { role: 'user' as const, content: message }]
    setMessages(history)
    setInput('')
    setChatBusy(true)
    try {
      const res = await twinChat({
        message,
        history: messages.map((m) => ({ role: m.role, content: m.content })),
        graph: data.graph,
        incident_id: data.incidentId,
        require_llm: true,
        assistant_mode: 'incident',
      })
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          content: res.reply,
          sources: res.sources,
          followUps: res.follow_ups,
          method: res.method,
          model: res.model,
          llmError: res.llm_error,
          disclaimer: res.disclaimer,
        },
      ])
      if (res.llm) setLlmLive(res.llm)
    } catch (e: unknown) {
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          content:
            e instanceof Error
              ? `The advisor endpoint refused or failed: ${e.message}`
              : 'The advisor endpoint refused or failed.',
          method: 'transport-error',
        },
      ])
    } finally {
      setChatBusy(false)
    }
  }

  if (loading) {
    return (
      <>
        <PageHeader eyebrow="Counterfactual" title="Digital twin" />
        <div className="grid gap-4 xl:grid-cols-2">
          {[0, 1].map((i) => (
            <Card key={i}>
              <CardBody>
                <SkeletonRows rows={8} />
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
        <PageHeader eyebrow="Counterfactual" title="Digital twin" />
        <Card>
          <ErrorState error={error ?? new Error('no graph')} retry={reload} />
        </Card>
      </>
    )
  }

  const { graph } = data
  const llm = llmLive ?? llmAtLoad ?? null
  const activeModel =
    llm?.active_provider ? llm.providers?.[llm.active_provider]?.model : undefined
  const advisorMeta = !llm
    ? 'language-model state unknown'
    : llm.enabled && llm.active_provider
      ? `${llm.active_provider}${activeModel ? ` · ${activeModel}` : ''} · not authoritative`
      : 'no language model active · deterministic templates'

  return (
    <>
      <PageHeader
        eyebrow="Safe response test"
        title="What happens if we isolate a computer?"
        description="Test a response on a copy of the attack map, with no changes to any real system."
        actions={
          <>
            <Badge variant={source === 'live' ? 'accent' : 'outline'}>
              {source === 'live'
                ? 'live analysis'
                : source === 'restored'
                  ? 'restored session'
                  : 'sample cache'}
            </Badge>
            <Badge variant="warn">simulation only</Badge>
          </>
        }
      />

      <div className="grid gap-4 xl:grid-cols-2">
        {/* ── Containment ─────────────────────────────────────────────── */}
        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Cpu className="size-4" aria-hidden />
                Incident under test
              </CardTitle>
              <CardMeta>{data.incidentId}</CardMeta>
            </CardHeader>
            <CardBody className="space-y-1">
              <StatRow label="Entry host">
                {graph.entry_host ?? (
                  <NotMeasured why="No entry point could be identified on this graph." />
                )}
              </StatRow>
              <StatRow label="Crown jewels reachable">
                {graph.critical_assets_at_risk?.length ? (
                  <span className="text-sev-critical">
                    {graph.critical_assets_at_risk.join(', ')}
                  </span>
                ) : (
                  <span className="text-faint">none marked reachable</span>
                )}
              </StatRow>
              <StatRow label="Blast radius">
                {graph.blast_radius_size != null ? (
                  `${graph.blast_radius_size.toLocaleString()} hosts`
                ) : (
                  <NotMeasured />
                )}
              </StatRow>
              <StatRow label="Backend recommendation">
                {graph.recommended_isolation ?? (
                  <NotMeasured why="No single host removal improved containment." />
                )}
              </StatRow>
            </CardBody>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Containment candidates</CardTitle>
              <CardMeta>benefit vs operational cost</CardMeta>
            </CardHeader>

            {data.candidatesError ? (
              <ErrorState error={data.candidatesError} retry={reload} />
            ) : data.candidates?.length ? (
              <>
                <Table>
                  <THead>
                    <TR>
                      <TH>Isolate</TH>
                      <TH>Crown jewels saved</TH>
                      <TH className="text-right">Blast cut</TH>
                      <TH className="text-right">Disruption</TH>
                      <TH>Verdict</TH>
                      <TH />
                    </TR>
                  </THead>
                  <TBody>
                    {data.candidates.map((c) => {
                      const chosen = sim?.candidate?.isolate_host === c.host
                      return (
                        <TR key={c.host} className={chosen ? 'bg-surface-2' : undefined}>
                          <TDMono className="text-text">
                            {c.host}
                            {c.is_crown_jewel ? (
                              <span className="ml-1 text-sev-critical">·crown jewel</span>
                            ) : null}
                          </TDMono>
                          <TD className="text-xs">
                            {c.crown_jewels_protected.length ? (
                              <span className="font-mono text-ok">
                                {c.crown_jewels_protected.join(', ')}
                              </span>
                            ) : (
                              <span className="text-faint">none</span>
                            )}
                          </TD>
                          <TDMono className="text-right">
                            −{c.blast_radius_reduction.toLocaleString()}
                            <span className="ml-1 text-faint">
                              ({c.blast_radius_reduction_pct}%)
                            </span>
                          </TDMono>
                          <TDMono className="text-right text-dim">
                            {c.sessions_severed} sess · {c.accounts_disrupted} acct
                          </TDMono>
                          <TD className="max-w-xs text-xs text-faint">{c.verdict}</TD>
                          <TD>
                            <Button
                              variant={chosen ? 'default' : 'secondary'}
                              size="sm"
                              disabled={simBusy !== null}
                              onClick={() => void simulate(c.host)}
                            >
                              <Scissors className="size-3" />
                              {simBusy === c.host ? 'Simulating…' : 'Simulate'}
                            </Button>
                          </TD>
                        </TR>
                      )
                    })}
                  </TBody>
                </Table>
                <div className="border-t border-border px-4 py-2 text-xs text-faint">
                  Ordered by crown jewels protected, then blast-radius reduction, then the
                  lowest operational cost, never a bigger outage for the same security
                  benefit. &ldquo;Simulate&rdquo; runs the counterfactual on a clone; it
                  proposes, it does not contain.
                </div>
              </>
            ) : (
              <EmptyState
                title="No containment candidate in this topology"
                detail="Every host with outbound movement was scored and none changed the exposure."
                icon={ShieldAlert}
              />
            )}
          </Card>

          {simError ? (
            <Card>
              <ErrorState error={simError} />
            </Card>
          ) : null}

          {sim ? (
            <Card>
              <CardHeader>
                <CardTitle className="font-mono">
                  Simulated isolation of {sim.candidate.isolate_host ?? 'unknown host'}
                </CardTitle>
                <Badge variant="warn">counterfactual</Badge>
              </CardHeader>
              <CardBody className="space-y-3">
                <p className="text-sm text-text">{sim.verdict}</p>

                <div className="grid gap-2 sm:grid-cols-2">
                  <Diff
                    label="Blast radius"
                    before={sim.before.blast_radius}
                    after={sim.after.blast_radius}
                  />
                  <Diff
                    label="Crown jewels reachable"
                    before={sim.before.crown_jewels_reachable.length}
                    after={sim.after.crown_jewels_reachable.length}
                  />
                </div>

                <div className="space-y-1">
                  <StatRow label="Crown jewels protected">
                    {sim.delta.crown_jewels_protected.length ? (
                      <span className="text-ok">
                        {sim.delta.crown_jewels_protected.join(', ')}
                      </span>
                    ) : (
                      <span className="text-faint">none</span>
                    )}
                  </StatRow>
                  <StatRow label="Still reachable after">
                    {sim.delta.crown_jewels_still_reachable.length ? (
                      <span className="text-sev-critical">
                        {sim.delta.crown_jewels_still_reachable.join(', ')}
                      </span>
                    ) : (
                      <span className="text-faint">none</span>
                    )}
                  </StatRow>
                  <StatRow label="Hosts removed from reach">
                    {sim.delta.hosts_no_longer_reachable.toLocaleString()}
                    <span className="ml-1 text-faint">
                      ({sim.delta.blast_radius_reduction_pct}%)
                    </span>
                  </StatRow>
                  <StatRow label="Operational cost">
                    {sim.operational_cost.hosts_taken_offline} host ·{' '}
                    {sim.operational_cost.sessions_severed} sessions ·{' '}
                    {sim.operational_cost.accounts_disrupted.length} accounts
                  </StatRow>
                  <StatRow label="Isolating a crown jewel">
                    {sim.operational_cost.host_is_crown_jewel ? 'yes' : 'no'}
                  </StatRow>
                </div>

                <div className="border-t border-border pt-2 text-xs text-faint">
                  <div>{sim.note}</div>
                  <ProvenanceLine method={sim.method} />
                </div>
              </CardBody>
            </Card>
          ) : null}
        </div>

        {/* ── Advisor ─────────────────────────────────────────────────── */}
        <Card className="flex flex-col">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Bot className="size-4" aria-hidden />
              Advisor
            </CardTitle>
            <CardMeta>{advisorMeta}</CardMeta>
          </CardHeader>

          {llm?.note ? (
            <p className="border-b border-border px-4 py-2 text-xs text-faint">
              {llm.note}
            </p>
          ) : null}

          <div
            className="flex min-h-[420px] flex-1 flex-col gap-4 overflow-y-auto p-4"
            role="log"
            aria-live="polite"
            aria-relevant="additions text"
          >
            {!messages.length ? (
              <EmptyState
                title="Ask the advisor about this incident"
                detail="Ask what is exposed, what isolation would cost, or what the analysis cannot tell you. Answers come from the configured language model using the incident facts; it does not decide or approve actions."
                icon={Bot}
              />
            ) : null}

            {messages.map((m, i) => (
              <div
                key={i}
                className={
                  m.role === 'user'
                    ? 'flex flex-col items-end gap-1'
                    : 'flex flex-col items-start gap-1'
                }
              >
                <div className="flex items-center gap-1.5 text-xs text-faint">
                  {m.role === 'user' ? (
                    <User className="size-3" aria-hidden />
                  ) : (
                    <Bot className="size-3" aria-hidden />
                  )}
                  {m.role === 'user' ? 'You' : 'Advisor'}
                </div>
                <div
                  className={
                    m.role === 'user'
                      ? 'max-w-[92%] whitespace-pre-wrap rounded-lg border border-accent/30 bg-accent-soft px-3 py-2 text-sm text-text'
                      : 'max-w-[92%] whitespace-pre-wrap rounded-lg border border-border bg-surface-2 px-3 py-2 text-sm text-text'
                  }
                >
                  {m.content}
                </div>

                {m.role === 'assistant' ? (
                  <>
                    <ProvenanceLine method={m.method} model={m.model} error={m.llmError} />
                    {m.disclaimer ? (
                      <p className="max-w-[92%] text-xs text-faint">{m.disclaimer}</p>
                    ) : null}
                    <Sources sources={m.sources} />
                    {m.followUps?.length && i === messages.length - 1 ? (
                      <div className="mt-1 flex flex-wrap gap-1.5">
                        {m.followUps.map((q) => (
                          <Button
                            key={q}
                            variant="outline"
                            size="sm"
                            disabled={chatBusy}
                            onClick={() => void send(q)}
                          >
                            {q}
                          </Button>
                        ))}
                      </div>
                    ) : null}
                  </>
                ) : null}
              </div>
            ))}

            {chatBusy ? <SkeletonRows rows={2} /> : null}
            <div ref={bottom} />
          </div>

          <form
            className="flex items-center gap-2 border-t border-border p-3"
            onSubmit={(e) => {
              e.preventDefault()
              void send(input)
            }}
          >
            <input
              value={input}
              onChange={(e) => setInput(e.target.value)}
              disabled={chatBusy}
              aria-label="Ask the advisor"
              placeholder="Ask what is exposed, what isolation costs, or what this analysis cannot tell you"
              className="flex-1 rounded-md border border-border bg-surface-2 px-3 py-1.5 text-sm text-text outline-none placeholder:text-faint focus-visible:outline-2 focus-visible:outline-accent"
            />
            <Button type="submit" size="sm" disabled={chatBusy || !input.trim()}>
              <Send className="size-3.5" />
              Send
            </Button>
          </form>
        </Card>
      </div>
    </>
  )
}

function Diff({ label, before, after }: { label: string; before: number; after: number }) {
  const better = after < before
  return (
    <div className="rounded-md border border-border bg-surface-2 px-3 py-2">
      <SectionLabel>{label}</SectionLabel>
      <div className="mt-1 flex items-baseline gap-2 font-mono text-sm tabular-nums">
        <span className="text-dim">{before.toLocaleString()}</span>
        <ArrowRight className="size-3 text-faint" aria-hidden />
        <span className={better ? 'text-ok' : after > before ? 'text-sev-critical' : 'text-text'}>
          {after.toLocaleString()}
        </span>
      </div>
    </div>
  )
}

/** What the advisor retrieved. When nothing came back the panel says so rather
 *  than leaving the reply looking grounded. */
function Sources({ sources }: { sources?: TwinChatSource[] }) {
  if (!sources) return null
  if (!sources.length) {
    return (
      <p className="text-xs text-faint">
        No source was retrieved for this answer; it restates the incident bundle only.
      </p>
    )
  }
  return (
    <div className="max-w-[92%] space-y-1">
      <SectionLabel>Retrieved sources · {sources.length}</SectionLabel>
      {sources.map((s, i) => (
        <div
          key={`${s.url}-${i}`}
          className="rounded-md border border-border bg-surface-2 px-2.5 py-1.5"
        >
          <div className="flex items-baseline gap-1.5">
            <span className="text-xs font-medium text-dim">{s.publisher}</span>
            <a
              href={s.url}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 text-xs text-accent underline-offset-4 hover:underline"
            >
              {s.title}
              <ExternalLink className="size-2.5" aria-hidden />
            </a>
            {s.injection_suspected ? (
              <Badge variant="critical">prompt injection suspected · quoted, not obeyed</Badge>
            ) : null}
          </div>
          {s.why_relevant ? (
            <p className="text-xs text-faint">{s.why_relevant}</p>
          ) : null}
          <p className="mt-0.5 line-clamp-2 text-xs text-faint">{s.excerpt}</p>
          {s.identifiers?.length ? (
            <p className="mt-0.5 font-mono text-xs text-faint">
              {s.identifiers.join(' · ')}
            </p>
          ) : null}
        </div>
      ))}
    </div>
  )
}
