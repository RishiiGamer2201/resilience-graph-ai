/**
 * Investigate — weak signals to one verified attack story.
 *
 * Seven bounded stages, run server-side by POST /api/investigate. Every number
 * on this screen is deterministic Python; every ATT&CK conclusion carries an
 * official citation or says it has none; every action is simulated and gated.
 *
 * Nothing here is hardcoded. The scenario list, the crown jewels, the trace,
 * the metrics, the claims, the containment candidates and the audit records all
 * come from the API. Where the API returns nothing, the screen says so rather
 * than filling the space.
 *
 * Two things that look like bugs and are not:
 *   - The Run button is not disabled for a viewer. RBAC is server-enforced; the
 *     403 and its reason are what an operator needs to see. Hiding the control
 *     would teach them the client is the gate.
 *   - The workflow lane and the agent lane can disagree. Both are rendered.
 */
import * as React from 'react'
import { useNavigate } from 'react-router-dom'
import { useReducedMotion } from 'motion/react'
import { CircleAlert, Play, RotateCcw, Search, Target } from 'lucide-react'

import {
  getCapabilities,
  getScenarios,
  investigate,
  resetAudit,
  twinCandidates,
} from '@/lib/api'
import { useFetch } from '@/hooks/useFetch'
import { useAnalysis } from '@/providers/analysis'
import { useSession } from '@/providers/session'

import { PageHeader } from '@/components/Layout'
import { Card, CardBody, CardHeader, CardMeta, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { SkeletonRows } from '@/components/ui/skeleton'
import {
  EmptyState,
  ErrorState,
  NotMeasured,
  Reveal,
  SectionLabel,
  SeverityBadge,
  StatRow,
} from '@/components/primitives'
import { Disclosed, FinePrint } from '@/components/Disclosure'
import { techniqueList, techniqueName } from '@/lib/techniques'

import StageRail from '@/components/StageRail'
import Headline from '@/components/Headline'
import Assessment, { ClaimsPanel } from '@/components/Assessment'
import EvidenceList from '@/components/EvidenceList'
import CaseFile from '@/components/CaseFile'
import CrossCheck from '@/components/CrossCheck'
import ReasoningAgents from '@/components/ReasoningAgents'
import Progression from '@/components/Progression'
import { TwinPanel, VulnPanel } from '@/components/ImpactPanel'
import ActionPanel from '@/components/ActionPanel'
import AuditPanel from '@/components/AuditPanel'

import type {
  Capabilities,
  ContainmentCandidate,
  InvestigationResult,
  IncidentReportData,
  ScenarioList,
  TraceNode,
} from '@/types/api'

/** The hero scenario, when the backend ships it: a concrete critical-
 *  infrastructure story with a named crown jewel and a real asset inventory, so
 *  vulnerability prioritisation has something honest to work with. If the
 *  backend does not list it, the first scenario it does list is used. No
 *  scenario is ever invented client-side. */
const HERO = 'aiims_ransomware'

/** One plan step, as the plan node reported it. */
interface PlanStep {
  node: string
  tool: string
  why: string
  selected: boolean
}

function isPlanStep(v: unknown): v is PlanStep {
  if (typeof v !== 'object' || v === null) return false
  const o = v as Record<string, unknown>
  return typeof o.node === 'string' && typeof o.tool === 'string'
}

function planSteps(nodes: TraceNode[]): PlanStep[] {
  const out = nodes.find((n) => n.node === 'plan')?.output?.steps
  return Array.isArray(out) ? out.filter(isPlanStep) : []
}

function Section({
  id,
  title,
  subtitle,
  children,
  registerRef,
}: {
  id: string
  title: string
  subtitle: string
  children: React.ReactNode
  registerRef: (id: string, el: HTMLElement | null) => void
}) {
  return (
    <section id={id} ref={(el) => registerRef(id, el)} className="mt-6 scroll-mt-4">
      <div className="mb-2 flex items-baseline gap-2">
        <SectionLabel>{title}</SectionLabel>
        <span className="text-xs text-faint">{subtitle}</span>
      </div>
      {children}
    </section>
  )
}

export default function Investigate() {
  const navigate = useNavigate()
  const reducedMotion = useReducedMotion()
  const { setBundle } = useAnalysis()
  const { role, label: roleLabel } = useSession()

  const scenarios = useFetch<ScenarioList>(getScenarios)
  const caps = useFetch<Capabilities>(getCapabilities)

  const [scenario, setScenario] = React.useState<string | null>(null)
  const [result, setResult] = React.useState<InvestigationResult | null>(null)
  const [candidates, setCandidates] = React.useState<ContainmentCandidate[]>([])
  const [running, setRunning] = React.useState(false)
  const [runError, setRunError] = React.useState<unknown>(null)
  const [resetError, setResetError] = React.useState<unknown>(null)
  const [resetting, setResetting] = React.useState(false)
  const [auditKey, setAuditKey] = React.useState(0)
  const [active, setActive] = React.useState<string | null>(null)
  const refs = React.useRef<Record<string, HTMLElement | null>>({})

  React.useEffect(() => {
    if (!result || typeof IntersectionObserver === 'undefined') return
    const sections = Object.entries(refs.current).filter(
      (entry): entry is [string, HTMLElement] => entry[1] instanceof HTMLElement,
    )
    const observer = new IntersectionObserver(
      (entries) => {
        const visible = entries
          .filter((entry) => entry.isIntersecting)
          .sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0]
        if (visible?.target.id) setActive(visible.target.id)
      },
      { rootMargin: '-15% 0px -65% 0px', threshold: [0, 0.15, 0.5] },
    )
    sections.forEach(([, element]) => observer.observe(element))
    return () => observer.disconnect()
  }, [result])

  const registerRef = React.useCallback((id: string, el: HTMLElement | null) => {
    refs.current[id] = el
  }, [])

  const list = React.useMemo(
    () => scenarios.data?.scenarios ?? [],
    [scenarios.data?.scenarios],
  )

  // The selection defaults to whatever the backend actually offers.
  React.useEffect(() => {
    if (scenario || !list.length) return
    setScenario(list.find((s) => s.name === HERO)?.name ?? list[0].name)
  }, [list, scenario])

  const meta = list.find((s) => s.name === scenario)
  // Stable identity: `run` depends on it, and a fresh array every render would
  // rebuild the callback for no reason.
  const critKey = (meta?.critical_default ?? []).join(',')
  const crit = React.useMemo(
    () => (critKey ? critKey.split(',') : []),
    [critKey],
  )

  const run = React.useCallback(async () => {
    if (!scenario) return
    setRunning(true)
    setRunError(null)
    setResetError(null)
    setResult(null)
    setCandidates([])
    try {
      const r = await investigate({ scenario, critical_assets: crit })
      setResult(r)
      // Every other screen renders this same analysis.
      setBundle({
        ...r.signals,
        analysis: {
          claims: r.impact.claims,
          assessment: r.impact.assessment,
          attack_progression_likelihood: r.impact.attack_progression_likelihood,
          evidence_confidence: r.impact.evidence_confidence,
          crown_jewel_exposure: r.impact.crown_jewel_exposure,
          progression_forecast: r.impact.progression_forecast,
          crosscheck: r.impact.crosscheck ?? r.crosscheck ?? null,
        },
        meta: r.meta,
      })
      setAuditKey((k) => k + 1)
      try {
        const c = await twinCandidates({ graph: r.signals.graph, limit: 6 })
        setCandidates(c.candidates)
      } catch {
        /* the twin is optional; the investigation stands without it */
      }
    } catch (e) {
      setRunError(e)
    } finally {
      setRunning(false)
    }
  }, [scenario, crit, setBundle])

  async function resetDemo() {
    setResetting(true)
    setResetError(null)
    try {
      await resetAudit()
      setResult(null)
      setCandidates([])
      setRunError(null)
      setActive(null)
      setBundle(null)
    } catch (error: unknown) {
      setResetError(error)
    } finally {
      setResetting(false)
      setAuditKey((k) => k + 1)
    }
  }

  function jump(node: string) {
    setActive(node)
    refs.current[node]?.scrollIntoView({
      behavior: reducedMotion ? 'auto' : 'smooth',
      block: 'start',
    })
  }

  const header = (
    <PageHeader
      eyebrow="Step-by-step investigation"
      title="Turn warning signs into a clear attack story"
      description="Follow seven guided stages. Each finding shows its evidence, and every response action is only a safe simulation until a person approves it."
      actions={result ? <SeverityBadge severity={result.signals.incident.severity} /> : null}
    />
  )

  if (scenarios.loading) {
    return (
      <>
        {header}
        <Card>
          <CardBody>
            <SkeletonRows rows={3} />
          </CardBody>
        </Card>
      </>
    )
  }

  if (scenarios.error) {
    return (
      <>
        {header}
        <Card>
          <ErrorState error={scenarios.error} retry={scenarios.reload} />
        </Card>
      </>
    )
  }

  const degraded = caps.data?.degraded ?? []
  const inc = result?.signals.incident
  const graph = result?.signals.graph

  return (
    <>
      {header}

      {degraded.length ? (
        <div className="mb-4 flex items-start gap-2 rounded-lg border border-warn/40 bg-warn/5 px-3 py-2 text-xs text-dim">
          <CircleAlert className="mt-0.5 size-3.5 shrink-0 text-warn" aria-hidden />
          <span>
            Running degraded: <span className="font-mono text-text">{degraded.join(', ')}</span>.
            The investigation still completes — each stage reports what it could not do instead
            of hiding it.
          </span>
        </div>
      ) : null}

      <Card>
        <CardBody className="flex flex-wrap items-end gap-3">
          <div className="min-w-56">
            <label htmlFor="scenario" className="section-label mb-1 block">
              Scenario
            </label>
            <select
              id="scenario"
              value={scenario ?? ''}
              disabled={running || !list.length}
              onChange={(e) => setScenario(e.target.value)}
              className="h-8 w-full rounded-md border border-border bg-surface-2 px-2 text-sm text-text"
            >
              {list.map((s) => (
                <option key={s.name} value={s.name}>
                  {s.label}
                  {s.n_events != null ? ` · ${s.n_events.toLocaleString()} events` : ''}
                </option>
              ))}
            </select>
          </div>

          <div className="min-w-0 flex-1">
            <SectionLabel>Crown jewels</SectionLabel>
            <div className="mt-1 flex items-center gap-1.5 font-mono text-xs text-dim">
              <Target className="size-3 shrink-0 text-faint" aria-hidden />
              {crit.length ? (
                <span className="truncate">{crit.join(', ')}</span>
              ) : (
                <span className="text-faint">none designated for this scenario</span>
              )}
            </div>
          </div>

          {/* Not disabled by role. The server refuses and its refusal is shown. */}
          <Button disabled={running || !scenario} onClick={() => void run()}>
            <Play className="size-3" aria-hidden />
            {running ? 'Investigating…' : 'Run investigation'}
          </Button>
          <Button
            variant="outline"
            disabled={running || resetting}
            onClick={() => void resetDemo()}
          >
            <RotateCcw className="size-3" aria-hidden />
            {resetting ? 'Resetting…' : 'Reset demo'}
          </Button>
        </CardBody>
      </Card>

      {!result ? (
        <div className="mt-4 lg:hidden">
          <StageRail trace={null} running={running} onJump={jump} active={active} />
        </div>
      ) : null}

      {/* Live region: an analysis completing is announced. */}
      <div className="sr-only" role="status" aria-live="polite">
        {running
          ? 'Investigation running'
          : result
            ? `Investigation complete: severity ${result.signals.incident.severity}`
            : ''}
      </div>

      {runError ? (
        <Card className="mt-4">
          <ErrorState error={runError} retry={() => void run()} />
          <CardBody className="border-t border-border">
            <FinePrint>
              Requests are sent as <span className="font-mono text-text">{roleLabel}</span> (
              <span className="font-mono">{role}</span>). Role is enforced server-side; switch it
              in the top bar to see a different answer from the API.
            </FinePrint>
          </CardBody>
        </Card>
      ) : null}

      {resetError ? (
        <Card className="mt-4">
          <ErrorState error={resetError} retry={() => void resetDemo()} />
        </Card>
      ) : null}

      {result && inc && graph ? (
        <div className="mt-6 grid items-start gap-6 lg:grid-cols-[14rem_minmax(0,1fr)]">
          <aside className="sticky top-4 z-20 hidden lg:block">
            <div className="section-label mb-2">Investigation path</div>
            <StageRail trace={result.trace} running={running} onJump={jump} active={active} />
          </aside>
          <div className="min-w-0">
            <div className="mb-4 lg:hidden">
              <StageRail trace={result.trace} running={running} onJump={jump} active={active} />
            </div>
          <Reveal>
            <div className="mt-4">
              <Headline headline={result.headline} />
            </div>
          </Reveal>

          <div className="mt-4">
            <Assessment
              assessment={result.headline.assessment}
              likelihood={result.headline.attack_progression_likelihood}
              confidence={result.headline.evidence_confidence}
            />
          </div>

          <Section
            id="understand"
            title="1 · Understand"
            subtitle="what we were given, and what is missing"
            registerRef={registerRef}
          >
            <Card>
              <CardBody className="grid gap-x-8 sm:grid-cols-2">
                <StatRow label="Source">
                  {result.understand.source} · provenance {result.understand.provenance}
                </StatRow>
                <StatRow label="Events">{result.understand.n_events.toLocaleString()}</StatRow>
                <StatRow label="Accounts">{result.understand.accounts_total}</StatRow>
                <StatRow label="Hosts">{result.understand.hosts_total}</StatRow>
                <StatRow label="Crown jewels designated">
                  {result.understand.crown_jewels_designated.join(', ') || (
                    <span className="text-faint">none</span>
                  )}
                </StatRow>
                <StatRow label="Columns defaulted by schema">
                  {result.understand.columns_missing.join(', ') || (
                    <span className="text-faint">none</span>
                  )}
                </StatRow>
                <StatRow label="Crown jewels absent from this log">
                  {result.understand.crown_jewels_not_in_log.join(', ') || (
                    <span className="text-faint">none</span>
                  )}
                </StatRow>
              </CardBody>
            </Card>
          </Section>

          <Section
            id="plan"
            title="2 · Plan"
            subtitle="only the tools this case needs"
            registerRef={registerRef}
          >
            <Card>
              <CardBody className="space-y-2">
                {planSteps(result.trace.nodes).length ? (
                  <ul className="space-y-1.5">
                    {planSteps(result.trace.nodes).map((s) => (
                      <li
                        key={s.node}
                        className={`rounded-md border px-3 py-2 ${
                          s.selected
                            ? 'border-border bg-surface-2'
                            : 'border-dashed border-border opacity-60'
                        }`}
                      >
                        <div className="flex flex-wrap items-baseline gap-2">
                          <span className="text-sm font-medium text-text">{s.node}</span>
                          <span className="font-mono text-xs text-faint">{s.tool}</span>
                          <span className="flex-1" />
                          <span className="text-xs text-faint">
                            {s.selected ? 'selected' : 'not needed for this case'}
                          </span>
                        </div>
                        <div className="mt-0.5 text-xs text-dim">{s.why}</div>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <Disclosed>The plan node reported no step list for this run.</Disclosed>
                )}
                <FinePrint>
                  {result.trace.bounded_by}. There is no free-running agent loop here.
                </FinePrint>
              </CardBody>
            </Card>
          </Section>

          <Section
            id="evidence"
            title="3 · Evidence"
            subtitle="official sources, hashed and dated"
            registerRef={registerRef}
          >
            <div className="space-y-4">
              <Card>
                <CardBody>
                  <EvidenceList evidence={result.evidence} />
                </CardBody>
              </Card>
              {/* Only for a scenario styled after a documented real incident.
                  Synthetic scenarios correctly show nothing here. */}
              <CaseFile casefile={result.casefile} />
            </div>
          </Section>

          <Section
            id="signals"
            title="4 · Signals"
            subtitle="detect, correlate, map, predict"
            registerRef={registerRef}
          >
            <div className="space-y-4">
              <div className="grid gap-4 xl:grid-cols-2">
                <Card>
                  <CardHeader>
                    <CardTitle>One correlated incident</CardTitle>
                    <CardMeta>{inc.incident_id}</CardMeta>
                  </CardHeader>
                  <CardBody>
                    <StatRow label="Severity">
                      {inc.severity} · peak score {inc.max_anomaly_score}/100
                    </StatRow>
                    <StatRow label="Collapsed">
                      {inc.event_count.toLocaleString()} events → {inc.alert_count} alerts → 1
                      incident
                    </StatRow>
                    <StatRow label="Accounts">{inc.accounts_involved?.length ?? 0}</StatRow>
                    <StatRow label="ATT&CK chain">
                      {inc.technique_ids.length ? techniqueList(inc.technique_ids) : <NotMeasured />}
                    </StatRow>
                    <StatRow label="Attacker pivot">
                      {graph.entry_host ?? (
                        <NotMeasured why="No entry point could be identified." />
                      )}
                    </StatRow>
                    <StatRow label="Crown jewels reachable">
                      {graph.critical_assets_at_risk.join(', ') || (
                        <span className="text-faint">none reached</span>
                      )}
                    </StatRow>
                  </CardBody>
                </Card>

                <Card>
                  <CardHeader>
                    <CardTitle>Predicted next moves</CardTitle>
                    <CardMeta>interpolated Markov · predicted, not observed</CardMeta>
                  </CardHeader>
                  <CardBody className="space-y-2">
                    <PredictedNext report={result.signals.report} />
                    <FinePrint>
                      Measured top-3 accuracy and the baseline it beats are on the{' '}
                      <button
                        type="button"
                        className="text-accent underline-offset-4 hover:underline"
                        onClick={() => navigate('/scoreboard')}
                      >
                        PS7 scoreboard
                      </button>
                      .
                    </FinePrint>
                  </CardBody>
                </Card>
              </div>

              <Card>
                <CardHeader>
                  <CardTitle>What we actually claim</CardTitle>
                  <CardMeta>observed · inferred · predicted</CardMeta>
                </CardHeader>
                <div className="pt-3">
                  <ClaimsPanel claims={result.impact.claims} />
                </div>
              </Card>

              {/* A second, differently-built analysis of the same log. The
                  workflow governs; agreement or disagreement here moves
                  evidence confidence and is never averaged away. */}
              <CrossCheck crosscheck={result.crosscheck} />
              {/* Both lanes above are deterministic. This one is not: it is the
                  only place a model decides what to look at next, which is why
                  it is opt-in and why its citations are checked in code. */}
              <ReasoningAgents
                scenario={result.scenario ?? undefined}
                criticalAssets={result.understand?.crown_jewels_designated ?? []}
                incidentId={result.incident_id}
              />
            </div>
          </Section>

          <Section
            id="replan"
            title="5 · Replan"
            subtitle="one bounded retry on an evidence gap"
            registerRef={registerRef}
          >
            <Card>
              <CardBody className="space-y-2">
                {result.trace.nodes.filter((n) => n.node === 'replan').length ? (
                  result.trace.nodes
                    .filter((n) => n.node === 'replan')
                    .map((n, i) => (
                      <div key={`${n.summary}-${i}`} className="text-xs text-dim">
                        <span className="mr-2 rounded-md border border-border bg-surface-2 px-1.5 py-0.5 font-mono text-faint">
                          pass {i + 1}
                        </span>
                        {n.summary}
                        {n.notes.map((x) => (
                          <div key={x} className="mt-0.5 text-faint">
                            {x}
                          </div>
                        ))}
                      </div>
                    ))
                ) : (
                  <Disclosed>
                    The replan node did not run: no evidence gap was worth a second pass.
                  </Disclosed>
                )}
              </CardBody>
            </Card>
          </Section>

          <Section
            id="impact"
            title="6 · Impact"
            subtitle="reachability, counterfactual containment, patch queue"
            registerRef={registerRef}
          >
            <div className="space-y-4">
              {/* Where the attack goes next, before the containment that stops it. */}
              <Progression forecast={result.impact.progression_forecast} />
              <TwinPanel
                graph={graph}
                counterfactual={result.impact.counterfactual}
                candidates={
                  candidates.length ? candidates : result.impact.containment_candidates
                }
              />
              <VulnPanel vulns={result.impact.vulnerabilities} />
            </div>
          </Section>

          <Section
            id="action"
            title="7 · Action"
            subtitle="simulated, gated, recorded"
            registerRef={registerRef}
          >
            <div className="space-y-4">
              <ActionPanel
                action={result.action}
                incidentId={inc.incident_id}
                techniqueIds={inc.technique_ids}
                evidence={result.evidence.citations}
                affected={graph.critical_assets_at_risk}
                onDecided={() => setAuditKey((k) => k + 1)}
              />
              <AuditPanel refreshKey={auditKey} onReset={() => setAuditKey((k) => k + 1)} />
            </div>
          </Section>

          </div>
        </div>
      ) : null}

      {!result && !running && !runError ? (
        <Card className="mt-4">
          {meta ? (
            <EmptyState
              icon={Search}
              title={`Pick a scenario and press Run — currently ${meta.label}`}
              detail={meta.description || 'The backend ships no description for this scenario.'}
              action={
                <span className="font-mono text-xs text-faint">
                  {meta.n_events != null ? (
                    `${meta.n_events.toLocaleString()} events`
                  ) : (
                    <NotMeasured why="The backend could not count the rows in this log." />
                  )}
                  {meta.critical_default.length
                    ? ` · crown jewels ${meta.critical_default.join(', ')}`
                    : ' · no crown jewels designated'}
                </span>
              }
            />
          ) : (
            <EmptyState
              icon={Search}
              title="No scenarios available"
              detail="The backend returned an empty scenario list. Nothing is substituted for it."
            />
          )}
        </Card>
      ) : null}
    </>
  )
}

/** The Markov lane's ranked next techniques. Predicted, never observed. */
function PredictedNext({ report }: { report: IncidentReportData }) {
  const preds = report.predicted_next ?? []

  if (!preds.length) {
    return (
      <p className="text-xs text-faint">
        No prediction: no technique has been observed yet, so there is no chain to roll forward.
      </p>
    )
  }

  return (
    <ol className="space-y-1">
      {preds.map((p, i) => (
        <li key={p.technique_id} className="flex items-baseline gap-2 text-sm">
          <span className="w-4 shrink-0 font-mono text-xs tabular-nums text-faint">{i + 1}</span>
          <span className="text-text">{techniqueName(p.technique_id, p.name)}</span>
        </li>
      ))}
    </ol>
  )
}
