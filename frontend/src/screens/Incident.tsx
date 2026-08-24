/**
 * Live incident - the correlated chain, in the order the events happened.
 *
 * `GET /api/incident` is the whole of the left-hand side; `GET /api/scenarios`
 * feeds the replay picker and `GET /api/analyze/stream` re-scores a shipped
 * scenario event by event over SSE. `IncidentReport` adds `GET /api/report`.
 *
 * The old screen carried a paragraph headed "What this means" that asserted the
 * account "appears to reuse stolen authentication material" - a sentence no
 * analysis produced. It is not ported. The backend writes its own summary and
 * that summary is in the report card below.
 */
import { useEffect, useRef, useState } from 'react'
import { Activity, Radio, Play, Users } from 'lucide-react'
import { getIncident, getScenarios, readEventStream, streamUrl } from '@/lib/api'
import { useFetch } from '@/hooks/useFetch'
import { useAnalysis, useScreenData } from '@/providers/analysis'
import { fmtTime, severityFromStep } from '@/lib/format'
import { PageHeader } from '@/components/Layout'
import BaselineLearningBanner from '@/components/BaselineLearningBanner'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Card, CardBody, CardHeader, CardMeta, CardTitle } from '@/components/ui/card'
import { SkeletonRows } from '@/components/ui/skeleton'
import {
  EmptyState,
  ErrorState,
  MetricCard,
  NotMeasured,
  RevealList,
  SeverityBadge,
  StatRow,
} from '@/components/primitives'
import IncidentReport from '@/components/IncidentReport'
import LiveScoreWidget from '@/components/LiveScoreWidget'
import type {
  AnalysisBundle,
  Incident as IncidentData,
  IncidentStep,
  ScenarioList,
} from '@/types/api'
import { techniqueName as mitreTechniqueName } from '@/lib/techniques'

const REPLAY_MS = 180

function prefersReducedMotion(): boolean {
  return (
    typeof window !== 'undefined' &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches
  )
}

/** The stream's terminal frame is the same full bundle returned by /api/analyze.
 * Validate the fields this route and the shared analysis store require before
 * replacing the current incident. */
function parseAnalysisBundle(raw: string): AnalysisBundle {
  const value: unknown = JSON.parse(raw)
  if (typeof value !== 'object' || value === null) {
    throw new Error('The completed stream did not return an analysis bundle.')
  }

  const candidate = value as Record<string, unknown>
  const incident = candidate.incident
  if (
    typeof incident !== 'object' ||
    incident === null ||
    typeof (incident as Record<string, unknown>).incident_id !== 'string' ||
    !Array.isArray((incident as Record<string, unknown>).steps) ||
    typeof candidate.graph !== 'object' ||
    candidate.graph === null
  ) {
    throw new Error('The completed stream omitted its incident or graph layer.')
  }

  return value as AnalysisBundle
}

export default function Incident() {
  const { bundle, setBundle, source: bundleSource } = useAnalysis()
  const { data: fetchedData, error, loading, reload, source } = useScreenData<IncidentData>(
    bundle?.incident,
    getIncident,
    bundleSource,
  )
  // Prefer the provider value immediately after an SSE completion. The screen
  // data hook synchronises in an effect, so reading only its state would leave
  // one render where streamed rows belong to the new scenario while the header,
  // ATT&CK summary and report still describe the old cached incident.
  const data = bundle?.incident ?? fetchedData
  const { data: scenarioList } = useFetch<ScenarioList>(getScenarios)

  const [visible, setVisible] = useState<number | null>(null) // null = show all
  const [replaying, setReplaying] = useState(false)
  const [streamSteps, setStreamSteps] = useState<IncidentStep[] | null>(null)
  const [streaming, setStreaming] = useState(false)
  const [streamError, setStreamError] = useState<string | null>(null)
  const [announcement, setAnnouncement] = useState('')
  const [scenario, setScenario] = useState('')

  const timer = useRef<number | null>(null)
  const streamController = useRef<AbortController | null>(null)

  useEffect(
    () => () => {
      if (timer.current) window.clearInterval(timer.current)
      streamController.current?.abort()
    },
    [],
  )

  const steps = data?.steps ?? []

  function replay() {
    if (timer.current) window.clearInterval(timer.current)
    setStreamSteps(null)
    if (prefersReducedMotion()) {
      setVisible(null)
      setReplaying(false)
      setAnnouncement(`Showing all ${steps.length} steps.`)
      return
    }
    setReplaying(true)
    setVisible(0)
    let i = 0
    timer.current = window.setInterval(() => {
      i += 1
      setVisible(i)
      if (i >= steps.length) {
        if (timer.current) window.clearInterval(timer.current)
        setReplaying(false)
        setVisible(null)
        setAnnouncement(`Replay finished: ${steps.length} steps.`)
      }
    }, REPLAY_MS)
  }

  async function streamLive() {
    if (!scenario) return
    if (timer.current) window.clearInterval(timer.current)
    setReplaying(false)
    setVisible(null)
    streamController.current?.abort()
    setStreamSteps([])
    setStreamError(null)
    setStreaming(true)
    setAnnouncement(`Scoring ${scenario} live.`)

    const controller = new AbortController()
    streamController.current = controller
    let completed = false
    try {
      await readEventStream(
        streamUrl(scenario),
        (event, raw) => {
          if (event === 'step') {
            try {
              const payload = JSON.parse(raw) as { step: IncidentStep }
              setStreamSteps((steps) => [...(steps ?? []), payload.step])
            } catch {
              /* malformed progress is never rendered as evidence */
            }
          }
          if (event === 'done') {
            const bundle = parseAnalysisBundle(raw)
            setBundle(bundle)
            setStreamSteps(null)
            setStreamError(null)
            setAnnouncement(`Live scoring complete. Loaded incident ${bundle.incident.incident_id}.`)
            completed = true
          }
        },
        controller.signal,
      )
      if (!completed) throw new Error(`The stream for '${scenario}' closed before it finished.`)
    } catch (error: unknown) {
      if (!controller.signal.aborted) {
        setStreamError(error instanceof Error ? error.message : 'The live stream failed.')
        setAnnouncement('Live scoring failed.')
      }
    } finally {
      if (streamController.current === controller) {
        streamController.current = null
        setStreaming(false)
      }
    }
  }

  if (loading) {
    return (
      <>
        <PageHeader eyebrow="Operations" title="Live incident" />
        <Card>
          <CardBody>
            <SkeletonRows rows={8} />
          </CardBody>
        </Card>
      </>
    )
  }

  if (error || !data) {
    return (
      <>
        <PageHeader eyebrow="Operations" title="Live incident" />
        <Card>
          <ErrorState error={error ?? new Error('no incident')} retry={reload} />
        </Card>
      </>
    )
  }

  const shown =
    streamSteps !== null ? streamSteps : visible === null ? steps : steps.slice(0, visible)
  const scenarios = scenarioList?.scenarios ?? []
  const techniqueName = (id: string) =>
    steps.find((s) => s.technique_id === id)?.technique ?? null

  return (
    <>
      <PageHeader
        eyebrow="Event timeline"
        title="How the incident developed"
        description="Follow related attack events in time order."
        actions={
          <>
            <Badge variant={source === 'live' ? 'accent' : 'outline'}>
              {source === 'live' ? 'live analysis' : source === 'restored' ? 'restored session' : 'sample cache'}
            </Badge>
            <span className="font-mono text-xs text-faint">{data.incident_id}</span>
            <SeverityBadge severity={data.severity} />
          </>
        }
      />

      <BaselineLearningBanner baseline={bundle?.meta?.baseline} />

      {/* Analysis completion is announced, not just drawn. */}
      <div aria-live="polite" className="sr-only">
        {announcement}
      </div>

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCard
          label="Severity"
          value={data.severity}
          context={data.incident_id}
          severity={data.severity}
        />
        <MetricCard
          label="Alerts correlated"
          value={data.alert_count.toLocaleString()}
          unit="alerts"
          context={`from ${data.event_count.toLocaleString()} raw events`}
        />
        <MetricCard
          label="Peak anomaly score"
          value={
            typeof data.max_anomaly_score === 'number' ? (
              data.max_anomaly_score
            ) : (
              <NotMeasured />
            )
          }
          unit="/100"
          context="Highest score any single event in the chain reached."
        />
        <MetricCard
          label="Accounts involved"
          value={data.accounts_involved?.length ?? 0}
          context={data.is_campaign ? 'Correlated as one campaign.' : 'Single-account incident.'}
        />
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader>
            <CardTitle>Correlated attack chain</CardTitle>
            <div className="flex items-center gap-2">
              <CardMeta>
                {streamSteps !== null
                  ? `${shown.length} streamed`
                  : `${shown.length} of ${data.steps_total?.toLocaleString() ?? steps.length} steps`}
              </CardMeta>
              <Button
                variant="secondary"
                size="sm"
                disabled={replaying || streaming || !steps.length}
                onClick={replay}
              >
                <Play className="size-3.5" />
                {replaying ? 'Replaying…' : 'Replay'}
              </Button>
            </div>
          </CardHeader>

          <div className="flex flex-wrap items-center gap-2 border-b border-border bg-surface-2 px-4 py-2">
            <label htmlFor="scenario" className="text-xs text-dim">
              Re-score a shipped log live
            </label>
            <select
              id="scenario"
              value={scenario}
              onChange={(e) => setScenario(e.target.value)}
              disabled={streaming || !scenarios.length}
              className="rounded-md border border-border bg-surface px-2 py-1 font-mono text-xs text-text"
            >
              <option value="">
                {scenarios.length ? 'select a scenario' : 'no scenarios available'}
              </option>
              {scenarios.map((s) => (
                <option key={s.name} value={s.name}>
                  {s.label}
                  {s.n_events != null ? ` · ${s.n_events.toLocaleString()} events` : ''}
                </option>
              ))}
            </select>
            <Button
              variant="secondary"
              size="sm"
              disabled={streaming || !scenario}
              onClick={streamLive}
            >
              <Radio className="size-3.5" />
              {streaming ? 'Streaming…' : 'Stream live'}
            </Button>
            {streamSteps !== null ? (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => {
                  streamController.current?.abort()
                  streamController.current = null
                  setStreaming(false)
                  setStreamSteps(null)
                  setStreamError(null)
                  setAnnouncement('Live scoring cancelled. Showing the current incident.')
                }}
              >
                Cancel stream
              </Button>
            ) : null}
          </div>

          {streamError ? (
            <p className="border-b border-border px-4 py-2 text-xs text-sev-high">
              {streamError}
            </p>
          ) : null}

          {shown.length ? (
            <div className="max-h-[560px] overflow-y-auto">
              <RevealList>
                {shown.map((step, i) => (
                  <StepRow key={`${String(step.timestamp)}-${i}`} step={step} />
                ))}
              </RevealList>
            </div>
          ) : (
            <EmptyState
              title={streaming ? 'Waiting for the first scored event' : 'No steps on this incident'}
              detail={
                streaming
                  ? 'The backend scores the log up front and paces the reveal; the first event should arrive shortly.'
                  : 'The correlated chain the backend returned is empty.'
              }
              icon={Activity}
            />
          )}

          {data.steps_total != null && data.steps_shown != null && data.steps_total > data.steps_shown ? (
            <div className="border-t border-border px-4 py-2 text-xs text-faint">
              The API returns {data.steps_shown.toLocaleString()} of{' '}
              {data.steps_total.toLocaleString()} correlated steps. The remainder is not
              withheld as a summary - it is simply not in this response.
            </div>
          ) : null}
        </Card>

        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>ATT&amp;CK chain</CardTitle>
              <CardMeta>observed order</CardMeta>
            </CardHeader>
            <CardBody>
              {data.technique_ids?.length ? (
                <div className="space-y-1.5">
                  {data.technique_ids.map((t) => (
                    <div key={t} className="flex items-baseline gap-2">
                      <span className="rounded-md border border-border bg-surface-2 px-2 py-0.5 text-xs text-text">
                        {mitreTechniqueName(t, techniqueName(t))}
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <EmptyState
                  title="No technique mapped"
                  detail="No alerting event in this incident matched a mapping rule."
                />
              )}
            </CardBody>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Technical reference</CardTitle>
              <CardMeta>
                <Users className="inline size-3" /> {data.accounts_involved?.length ?? 0}
              </CardMeta>
            </CardHeader>
            <CardBody className="space-y-1">
              <StatRow label="Account">
                {data.account ?? (
                  <NotMeasured why="This incident spans more accounts than one label can carry." />
                )}
              </StatRow>
              <StatRow label="Investigation pivot">
                {typeof data.pivot === 'string' ? (
                  data.pivot
                ) : (
                  <NotMeasured why="No single host was chosen as the pivot." />
                )}
              </StatRow>
              <StatRow label="Correlated as">
                {data.is_campaign ? 'campaign' : 'single incident'}
              </StatRow>
              <StatRow label="Users involved">
                {data.users_involved?.length ?? data.accounts_involved?.length ?? (
                  <NotMeasured />
                )}
              </StatRow>
            </CardBody>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Live event scoring</CardTitle>
              <CardMeta>POST /score-event</CardMeta>
            </CardHeader>
            <LiveScoreWidget />
          </Card>
        </div>
      </div>

      <IncidentReport />
    </>
  )
}

function StepRow({ step }: { step: IncidentStep }) {
  const sev = severityFromStep(step)
  const tid = step.technique_id && step.technique_id !== '-' ? step.technique_id : null
  const spine =
    sev === 'critical'
      ? 'bg-sev-critical'
      : sev === 'high'
        ? 'bg-sev-high'
        : sev === 'medium'
          ? 'bg-sev-medium'
          : sev === 'low'
            ? 'bg-sev-low'
            : 'bg-sev-normal'

  return (
    <div className="relative flex items-start gap-3 border-b border-border py-2 pl-4 pr-4 last:border-0">
      <span className={`absolute left-0 top-0 h-full w-[3px] ${spine}`} aria-hidden />
      <span className="w-16 shrink-0 font-mono text-xs tabular-nums text-faint">
        {fmtTime(typeof step.timestamp === 'number' ? step.timestamp : undefined)}
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-baseline gap-x-2 font-mono text-xs">
          <span className="text-text">{step.user ?? 'Not available'}</span>
          <span className="text-faint">
            {step.source_host ?? 'Not available'} → {step.destination_host ?? 'Not available'}
          </span>
          {step.is_alert ? (
            <span className="rounded-full border border-sev-high/40 bg-sev-high/10 px-1.5 text-xs text-sev-high">
              alert
            </span>
          ) : null}
        </div>
        <div className="mt-0.5 flex flex-wrap items-baseline gap-x-2 text-xs">
          <span className="text-dim">{step.tactic ?? 'unmapped'}</span>
          {tid ? <span className="text-faint">{mitreTechniqueName(tid, step.technique)}</span> : null}
        </div>
        {typeof step.explanation === 'string' && step.explanation ? (
          <p className="mt-0.5 line-clamp-2 text-xs text-faint">{step.explanation}</p>
        ) : null}
      </div>
      <div className="shrink-0 text-right">
        <div className="font-mono text-sm tabular-nums text-text">
          {typeof step.anomaly_score === 'number' ? step.anomaly_score : <NotMeasured />}
        </div>
        <SeverityBadge severity={sev} />
      </div>
    </div>
  )
}
