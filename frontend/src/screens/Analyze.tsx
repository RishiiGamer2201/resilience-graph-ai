/**
 * Analyze — run the pipeline on a shipped scenario or on your own CSV.
 *
 * Two streaming paths, both real Server-Sent Events endpoints, both ending in a
 * `done` frame carrying the full analysis bundle:
 *
 *   /api/agents/stream   the 10-agent lane, one `progress` frame per agent,
 *                        each carrying the agent's own measured ms and its
 *                        self-reported confidence.
 *   /api/analyze/stream  the deterministic lane replaying each event's real
 *                        score, one `step` frame at a time.
 *   /api/agents/stream/upload
 *                        the same 10-agent lane over a file you supply. A POST,
 *                        because an uploaded CSV cannot be a query string.
 *
 * The stage progression IS the animation on this screen: a stage advancing is a
 * state change, which is the one thing motion is for here. Reduced motion drops
 * the transition and keeps every number.
 *
 * Nothing is hardcoded. Scenario names, event counts, agent names, timings and
 * confidences all come off the wire. A confidence the backend did not send
 * renders as "Not measured", never as 100%.
 */
import * as React from 'react'
import { useNavigate } from 'react-router-dom'
import {
  ArrowRight,
  Bot,
  CheckCircle2,
  Cpu,
  FlaskConical,
  Play,
  Upload,
  X,
} from 'lucide-react'
import { AnimatePresence, motion, useReducedMotion } from 'motion/react'
import { techniqueList } from '@/lib/techniques'

import {
  agentStreamUploadInit,
  agentStreamUploadUrl,
  agentStreamUrl,
  getScenarios,
  readEventStream,
  streamUrl,
} from '@/lib/api'
import { useFetch } from '@/hooks/useFetch'
import { useAnalysis } from '@/providers/analysis'
import { DURATION, EASE, fadeUp } from '@/lib/motion'

import { PageHeader } from '@/components/Layout'
import { Card, CardBody, CardHeader, CardMeta, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { SkeletonRows } from '@/components/ui/skeleton'
import {
  EmptyState,
  ErrorState,
  NotMeasured,
  SectionLabel,
  SeverityBadge,
} from '@/components/primitives'
import { FinePrint } from '@/components/Disclosure'

import type {
  AgentProgress,
  AnalysisBundle,
  AnalyzeStreamStep,
  Scenario,
  ScenarioList,
} from '@/types/api'

type Lane = 'agents' | 'events'

/** One completed stage of whichever lane is running. Both lanes are normalised
 *  to this so the progression renders once. `ms` and `confidence` are null when
 *  the backend did not send them — they are never defaulted to a number. */
interface Stage {
  key: string
  index: number
  total: number
  name: string
  detail: string
  ms: number | null
  confidence: number | null
}

const asAgentProgress = (v: unknown): AgentProgress | null => {
  if (typeof v !== 'object' || v === null) return null
  const o = v as Record<string, unknown>
  return typeof o.name === 'string' && typeof o.stage_num === 'number'
    ? (v as AgentProgress)
    : null
}

const asStreamStep = (v: unknown): AnalyzeStreamStep | null => {
  if (typeof v !== 'object' || v === null) return null
  const o = v as Record<string, unknown>
  return typeof o.i === 'number' && typeof o.total === 'number'
    ? (v as AnalyzeStreamStep)
    : null
}

const num = (v: unknown): number | null =>
  typeof v === 'number' && Number.isFinite(v) ? v : null

export default function Analyze() {
  const navigate = useNavigate()
  const { setBundle } = useAnalysis()
  const reduced = useReducedMotion()
  const scenarios = useFetch<ScenarioList>(getScenarios)

  const [crit, setCrit] = React.useState<string[]>([])
  const [draft, setDraft] = React.useState('')
  const [file, setFile] = React.useState<File | null>(null)

  const [lane, setLane] = React.useState<Lane | null>(null)
  const [busy, setBusy] = React.useState(false)
  const [error, setError] = React.useState<unknown>(null)
  const [status, setStatus] = React.useState('')
  const [stages, setStages] = React.useState<Stage[]>([])
  const [current, setCurrent] = React.useState<Stage | null>(null)
  const [done, setDone] = React.useState<AnalysisBundle | null>(null)
  const streamController = React.useRef<AbortController | null>(null)

  React.useEffect(
    () => () => {
      streamController.current?.abort()
    },
    [],
  )

  function addCrit(v: string) {
    const t = v.trim()
    if (t && !crit.includes(t)) setCrit((c) => [...c, t])
    setDraft('')
  }

  function reset(which: Lane, label: string) {
    streamController.current?.abort()
    setLane(which)
    setBusy(true)
    setError(null)
    setStatus(label)
    setStages([])
    setCurrent(null)
    setDone(null)
  }

  /** Both lanes share this: open the stream, normalise its progress frames into
   *  Stage, and land the `done` bundle. */
  function open(
    url: string,
    which: Lane,
    progressEvent: string,
    toStage: (d: unknown) => Stage | null,
    init?: { method?: string; body?: BodyInit },
  ) {
    const controller = new AbortController()
    streamController.current = controller
    let completed = false
    void readEventStream(
      url,
      (event, raw) => {
        if (event === progressEvent) {
          let parsed: unknown
          try {
            parsed = JSON.parse(raw)
          } catch {
            setError(new Error('The stream sent a frame this client could not parse.'))
            return
          }
          const stage = toStage(parsed)
          if (!stage) return
          setCurrent(stage)
          setStages((previous) => which === 'events' ? [stage] : [...previous, stage])
        }
        if (event === 'done') {
          const bundle = JSON.parse(raw) as AnalysisBundle
          if (!bundle.analysis) throw new Error('The completed stream omitted its analysis layer.')
          setBundle(bundle)
          setDone(bundle)
          setStatus('Pipeline complete. The bundle is loaded into the console.')
          completed = true
        }
      },
      controller.signal,
      init,
    ).then(() => {
      if (!completed) throw new Error('The stream closed before returning a completed analysis.')
    }).catch((cause: unknown) => {
      if (!controller.signal.aborted) {
        setError(cause instanceof Error ? cause : new Error(`The connection to ${url} failed.`))
      }
    }).finally(() => {
      if (streamController.current === controller) streamController.current = null
      setBusy(false)
      setCurrent(null)
    })
  }

  /** One mapper, because both agent lanes emit the same `progress` frame. It
   *  was inline in the scenario lane, which is part of why the upload lane
   *  never grew one. */
  const agentStage = (d: unknown): Stage | null => {
    const p = asAgentProgress(d)
    if (!p) return null
    return {
      key: `${p.stage_num}-${p.agent}`,
      index: p.stage_num,
      total: p.total_stages,
      name: p.name,
      detail: p.summary,
      ms: num(p.ms),
      confidence: num(p.confidence),
    }
  }

  function runAgents(s: Scenario) {
    const critical = crit.length ? crit : s.critical_default
    reset('agents', `Running the 10-agent pipeline on ${s.label}`)
    open(agentStreamUrl(s.name, critical), 'agents', 'progress', agentStage)
  }

  function runEvents(s: Scenario) {
    const critical = crit.length ? crit : s.critical_default
    reset('events', `Replaying scored events from ${s.label}`)
    open(streamUrl(s.name, critical), 'events', 'step', (d) => {
      const st = asStreamStep(d)
      if (!st) return null
      const row = st.step
      return {
        key: `step-${st.i}`,
        index: st.i + 1,
        total: st.total,
        name: `Event ${st.i + 1} of ${st.total}`,
        detail: [row.user, row.source_host, row.destination_host]
          .filter(Boolean)
          .join(' → '),
        ms: null,
        confidence: null,
      }
    })
  }

  function runUpload() {
    if (!file) return
    reset('agents', `Running the 10-agent pipeline on ${file.name}`)
    open(
      agentStreamUploadUrl(),
      'agents',
      'progress',
      agentStage,
      agentStreamUploadInit(file, crit),
    )
  }

  const progress = current && current.total ? current.index / current.total : done ? 1 : 0
  const list = scenarios.data?.scenarios ?? []

  const header = (
    <PageHeader
      eyebrow="Check security activity"
      title="Analyze a security log"
      description="Choose a sample or upload a CSV file. The app checks each event, groups related warnings, and explains the attacker behaviors it finds."
      actions={done?.incident ? <SeverityBadge severity={done.incident.severity} /> : null}
    />
  )

  return (
    <>
      {header}

      {/* ── Execution monitor ────────────────────────────────────────────── */}
      {busy || stages.length > 0 || done || error ? (
        <Card className={`mb-4 ${busy ? 'border-accent/50' : ''}`}>
          <CardHeader className="flex-wrap">
            <div className="flex min-w-0 items-baseline gap-3">
              <CardTitle>
                {lane === 'events' ? 'Scored event replay' : '10-agent execution pipeline'}
              </CardTitle>
              <CardMeta>
                {busy ? 'running' : done ? 'complete' : error ? 'failed' : ''}
              </CardMeta>
            </div>
            {done ? (
              <Button size="sm" onClick={() => navigate('/overview')}>
                Open command center <ArrowRight className="size-3" aria-hidden />
              </Button>
            ) : null}
          </CardHeader>

          {/* The stage bar. This is the animated state transition. */}
          <div className="h-0.5 w-full bg-surface-2">
            <motion.div
              className="h-full bg-accent"
              initial={reduced ? false : { width: 0 }}
              animate={{ width: `${Math.round(progress * 100)}%` }}
              transition={{ duration: reduced ? 0 : DURATION.base, ease: EASE }}
            />
          </div>

          <CardBody className="space-y-3">
            <div className="sr-only" role="status" aria-live="polite">
              {busy ? status : done ? 'Analysis complete' : ''}
            </div>

            {error ? <ErrorState error={error} /> : null}

            <AnimatePresence mode="wait" initial={false}>
              {busy && current ? (
                <motion.div
                  key={current.key}
                  initial={reduced ? false : 'hidden'}
                  animate="show"
                  exit={reduced ? undefined : 'hidden'}
                  variants={fadeUp}
                  className="flex items-center justify-between gap-3 rounded-md border-l-2 border-accent bg-surface-2 px-3 py-2"
                >
                  <div className="flex min-w-0 items-center gap-2.5">
                    <Cpu className="size-4 shrink-0 text-accent" aria-hidden />
                    <div className="min-w-0">
                      <div className="truncate text-sm font-medium text-text">{current.name}</div>
                      <div className="truncate font-mono text-xs text-faint">
                        {current.detail || status}
                      </div>
                    </div>
                  </div>
                  <Badge variant="accent">
                    {current.index}/{current.total}
                  </Badge>
                </motion.div>
              ) : null}
            </AnimatePresence>

            {stages.length ? (
              <ol className="max-h-80 space-y-1.5 overflow-y-auto">
                {stages.map((s) => (
                  <li
                    key={s.key}
                    className="flex items-center justify-between gap-3 rounded-md border-l-2 border-ok/60 bg-surface-2 px-3 py-1.5"
                  >
                    <div className="flex min-w-0 items-center gap-2">
                      <CheckCircle2 className="size-3.5 shrink-0 text-ok" aria-hidden />
                      <span className="truncate text-xs">
                        <span className="font-medium text-text">{s.name}</span>
                        {s.detail ? <span className="text-dim">: {s.detail}</span> : null}
                      </span>
                    </div>
                    <span className="shrink-0 font-mono text-xs text-faint">
                      {s.ms != null ? `${s.ms} ms` : null}
                      {s.ms != null && s.confidence != null ? ' · ' : null}
                      {s.confidence != null ? (
                        `conf ${s.confidence}`
                      ) : s.ms == null ? (
                        <NotMeasured why="This lane does not report a per-stage confidence." />
                      ) : null}
                    </span>
                  </li>
                ))}
              </ol>
            ) : null}

            {done ? (
              <div className="rounded-md border border-accent/40 bg-accent-soft px-3 py-2.5">
                <div className="text-sm font-medium text-accent">Analysis complete</div>
                <div className="mt-1 grid gap-x-6 gap-y-0.5 font-mono text-xs text-dim sm:grid-cols-2">
                  <span>
                    incident {done.incident?.incident_id ?? 'not reported'} · severity{' '}
                    {done.incident?.severity ?? 'not reported'}
                  </span>
                  <span>
                    {done.incident?.event_count != null ? done.incident.event_count.toLocaleString() : <NotMeasured />} events ·{' '}
                    {done.incident?.alert_count != null ? done.incident.alert_count : <NotMeasured />} alerts
                  </span>
                  <span>
                    attacker behaviors: {techniqueList(done.incident?.technique_ids)}
                  </span>
                  <span>
                    blast radius{' '}
                    {done.graph?.blast_radius_size != null
                      ? `${done.graph.blast_radius_size} hosts`
                      : 'not measured'}
                  </span>
                </div>
                <FinePrint className="mt-1.5">
                  Every figure above is the bundle&apos;s own. The full assessment, claims and
                  proposed response are on the command center and the investigation screen.
                </FinePrint>
              </div>
            ) : null}
          </CardBody>
        </Card>
      ) : null}

      {/* ── Inputs ───────────────────────────────────────────────────────── */}
      <div className="grid gap-4 xl:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Shipped scenarios</CardTitle>
            <CardMeta>
              <Bot className="inline size-3" aria-hidden /> two lanes, one bundle
            </CardMeta>
          </CardHeader>
          <CardBody className="space-y-3">
            {scenarios.loading ? <SkeletonRows rows={3} /> : null}
            {scenarios.error ? (
              <ErrorState error={scenarios.error} retry={scenarios.reload} />
            ) : null}
            {!scenarios.loading && !scenarios.error && !list.length ? (
              <EmptyState
                icon={FlaskConical}
                title="No scenarios shipped with this build"
                detail="The backend returned an empty list. Upload a CSV instead — nothing is substituted here."
              />
            ) : null}

            {list.map((s) => (
              <div
                key={s.name}
                className="flex flex-wrap items-start gap-3 rounded-md border border-border bg-surface-2 p-3"
              >
                <FlaskConical className="mt-0.5 size-4 shrink-0 text-accent" aria-hidden />
                <div className="min-w-52 flex-1">
                  <div className="text-sm font-medium text-text">{s.label}</div>
                  <div className="mt-0.5 text-xs text-dim">
                    {s.description || 'No description shipped for this scenario.'}
                  </div>
                  <div className="mt-1 font-mono text-xs text-faint">
                    {s.n_events != null ? (
                      `${s.n_events.toLocaleString()} events`
                    ) : (
                      <NotMeasured why="The backend could not count the rows in this log." />
                    )}
                    {s.critical_default.length
                      ? ` · crown jewels ${s.critical_default.join(', ')}`
                      : ' · no crown jewels designated'}
                  </div>
                </div>
                <div className="flex shrink-0 flex-col gap-1.5">
                  <Button size="sm" disabled={busy} onClick={() => runAgents(s)}>
                    <Play className="size-3" aria-hidden /> Agent lane
                  </Button>
                  <Button size="sm" variant="outline" disabled={busy} onClick={() => runEvents(s)}>
                    <Play className="size-3" aria-hidden /> Event replay
                  </Button>
                </div>
              </div>
            ))}
          </CardBody>
        </Card>

        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Upload your own log</CardTitle>
              <CardMeta>CSV · common event schema</CardMeta>
            </CardHeader>
            <CardBody className="space-y-3">
              <p className="text-xs leading-relaxed text-dim">
                Columns:{' '}
                <span className="font-mono text-text">
                  timestamp, user, source_host, destination_host, status, protocol
                </span>{' '}
                (extras ignored). Max 50k rows.
              </p>
              <p className="text-xs leading-relaxed text-dim">
                No file handy? The build ships a synthetic{' '}
                <a
                  href="/sample_bank_incident.csv"
                  download
                  className="text-accent underline-offset-4 hover:underline"
                >
                  sample incident CSV
                </a>{' '}
                — a fictional estate, unrelated to any shipped scenario, that shows the pipeline
                analysing whatever it is given. Its crown jewels are whichever hosts you
                designate below.
              </p>
              <label className="inline-flex h-8 w-fit cursor-pointer items-center gap-2 rounded-md border border-border bg-transparent px-3 text-sm text-text hover:bg-surface-2 focus-within:outline-2 focus-within:outline-offset-2 focus-within:outline-accent">
                <Upload className="size-3" aria-hidden />
                {file ? file.name : 'Choose CSV'}
                <input
                  type="file"
                  accept=".csv"
                  className="sr-only"
                  onChange={(e) => setFile(e.target.files?.[0] ?? null)}
                />
              </label>
              <Button className="w-fit" disabled={busy || !file} onClick={runUpload}>
                {busy && lane === 'agents' && !stages.length ? status : 'Analyze upload'}
              </Button>
              <FinePrint>
                Your file runs the same ten-agent pipeline as the shipped scenarios, and
                streams the same per-agent trace while it does.
              </FinePrint>
            </CardBody>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Crown jewels</CardTitle>
              <CardMeta>optional · hosts to protect</CardMeta>
            </CardHeader>
            <CardBody className="space-y-3">
              <div className="flex flex-wrap items-center gap-1.5">
                {crit.map((id) => (
                  <span
                    key={id}
                    className="inline-flex items-center gap-1 rounded-full border border-border bg-surface-2 px-2 py-0.5 font-mono text-xs text-text"
                  >
                    {id}
                    <button
                      type="button"
                      onClick={() => setCrit((c) => c.filter((x) => x !== id))}
                      aria-label={`Remove ${id}`}
                      className="text-faint hover:text-sev-critical"
                    >
                      <X className="size-3" aria-hidden />
                    </button>
                  </span>
                ))}
                {!crit.length ? (
                  <span className="text-xs text-faint">
                    None added — each scenario&apos;s own default is used.
                  </span>
                ) : null}
              </div>
              <form
                className="flex items-center gap-2"
                onSubmit={(e) => {
                  e.preventDefault()
                  addCrit(draft)
                }}
              >
                <label className="sr-only" htmlFor="crown-jewel">
                  Add a crown-jewel host
                </label>
                <input
                  id="crown-jewel"
                  value={draft}
                  onChange={(e) => setDraft(e.target.value)}
                  placeholder="host name"
                  className="h-8 min-w-0 flex-1 rounded-md border border-border bg-surface-2 px-2.5 font-mono text-sm text-text placeholder:font-sans placeholder:text-faint"
                />
                <Button type="submit" size="sm" variant="outline">
                  Add
                </Button>
              </form>
              <SectionLabel>Why this matters</SectionLabel>
              <FinePrint>
                Designated hosts get shortest-path analysis in the attack graph, and the response
                gate escalates to named human approval when one of them is at risk.
              </FinePrint>
            </CardBody>
          </Card>
        </div>
      </div>
    </>
  )
}
