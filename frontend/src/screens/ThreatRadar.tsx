/**
 * Threat Radar - external CTI, cross-referenced against the open incident.
 *
 * POST /api/threat-radar. The backend fetches the free feeds live when asked
 * and falls back to the snapshot bundled at build time if nothing answers. It
 * reports which in `meta.source`, and this screen never lets a snapshot pass
 * for live: the badge reads from that field alone, and a refresh that produced
 * no live source says so in words.
 *
 * Sources the backend could not reach - usually an optional free API key that
 * is not set - are listed as skipped with the reason. Dropping them would make
 * a two-feed radar look like a seven-feed one.
 *
 * Scoring is server-side (src/shared/osint.relevance) and reported as three
 * separate signals: exact technique overlap, same ATT&CK tactic, and a named
 * attributed actor. A tactic-only hit is never dressed up as a technique hit.
 *
 * Sector alerts are simulated and human-gated. Nothing is dispatched anywhere.
 */
import * as React from 'react'
import { Link } from 'react-router-dom'
import {
  Check,
  Crosshair,
  ExternalLink,
  RefreshCw,
  ShieldAlert,
  Siren,
  Waypoints,
  X,
} from 'lucide-react'
import { getGraph, getIncident, getThreatIntel, getThreatRadar } from '@/lib/api'
import { useFetch } from '@/hooks/useFetch'
import { useAnalysis, useScreenData } from '@/providers/analysis'
import { PageHeader } from '@/components/Layout'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardBody, CardFooter, CardHeader, CardMeta, CardTitle } from '@/components/ui/card'
import { SkeletonRows } from '@/components/ui/skeleton'
import { EmptyState, ErrorState, SectionLabel } from '@/components/primitives'
import { cn } from '@/lib/utils'
import { techniqueList, techniqueName } from '@/lib/techniques'
import type {
  AttackGraph,
  ExposureMove,
  GraphEdge,
  Incident,
  RadarItem,
  RadarRelevance,
  RadarSourceStatus,
  ThreatIntelView,
  ThreatRadarPayload,
} from '@/types/api'

const EMPTY_RELEVANCE: RadarRelevance = {
  score: 0,
  matched_techniques: [],
  matched_tactics: [],
  matched_actors: [],
}

/** Same wall clock as the rest of the product (src/shared/timeutil.fmt_ist). */
const nowIST = () =>
  `${new Date().toLocaleString('en-CA', {
    timeZone: 'Asia/Kolkata',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  })} IST`

/** The distinct techniques behind an item's exposure movements, so the graph
 *  can be deep-linked to exactly those movements. */
function exposureTechniques(item: RadarItem): string[] {
  const bridge = exposureBridge(item).moves
  return [
    ...new Set(
      Object.values(bridge)
        .flat()
        .map((m) => m.technique)
        .filter((t): t is string => Boolean(t)),
    ),
  ]
}

/** Exact-technique exposure if the backend found any, else tactic-level. The
 *  two are different strengths of claim and the caller is told which. */
function exposureBridge(item: RadarItem): {
  moves: Record<string, ExposureMove[]>
  exact: boolean
} {
  const exact = item.your_exposure ?? {}
  if (Object.keys(exact).length) return { moves: exact, exact: true }
  return { moves: item.your_exposure_tactic ?? {}, exact: false }
}

interface QueueEntry {
  item: RadarItem
  relevance: RadarRelevance
  queued_at: string
  decided_at?: string
  status: 'pending' | 'approved' | 'dismissed'
}

/** The advisory a SOC lead would review before anything left the building.
 *  Built from real fields only - no invented impact claim. */
function draftAdvisory(entry: QueueEntry, incidentId: string | undefined): string {
  const r = entry.relevance
  const why = [
    r.matched_techniques.length
      ? `shares attacker behavior(s) ${techniqueList(r.matched_techniques, ', ')}`
      : null,
    !r.matched_techniques.length && r.matched_tactics.length
      ? `shares ATT&CK tactic(s) ${r.matched_tactics.join(', ')}`
      : null,
    r.matched_actors.length ? `names attributed actor ${r.matched_actors.join(', ')}` : null,
  ]
    .filter(Boolean)
    .join('; ')
  return [
    'SECTOR ADVISORY (DRAFT - NOT DISPATCHED)',
    `Source: ${entry.item.source} · ${entry.item.published}`,
    `Report: ${entry.item.title}`,
    `Link: ${entry.item.url}`,
    '',
    `Relevance to ${incidentId || 'the open incident'}: ${why || 'context only'}.`,
    entry.item.techniques.length
      ? `Attacker behaviors in report: ${techniqueList(entry.item.techniques, ', ')}`
      : '',
    '',
    'Recommended action: review your own detections for the technique(s) above.',
    'This advisory is simulated. No recipient is contacted by this system.',
  ].join('\n')
}

/** Every source the backend tried, including the ones it could not. */
function SourceStatus({ sources }: { sources: RadarSourceStatus[] }) {
  const answered = sources.filter((s) => s.ok)
  const skipped = sources.filter((s) => !s.ok)
  return (
    <div className="space-y-2">
      <div>
        <SectionLabel>Answered · {answered.length}</SectionLabel>
        <div className="mt-1 flex flex-wrap gap-1.5">
          {answered.length ? (
            answered.map((s) => (
              <Badge key={s.source} variant="ok">
                {s.source}
                <span className="font-mono">{s.items}</span>
              </Badge>
            ))
          ) : (
            <span className="text-xs text-faint">No source answered.</span>
          )}
        </div>
      </div>
      {skipped.length ? (
        <div>
          <SectionLabel>Skipped · {skipped.length}</SectionLabel>
          <div className="mt-1 space-y-0.5">
            {skipped.map((s) => (
              <div key={s.source} className="flex items-baseline gap-2 text-xs">
                <Badge variant="outline">{s.source}</Badge>
                <span className="font-mono text-faint">
                  {s.note ?? 'unavailable, no reason reported'}
                </span>
              </div>
            ))}
          </div>
        </div>
      ) : null}
    </div>
  )
}

function TechniqueChips({
  item,
  names,
  matched,
}: {
  item: RadarItem
  names: Record<string, string>
  matched: string[]
}) {
  if (!item.techniques.length) return null
  return (
    <div className="mt-1.5 flex flex-wrap gap-1">
      {item.techniques.map((t) => {
        const hit = matched.includes(t)
        return (
          <span
            key={t}
            className={cn(
              'rounded-md border px-1.5 py-0.5 font-mono text-xs',
              hit
                ? 'border-sev-critical/40 bg-sev-critical/10 text-sev-critical'
                : 'border-accent/30 bg-accent-soft text-accent',
            )}
          >
            {techniqueName(t, names[t])}
          </span>
        )
      })}
    </div>
  )
}

function ExposureBlock({ item }: { item: RadarItem }) {
  const { moves, exact } = exposureBridge(item)
  const keys = Object.keys(moves)
  if (!keys.length) return null
  const techs = exposureTechniques(item)
  return (
    <div className="mt-2 border-t border-border pt-2">
      <div className="flex items-center gap-1.5 text-xs font-medium text-text">
        <Crosshair className="size-3 text-sev-high" aria-hidden />
        Where you are exposed - {exact ? 'same technique' : 'same tactic only'} in your
        own incident
      </div>
      {keys.map((key) => (
        <div key={key} className="mt-1">
          <span className="font-mono text-xs text-sev-high">{key}</span>
          <span className="text-xs text-dim"> - {moves[key].length} of your movements</span>
          <div className="mt-1 flex flex-wrap gap-1">
            {moves[key].slice(0, 8).map((m, i) => (
              <span
                key={`${m.from}-${m.to}-${i}`}
                title={`${m.technique ? techniqueName(m.technique) : 'Technique not identified'} · anomaly score ${m.score ?? 'not measured'}`}
                className="rounded-md border border-border bg-surface-2 px-1.5 py-0.5 font-mono text-xs text-dim"
              >
                {m.from}→{m.to}
                {m.event_count > 1 ? ` ×${m.event_count}` : ''}
              </span>
            ))}
            {moves[key].length > 8 ? (
              <span className="rounded-md border border-border bg-surface-2 px-1.5 py-0.5 font-mono text-xs text-faint">
                +{moves[key].length - 8}
              </span>
            ) : null}
          </div>
        </div>
      ))}
      <Button asChild size="sm" variant="outline" className="mt-2">
        <Link to={`/graph?techniques=${encodeURIComponent(techs.join(','))}`}>
          <Waypoints className="size-3" aria-hidden />
          Highlight these in the Attack Graph
        </Link>
      </Button>
    </div>
  )
}

function RadarEntry({
  item,
  names,
  queued,
  onQueue,
}: {
  item: RadarItem
  names: Record<string, string>
  queued: boolean
  onQueue: (item: RadarItem) => void
}) {
  const rel = item.relevance ?? EMPTY_RELEVANCE
  const strong = rel.matched_techniques.length > 0 || rel.matched_actors.length > 0
  const related = rel.score > 0
  return (
    <div
      className={cn(
        'border-l-2 pl-3',
        strong ? 'border-sev-critical' : related ? 'border-sev-high' : 'border-border',
      )}
    >
      <div className="flex flex-wrap items-center gap-1.5">
        <Badge variant="outline">{item.source}</Badge>
        <span className="font-mono text-xs text-faint">{item.published}</span>
        {item.tags?.slice(0, 2).map((t) => (
          <Badge key={t}>{t}</Badge>
        ))}
      </div>

      <a
        href={item.url}
        target="_blank"
        rel="noopener noreferrer"
        className="mt-1 inline-flex items-baseline gap-1.5 text-sm font-medium text-accent underline-offset-4 hover:underline"
      >
        {item.title}
        <ExternalLink className="size-3 shrink-0" aria-hidden />
      </a>

      {item.text ? (
        <p className="mt-0.5 text-xs leading-relaxed text-dim">{item.text.slice(0, 180)}</p>
      ) : null}

      <TechniqueChips item={item} names={names} matched={rel.matched_techniques} />

      {related ? (
        <div className="mt-2 flex flex-wrap items-center gap-2 text-xs text-text">
          <ShieldAlert
            className={cn('size-3', strong ? 'text-sev-critical' : 'text-sev-high')}
            aria-hidden
          />
          <span>
            {rel.matched_techniques.length ? (
              <>
                Same technique as your incident:{' '}
                <span>{techniqueList(rel.matched_techniques, ', ')}</span>.{' '}
              </>
            ) : rel.matched_tactics.length ? (
              <>Same ATT&amp;CK tactic as your incident: {rel.matched_tactics.join(', ')}. </>
            ) : null}
            {rel.matched_actors.length ? (
              <>Mentions attributed actor {rel.matched_actors.join(', ')}. </>
            ) : null}
            <span className="font-mono text-faint">relevance {rel.score.toFixed(3)}</span>
          </span>
          <Button size="sm" variant="secondary" disabled={queued} onClick={() => onQueue(item)}>
            <Siren className="size-3" aria-hidden />
            {queued ? 'queued - see the alert queue' : 'Queue sector alert (simulated)'}
          </Button>
        </div>
      ) : null}

      <ExposureBlock item={item} />
    </div>
  )
}

function QueueEntryCard({
  entry,
  incidentId,
  onDecide,
}: {
  entry: QueueEntry
  incidentId: string | undefined
  onDecide: (url: string, status: 'approved' | 'dismissed') => void
}) {
  const techs = exposureTechniques(entry.item)
  return (
    <div
      className={cn(
        'border-l-2 pl-3',
        entry.status === 'approved'
          ? 'border-sev-medium'
          : entry.status === 'dismissed'
            ? 'border-sev-normal opacity-60'
            : 'border-sev-high',
      )}
    >
      <div className="flex flex-wrap items-center gap-1.5">
        <Badge variant="outline">{entry.item.source}</Badge>
        <Badge variant={entry.status === 'pending' ? 'warn' : 'default'}>
          {entry.status === 'pending'
            ? 'awaiting human approval'
            : entry.status === 'approved'
              ? 'approved · simulated, not dispatched'
              : 'dismissed'}
        </Badge>
        <span className="font-mono text-xs text-faint">
          queued {entry.queued_at}
          {entry.decided_at ? ` · decided ${entry.decided_at}` : ''}
        </span>
      </div>

      <div className="mt-1 text-sm font-medium text-text">{entry.item.title}</div>

      <div className="mt-1 text-xs text-dim">
        Would notify: sector CERT / peer operators (simulated recipient) · Basis:{' '}
        {entry.relevance.matched_techniques.length ? (
          <>
            technique{' '}
            <span>{techniqueList(entry.relevance.matched_techniques, ', ')}</span>
          </>
        ) : entry.relevance.matched_tactics.length ? (
          <>tactic {entry.relevance.matched_tactics.join(', ')}</>
        ) : (
          'context'
        )}
        {entry.relevance.matched_actors.length
          ? ` · actor ${entry.relevance.matched_actors.join(', ')}`
          : ''}
      </div>

      <details className="mt-2">
        <summary className="cursor-pointer text-xs text-accent">View draft advisory</summary>
        <pre className="mt-1.5 whitespace-pre-wrap rounded-md border border-border bg-surface-2 p-2.5 font-mono text-xs text-dim">
          {draftAdvisory(entry, incidentId)}
        </pre>
      </details>

      <div className="mt-2 flex flex-wrap items-center gap-2">
        {entry.status === 'pending' ? (
          <>
            <Button size="sm" onClick={() => onDecide(entry.item.url, 'approved')}>
              <Check className="size-3" aria-hidden />
              Approve (simulated)
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => onDecide(entry.item.url, 'dismissed')}
            >
              <X className="size-3" aria-hidden />
              Dismiss
            </Button>
          </>
        ) : null}
        <Button asChild size="sm" variant="outline">
          <Link to={techs.length ? `/graph?techniques=${encodeURIComponent(techs.join(','))}` : '/graph'}>
            <Waypoints className="size-3" aria-hidden />
            Review your attack path
          </Link>
        </Button>
        <Button asChild size="sm" variant="outline">
          <a href={entry.item.url} target="_blank" rel="noopener noreferrer">
            <ExternalLink className="size-3" aria-hidden />
            Source report
          </a>
        </Button>
      </div>
    </div>
  )
}

/** Mounted only once the incident context has settled, so the radar is asked
 *  for exactly one cross-reference rather than one empty and one real. */
function Radar({
  techniqueIds,
  actors,
  edges,
  incidentId,
  contextNote,
}: {
  techniqueIds: string[]
  actors: string[]
  edges: GraphEdge[]
  incidentId: string | undefined
  contextNote: string | null
}) {
  // Which mode the last request used. A refresh that falls back to the cache
  // has to say so; silence would read as "this is live".
  const wantLive = React.useRef(false)
  const [askedLive, setAskedLive] = React.useState(false)
  const [queue, setQueue] = React.useState<QueueEntry[]>([])
  const requestKey = React.useMemo(
    () => JSON.stringify({ techniqueIds, actors, edges }),
    [techniqueIds, actors, edges],
  )

  const { data, error, loading, reload } = useFetch<ThreatRadarPayload>(() => {
    const refresh = wantLive.current
    return getThreatRadar({
      technique_ids: techniqueIds,
      actors,
      // Only the five fields the exposure bridge reads. The full edge carries
      // an ATT&CK description per row and there is no reason to ship it back.
      edges: edges.map((e) => ({
        technique: e.technique,
        from: e.from,
        to: e.to,
        score: e.score,
        event_count: e.event_count,
      })),
      refresh,
    }).finally(() => {
      if (refresh) wantLive.current = false
    })
  },
    [requestKey],
  )

  const refresh = () => {
    wantLive.current = true
    setAskedLive(true)
    reload()
  }

  const enqueue = (item: RadarItem) =>
    setQueue((q) =>
      q.some((e) => e.item.url === item.url)
        ? q
        : [
            {
              item,
              relevance: item.relevance ?? EMPTY_RELEVANCE,
              queued_at: nowIST(),
              status: 'pending',
            },
            ...q,
          ],
    )

  const decide = (url: string, status: 'approved' | 'dismissed') =>
    setQueue((q) =>
      q.map((e) => (e.item.url === url ? { ...e, status, decided_at: nowIST() } : e)),
    )

  if (loading && !data) {
    return (
      <Card>
        <CardBody>
          <SkeletonRows rows={6} />
        </CardBody>
      </Card>
    )
  }

  if (error || !data) {
    return (
      <Card>
        <ErrorState error={error ?? new Error('no data')} retry={reload} />
      </Card>
    )
  }

  const names = data.technique_names ?? {}
  const sources = data.sources ?? []
  const items = data.items ?? []
  const relevant = items.filter((i) => (i.relevance?.score ?? 0) > 0)
  const rest = items.filter((i) => !((i.relevance?.score ?? 0) > 0))
  const live = data.meta?.source === 'live'
  const pending = queue.filter((e) => e.status === 'pending').length

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle>Feed status</CardTitle>
          <div className="flex items-center gap-2">
            <CardMeta>fetched {data.fetched_at}</CardMeta>
            <Badge variant={live ? 'ok' : 'default'}>
              {live ? 'live fetch' : 'bundled snapshot'}
            </Badge>
            <Button size="sm" variant="secondary" onClick={refresh} disabled={loading}>
              <RefreshCw className={cn('size-3', loading && 'animate-spin')} aria-hidden />
              {loading ? 'Fetching' : 'Refresh (live)'}
            </Button>
          </div>
        </CardHeader>
        <CardBody className="space-y-3">
          {askedLive && !live ? (
            <div className="rounded-md border border-sev-high/40 bg-sev-high/10 px-3 py-2 text-xs text-sev-high">
              A live re-fetch was requested and no source responded. This is the
              snapshot bundled at build time, not current intelligence.
            </div>
          ) : null}
          {contextNote ? (
            <div className="rounded-md border border-border bg-surface-2 px-3 py-2 text-xs text-dim">
              {contextNote}
            </div>
          ) : null}
          <SourceStatus sources={sources} />
          {data.note ? <p className="text-xs leading-relaxed text-faint">{data.note}</p> : null}
        </CardBody>
      </Card>

      <SectionLabel className="mb-1.5 mt-4">
        Relevant to your incident{incidentId ? ` · ${incidentId}` : ''}
      </SectionLabel>
      <Card>
        <CardHeader>
          <CardTitle>Cross-referenced hits</CardTitle>
          <CardMeta>
            {techniqueIds.length
              ? `matching ${techniqueList(techniqueIds, ', ')}${actors.length ? ` · ${actors[0]}` : ''}`
              : 'no incident techniques to match on'}
          </CardMeta>
        </CardHeader>
        {relevant.length ? (
          <CardBody className="space-y-4">
            {relevant.map((i) => (
              <RadarEntry
                key={i.url}
                item={i}
                names={names}
                queued={queue.some((e) => e.item.url === i.url)}
                onQueue={enqueue}
              />
            ))}
          </CardBody>
        ) : (
          <CardBody>
            <p className="text-sm leading-relaxed text-dim">
              <span className="font-medium text-text">
                No current external item matches this incident.
              </span>{' '}
              That is a real result, not a gap. This incident is authentication-based
              {techniqueIds.length ? (
                <>
                  {' '}
                  (<span className="text-xs">{techniqueList(techniqueIds, ', ')}</span>)
                </>
              ) : null}
              , while today&apos;s public feeds are dominated by vulnerability and
              malware reporting. A hit here would mean the outside world is talking
              about the same techniques you are seeing; we show the absence rather
              than manufacture a match.
            </p>
          </CardBody>
        )}
        <CardFooter>
          Alerts are simulated and human-gated - the same policy as the SOAR actions.
          Nothing is dispatched to any real organisation.
        </CardFooter>
      </Card>

      {queue.length ? (
        <>
          <SectionLabel className="mb-1.5 mt-4">
            Alert queue · {pending} awaiting approval
          </SectionLabel>
          <Card>
            <CardHeader>
              <CardTitle>Queued sector alerts</CardTitle>
              <CardMeta>simulated · a SOC lead approves before anything would leave</CardMeta>
            </CardHeader>
            <CardBody className="space-y-4">
              {queue.map((e) => (
                <QueueEntryCard
                  key={e.item.url}
                  entry={e}
                  incidentId={incidentId}
                  onDecide={decide}
                />
              ))}
            </CardBody>
            <CardFooter>
              External intel has no attack path of its own - we hold no telemetry for
              someone else&apos;s breach, and inventing one would be fabrication. The
              path lives with your incident:{' '}
              <Link to="/graph" className="text-accent underline-offset-4 hover:underline">
                Attack Graph
              </Link>{' '}
              ·{' '}
              <Link to="/incident" className="text-accent underline-offset-4 hover:underline">
                Live Incident
              </Link>
              . Approval here is a simulated gate; nothing is transmitted.
            </CardFooter>
          </Card>
        </>
      ) : null}

      <SectionLabel className="mb-1.5 mt-4">
        Everything the radar is watching · {rest.length}
      </SectionLabel>
      <Card>
        <CardHeader>
          <CardTitle>Feed</CardTitle>
          <CardMeta>newest first</CardMeta>
        </CardHeader>
        {rest.length ? (
          <CardBody className="max-h-[620px] space-y-4 overflow-y-auto">
            {rest.map((i) => (
              <RadarEntry
                key={i.url}
                item={i}
                names={names}
                queued={queue.some((e) => e.item.url === i.url)}
                onQueue={enqueue}
              />
            ))}
          </CardBody>
        ) : (
          <EmptyState
            title="The radar returned no unmatched items"
            detail="Either every item cross-referenced to your incident, or no source returned anything."
          />
        )}
      </Card>
    </>
  )
}

export default function ThreatRadar() {
  // The incident being investigated drives the cross-reference: the live
  // analysis bundle if the operator ran one, otherwise the sample cache. Each
  // cached call may fail on its own; a failure narrows the cross-reference, it
  // does not take the radar down - and the operator is told which is missing.
  const { bundle, source } = useAnalysis()
  const incident = useScreenData<Incident>(bundle?.incident, getIncident, source)
  const intel = useScreenData<ThreatIntelView>(bundle?.threat_intel, getThreatIntel, source)
  const graph = useScreenData<AttackGraph>(bundle?.graph, getGraph, source)
  const settled = !incident.loading && !intel.loading && !graph.loading

  const sliceSources = new Set([incident.source, intel.source, graph.source])
  const radarSource = sliceSources.size === 1 ? incident.source : 'mixed'
  const radarSourceLabel =
    radarSource === 'live'
      ? 'live analysis'
      : radarSource === 'restored'
        ? 'restored session'
        : radarSource === 'sample'
          ? 'sample cache'
          : 'mixed live and sample data'

  const incidentData = incident.data
  const intelData = intel.data
  const graphData = graph.data

  const header = (
    <PageHeader
      eyebrow="Public threat reports"
      title="What are others seeing?"
      description="Match this incident with recent public security reports."
      actions={
        <Badge variant={radarSource === 'live' ? 'accent' : 'outline'}>
          {radarSourceLabel}
        </Badge>
      }
    />
  )

  if (!settled) {
    return (
      <>
        {header}
        <Card>
          <CardBody>
            <SkeletonRows rows={6} />
          </CardBody>
        </Card>
      </>
    )
  }

  const missing = [
    !incidentData ? 'the incident' : null,
    !intelData ? 'its attributed actors' : null,
    !graphData ? 'its attack graph' : null,
  ].filter((s): s is string => Boolean(s))

  return (
    <>
      {header}
      <Radar
        techniqueIds={incidentData?.technique_ids ?? []}
        actors={(intelData?.attribution ?? []).slice(0, 3).map((a) => a.actor)}
        edges={graphData?.edges ?? []}
        incidentId={incidentData?.incident_id}
        contextNote={
          missing.length
            ? `Could not load ${missing.join(' and ')}, so the cross-reference below is narrower than it should be.`
            : null
        }
      />
    </>
  )
}
