/**
 * Attack graph — the lateral-movement topology in three dimensions.
 *
 * Everything on this screen comes from `GET /api/graph`. The nodes are the
 * hosts the backend returned, the links are its aggregated authentication
 * pairs, and the five node roles are read straight off `entry_host`,
 * `attacker_pivots`, `critical_assets_at_risk`, `choke_points` and
 * `recommended_isolation`. Nothing is synthesised to fill the frame.
 *
 * The old screen carried an "attack propagation simulation" that invented step
 * titles, tactics and technique IDs (T1566.001, T1486) that no analysis had
 * produced. It is not ported. `paths_to_critical` is the real version of that
 * story and it is shown as a table, in the order the backend computed it.
 */
import {
  Component,
  Suspense,
  lazy,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react'
import { useSearchParams } from 'react-router-dom'
import { useReducedMotion } from 'motion/react'
import {
  Box,
  Crosshair,
  List,
  RotateCw,
  Route,
  Search,
  ShieldAlert,
  X,
} from 'lucide-react'
import { analyze, getAttackers, getGraph } from '@/lib/api'
import { useFetch } from '@/hooks/useFetch'
import { useAnalysis, useScreenData } from '@/providers/analysis'
import { fmtTime, severityFromScore } from '@/lib/format'
import {
  ROLE_LABEL,
  ROLE_ORDER,
  ROLE_SOURCE,
  ROLE_SWATCH,
  type Graph3DLink,
  type Graph3DNode,
  type NodeRole,
} from '@/lib/graphRoles'
import { PageHeader } from '@/components/Layout'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Card, CardBody, CardHeader, CardMeta, CardTitle } from '@/components/ui/card'
import { SkeletonRows } from '@/components/ui/skeleton'
import { Table, TBody, TD, TDMono, TH, THead, TR } from '@/components/ui/table'
import {
  EmptyState,
  ErrorState,
  MetricCard,
  NotMeasured,
  SectionLabel,
  SeverityBadge,
  StatRow,
} from '@/components/primitives'
import type { AttackGraph, GraphEdge } from '@/types/api'

// three.js and the WebGL renderer live behind this boundary and nowhere else.
const AttackGraph3D = lazy(() => import('@/components/AttackGraph3D'))

const CANVAS_HEIGHT = 620

/** Contains lazy-module, WebGL-context and renderer failures. The parent moves
 *  to the complete host list, so a failed canvas never leaves a blank panel. */
class GraphCanvasBoundary extends Component<
  { children: ReactNode; onFailure: () => void },
  { failed: boolean }
> {
  state = { failed: false }

  static getDerivedStateFromError() {
    return { failed: true }
  }

  componentDidCatch() {
    this.props.onFailure()
  }

  render() {
    return this.state.failed ? null : this.props.children
  }
}

/** A browser without WebGL gets the list, not a blank rectangle. */
function webglAvailable(): boolean {
  try {
    const c = document.createElement('canvas')
    return Boolean(c.getContext('webgl2') ?? c.getContext('webgl'))
  } catch {
    return false
  }
}

function useMeasuredWidth() {
  const ref = useRef<HTMLDivElement>(null)
  const [w, setW] = useState(760)
  useEffect(() => {
    const el = ref.current
    if (!el) return
    const ro = new ResizeObserver((entries) => {
      const cw = entries[0]?.contentRect.width
      if (cw) setW(Math.max(320, Math.floor(cw)))
    })
    ro.observe(el)
    return () => ro.disconnect()
  }, [])
  return [ref, w] as const
}

interface HostRow extends Graph3DNode {
  inbound: GraphEdge[]
  outbound: GraphEdge[]
}

export default function Graph() {
  const { bundle, setBundle, source: bundleSource } = useAnalysis()
  const roster = useFetch(getAttackers)
  const { data, error, loading, reload, source } = useScreenData<AttackGraph>(
    bundle?.graph,
    getGraph,
    bundleSource,
  )
  const reduced = useReducedMotion() ?? false
  const [wrapRef, width] = useMeasuredWidth()
  const [selected, setSelected] = useState<string | null>(null)
  const [q, setQ] = useState('')
  const [showPaths, setShowPaths] = useState(false)
  const [orbit, setOrbit] = useState(false)
  const [mode, setMode] = useState<'3d' | 'list'>('3d')
  const [webgl] = useState(webglAvailable)
  const [canvasFailed, setCanvasFailed] = useState(false)
  const [account, setAccount] = useState('')
  const [scopeBusy, setScopeBusy] = useState(false)
  const [scopeError, setScopeError] = useState<unknown>(null)
  const modeButtonRef = useRef<HTMLButtonElement>(null)

  const onCanvasFailure = useCallback(() => {
    setCanvasFailed(true)
    setMode('list')
  }, [])

  async function scopeToAccount() {
    if (
      !account ||
      !roster.data?.scenario ||
      bundle?.meta?.scenario !== roster.data.scenario ||
      scopeBusy
    ) return
    setScopeBusy(true)
    setScopeError(null)
    try {
      const scoped = await analyze({ scenario: roster.data.scenario, account })
      setBundle(scoped)
      setSelected(null)
    } catch (cause: unknown) {
      setScopeError(cause)
    } finally {
      setScopeBusy(false)
    }
  }

  // Threat Radar links here with ?techniques=T1550.002,… to show only the
  // movements that used them.
  const [params, setParams] = useSearchParams()
  const techFocus = useMemo(() => {
    const raw = params.get('techniques')
    const ids = raw ? raw.split(',').filter(Boolean) : []
    return ids.length ? new Set(ids) : null
  }, [params])

  const edges = useMemo<GraphEdge[]>(() => {
    const all = data?.edges ?? []
    return techFocus ? all.filter((e) => e.technique && techFocus.has(e.technique)) : all
  }, [data, techFocus])

  /** Every host in view, with its roles, its degree and its movements. */
  const rows = useMemo<HostRow[]>(() => {
    if (!data) return []
    const crown = new Set(data.critical_assets_at_risk ?? [])
    const pivots = new Set(data.attacker_pivots ?? [])
    const chokes = new Set(data.choke_points ?? [])
    const inbound = new Map<string, GraphEdge[]>()
    const outbound = new Map<string, GraphEdge[]>()
    for (const e of edges) {
      if (e.to) inbound.set(e.to, [...(inbound.get(e.to) ?? []), e])
      if (e.from) outbound.set(e.from, [...(outbound.get(e.from) ?? []), e])
    }
    // In a technique drill-in only the hosts those movements touched remain.
    const keep = techFocus
      ? new Set([...inbound.keys(), ...outbound.keys()])
      : null

    return (data.nodes ?? [])
      .filter((n) => !keep || keep.has(n.id))
      .map((n) => {
        const roles: NodeRole[] = []
        if (crown.has(n.id) || n.critical) roles.push('crown-jewel')
        if (n.id === data.entry_host || n.entry) roles.push('entry')
        if (pivots.has(n.id) || n.pivot) roles.push('pivot')
        if (chokes.has(n.id)) roles.push('choke')
        if (!roles.length) roles.push('reached')
        const inb = inbound.get(n.id) ?? []
        const outb = outbound.get(n.id) ?? []
        return {
          id: n.id,
          roles,
          role: ROLE_ORDER.find((r) => roles.includes(r)) ?? 'reached',
          degree: inb.length + outb.length,
          recommendedIsolation: n.id === data.recommended_isolation,
          inbound: inb,
          outbound: outb,
        }
      })
      .sort(
        (a, b) =>
          ROLE_ORDER.indexOf(a.role) - ROLE_ORDER.indexOf(b.role) || b.degree - a.degree,
      )
  }, [data, edges, techFocus])

  /** Edges lying on one of the backend's shortest paths to a crown jewel. */
  const pathEdges = useMemo(() => {
    const set = new Set<string>()
    for (const path of Object.values(data?.paths_to_critical ?? {})) {
      if (!Array.isArray(path)) continue
      for (let i = 0; i < path.length - 1; i += 1) set.add(`${path[i]}->${path[i + 1]}`)
    }
    return set
  }, [data])

  const { links, canvasMetricsComplete } = useMemo(() => {
    const connected = edges.filter((e) => e.from && e.to)
    const complete = connected.filter(
      (e) => typeof e.score === 'number' && typeof e.event_count === 'number',
    )
    return {
      links: complete.map<Graph3DLink>((e) => ({
        source: e.from,
        target: e.to,
        technique: e.technique ?? '',
        score: e.score as number,
        eventCount: e.event_count as number,
        onPath: pathEdges.has(`${e.from}->${e.to}`),
      })),
      canvasMetricsComplete: complete.length === connected.length,
    }
  }, [edges, pathEdges])

  const canvasAvailable = webgl && !canvasFailed && canvasMetricsComplete

  // The 3D renderer requires numeric score/count encodings. If the backend did
  // not measure either one, keep every edge in the honest list representation
  // instead of inventing a zero or one for the canvas.
  useEffect(() => {
    if (!canvasAvailable && mode === '3d') setMode('list')
  }, [canvasAvailable, mode])

  const nodes = useMemo<Graph3DNode[]>(
    () =>
      rows.map(({ id, role, roles, degree, recommendedIsolation }) => ({
        id,
        role,
        roles,
        degree,
        recommendedIsolation,
      })),
    [rows],
  )

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase()
    return needle ? rows.filter((r) => r.id.toLowerCase().includes(needle)) : rows
  }, [rows, q])

  const detail = selected ? rows.find((r) => r.id === selected) ?? null : null

  // Escape leaves the canvas: it drops the selection and puts focus back on a
  // real control, so a keyboard user is never stranded inside the renderer.
  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key !== 'Escape') return
    e.stopPropagation()
    setSelected(null)
    modeButtonRef.current?.focus()
  }

  if (loading) {
    return (
      <>
        <PageHeader eyebrow="Topology" title="Attack graph" />
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
        <PageHeader eyebrow="Topology" title="Attack graph" />
        <Card>
          <ErrorState error={error ?? new Error('no graph data')} retry={reload} />
        </Card>
      </>
    )
  }

  const useCanvas = mode === '3d' && canvasAvailable
  const rolesPresent = ROLE_ORDER.filter((r) => rows.some((n) => n.roles.includes(r)))
  const criticalAssets = Array.isArray(data.critical_assets_at_risk)
    ? data.critical_assets_at_risk
    : null
  const listFallbackReason = canvasFailed
    ? 'The 3D renderer failed, so the complete graph is shown as a list.'
    : !webgl
      ? 'WebGL is unavailable in this browser, so the graph is listed rather than rendered.'
      : !canvasMetricsComplete
        ? 'At least one movement has no measured anomaly score or event count, so the complete graph is listed rather than assigning invented canvas values.'
        : null
  const canScopeAccounts = Boolean(
    bundle?.meta?.scenario && bundle.meta.scenario === roster.data?.scenario,
  )

  return (
    <>
      <PageHeader
        eyebrow="Topology"
        title="Attack graph"
        description="Hosts the attacker authenticated to, as the deterministic graph algorithms see them. Colour is role, size is degree."
        actions={
          <>
            <Badge variant={source === 'live' ? 'accent' : 'outline'}>
              {source === 'live' ? 'live analysis' : source === 'restored' ? 'restored session' : 'sample cache'}
            </Badge>
            <Button
              ref={modeButtonRef}
              variant="secondary"
              size="sm"
              aria-pressed={useCanvas}
              disabled={!canvasAvailable}
              title={listFallbackReason ?? undefined}
              onClick={() => setMode(mode === '3d' ? 'list' : '3d')}
            >
              {mode === '3d' ? <List className="size-3.5" /> : <Box className="size-3.5" />}
              {mode === '3d' ? 'Host list' : '3D view'}
            </Button>
            <Button
              variant={showPaths ? 'default' : 'secondary'}
              size="sm"
              aria-pressed={showPaths}
              onClick={() => setShowPaths((v) => !v)}
            >
              <Route className="size-3.5" />
              Paths to crown jewels
            </Button>
            <Button
              variant={orbit ? 'default' : 'secondary'}
              size="sm"
              aria-pressed={orbit}
              disabled={reduced || !useCanvas}
              title={
                reduced
                  ? 'Disabled: this browser is set to reduce motion.'
                  : 'Rotate the camera slowly. Off by default.'
              }
              onClick={() => setOrbit((v) => !v)}
            >
              <RotateCw className="size-3.5" />
              Orbit
            </Button>
          </>
        }
      />

      {techFocus ? (
        <div className="mb-4 flex items-center gap-3 rounded-lg border border-border border-l-[3px] border-l-sev-high bg-surface px-4 py-2.5 text-sm text-dim">
          <Crosshair className="size-3.5 shrink-0 text-sev-high" aria-hidden />
          <span>
            Focused subgraph: <span className="font-mono text-text">{edges.length}</span>{' '}
            movement{edges.length === 1 ? '' : 's'} using{' '}
            <span className="font-mono text-text">{[...techFocus].join(', ')}</span> across{' '}
            <span className="font-mono text-text">{rows.length}</span> hosts.
          </span>
          <Button
            variant="ghost"
            size="sm"
            className="ml-auto"
            onClick={() => setParams({})}
          >
            Clear
          </Button>
        </div>
      ) : null}

      {canScopeAccounts ? <div className="mb-4 flex flex-col gap-3 border border-border bg-surface p-3 sm:flex-row sm:items-end">
        <label className="min-w-0 flex-1">
          <span className="section-label mb-1 block">Account scope</span>
          <select
            value={account}
            disabled={roster.loading || scopeBusy || !roster.data?.attackers.length}
            onChange={(event) => setAccount(event.target.value)}
            className="h-9 w-full rounded-md border border-border bg-surface-2 px-2 text-sm text-text"
          >
            <option value="">Choose an account to scope this graph</option>
            {(roster.data?.attackers ?? []).map((item) => (
              <option key={item.user} value={item.user}>{item.user} · {item.alerts} alerts</option>
            ))}
          </select>
        </label>
        <Button
          variant="secondary"
          disabled={!account || scopeBusy || !roster.data?.scenario}
          onClick={() => void scopeToAccount()}
        >
          <Crosshair className="size-3.5" />
          {scopeBusy ? 'Building scoped graph…' : 'Build scoped graph'}
        </Button>
      </div> : null}
      {scopeError ? (
        <Card className="mb-4"><ErrorState error={scopeError} retry={() => void scopeToAccount()} /></Card>
      ) : null}

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCard
          label="Hosts in view"
          value={rows.length.toLocaleString()}
          unit="hosts"
          context={`${data.n_nodes.toLocaleString()} in the full graph`}
        />
        <MetricCard
          label="Movements in view"
          value={edges.length.toLocaleString()}
          unit="edges"
          context={`${data.n_edges.toLocaleString()} in the full graph`}
        />
        <MetricCard
          label="Blast radius"
          value={
            data.blast_radius_size != null ? (
              data.blast_radius_size.toLocaleString()
            ) : (
              <NotMeasured why="Reachability was not computed for this graph." />
            )
          }
          unit="hosts"
          context={`Reachable from any of ${data.n_pivots} pivot${data.n_pivots === 1 ? '' : 's'}, not hosts already affected.`}
        />
        <MetricCard
          label="Crown jewels reachable"
          value={
            criticalAssets ? (
              criticalAssets.length
            ) : (
              <NotMeasured why="The graph response did not include critical-asset reachability." />
            )
          }
          severity={criticalAssets?.length ? 'critical' : undefined}
          context="Designated critical assets on a path from a pivot."
        />
      </div>

      <div className="mt-4 grid items-start gap-4 xl:grid-cols-[minmax(0,1fr)_22rem]">
        <Card>
          <CardHeader>
            <CardTitle>{useCanvas ? 'Topology · 3D' : 'Topology · list'}</CardTitle>
            <CardMeta>
              {rows.length} hosts · {links.length} movements
            </CardMeta>
          </CardHeader>

          {!rows.length ? (
            <EmptyState
              title="No hosts in this view"
              detail={
                techFocus
                  ? 'No movement in this incident used the requested technique.'
                  : 'The graph the backend returned has no nodes.'
              }
              icon={ShieldAlert}
            />
          ) : useCanvas ? (
            <div
              ref={wrapRef}
              onKeyDown={onKeyDown}
              role="group"
              tabIndex={0}
              aria-label="Attack graph, three-dimensional. Press Escape to leave the view. The host list beside it is the keyboard equivalent."
              className="relative border-b border-border outline-none focus-visible:outline-2 focus-visible:outline-accent focus-visible:outline-offset-[-2px]"
              style={{ height: CANVAS_HEIGHT }}
            >
              <GraphCanvasBoundary onFailure={onCanvasFailure}>
                <Suspense
                  fallback={
                    <div className="p-4">
                      <SkeletonRows rows={6} />
                    </div>
                  }
                >
                  <AttackGraph3D
                    nodes={nodes}
                    links={links}
                    selected={selected}
                    onSelect={setSelected}
                    showPaths={showPaths}
                    orbit={orbit && !reduced}
                    reducedMotion={reduced}
                    height={CANVAS_HEIGHT}
                    width={width}
                  />
                </Suspense>
              </GraphCanvasBoundary>
            </div>
          ) : (
            <div className="border-b border-border">
              {listFallbackReason ? (
                <p className="border-b border-border bg-surface-2 px-4 py-2 text-xs text-faint">
                  {listFallbackReason} Every host, role and degree below comes from the
                  same graph response.
                </p>
              ) : null}
              <div className="max-h-[460px] overflow-y-auto">
                <Table>
                  <THead>
                    <TR>
                      <TH>Host</TH>
                      <TH>Roles</TH>
                      <TH className="text-right">Degree</TH>
                    </TR>
                  </THead>
                  <TBody>
                    {filtered.slice(0, 300).map((n) => (
                      <TR key={n.id}>
                        <TDMono>
                          <button
                            type="button"
                            className="text-accent underline-offset-4 hover:underline"
                            onClick={() => setSelected(n.id)}
                          >
                            {n.id}
                          </button>
                        </TDMono>
                        <TD className="text-xs text-dim">
                          {n.roles.map((r) => ROLE_LABEL[r]).join(' · ')}
                          {n.recommendedIsolation ? ' · recommended isolation' : ''}
                        </TD>
                        <TDMono className="text-right">{n.degree}</TDMono>
                      </TR>
                    ))}
                  </TBody>
                </Table>
                {filtered.length > 300 ? (
                  <p className="px-4 py-2 text-xs text-faint">
                    +{filtered.length - 300} more — narrow the search.
                  </p>
                ) : null}
              </div>
            </div>
          )}

          {/* The legend states the encoding, because a colour with no stated
              meaning is decoration. */}
          <CardBody className="space-y-2">
            <SectionLabel>Legend</SectionLabel>
            <div className="flex flex-wrap gap-x-5 gap-y-1.5">
              {ROLE_ORDER.map((r) => (
                <span key={r} className="inline-flex items-center gap-1.5 text-xs">
                  <i className={`size-2 rounded-full ${ROLE_SWATCH[r]}`} aria-hidden />
                  <span className={rolesPresent.includes(r) ? 'text-dim' : 'text-faint'}>
                    {ROLE_LABEL[r]}
                  </span>
                  <span className="font-mono text-faint">{ROLE_SOURCE[r]}</span>
                </span>
              ))}
              <span className="inline-flex items-center gap-1.5 text-xs">
                <i
                  className="size-2.5 rounded-full border border-accent"
                  aria-hidden
                />
                <span className="text-dim">ring: recommended isolation</span>
              </span>
            </div>
            <p className="text-xs text-faint">
              A host can hold more than one role; it is coloured by the first in the
              order above and the panel beside it lists all of them. Sphere volume is
              degree — the number of movements that touched the host. Link colour is the
              pair&apos;s highest anomaly score on the backend&apos;s severity bands;
              link thickness is how many authentications collapsed into it. With
              &ldquo;Paths to crown jewels&rdquo; on, edges on `paths_to_critical` turn
              accent.
            </p>
          </CardBody>
        </Card>

        <div className="space-y-4">
          {detail ? (
            <Card>
              <CardHeader>
                <CardTitle className="font-mono">{detail.id}</CardTitle>
                <div className="flex items-center gap-2">
                  <CardMeta>
                    {detail.degree} movement{detail.degree === 1 ? '' : 's'}
                  </CardMeta>
                  <Button
                    variant="ghost"
                    size="icon"
                    aria-label="Close host detail"
                    onClick={() => setSelected(null)}
                  >
                    <X className="size-3.5" />
                  </Button>
                </div>
              </CardHeader>
              <CardBody className="space-y-1">
                <StatRow label="Roles" mono={false}>
                  <span className="text-dim">
                    {detail.roles.map((r) => ROLE_LABEL[r]).join(' · ')}
                  </span>
                </StatRow>
                <StatRow label="Recommended isolation">
                  {detail.recommendedIsolation ? 'yes' : 'no'}
                </StatRow>
                <StatRow label="Movements">
                  {detail.inbound.length} in · {detail.outbound.length} out
                </StatRow>
                <StatRow label="Accounts seen">
                  {(() => {
                    const accounts = [
                      ...new Set(
                        [...detail.inbound, ...detail.outbound].flatMap(
                          (e) => e.users ?? [],
                        ),
                      ),
                    ]
                    if (!accounts.length)
                      return <NotMeasured why="No account was recorded on these movements." />
                    return accounts.length > 3
                      ? `${accounts.length} accounts`
                      : accounts.join(', ')
                  })()}
                </StatRow>
                <StatRow label="Techniques">
                  {(() => {
                    const t = [
                      ...new Set(
                        [...detail.inbound, ...detail.outbound]
                          .map((e) => e.technique)
                          .filter((x): x is string => Boolean(x) && x !== '-'),
                      ),
                    ]
                    return t.length ? t.join(' ') : <NotMeasured />
                  })()}
                </StatRow>
                <StatRow label="Highest anomaly score">
                  {(() => {
                    const scores = [...detail.inbound, ...detail.outbound]
                      .map((e) => e.score)
                      .filter((s): s is number => typeof s === 'number')
                    if (!scores.length) return <NotMeasured />
                    const max = Math.max(...scores)
                    return (
                      <span className="inline-flex items-center gap-2">
                        {max}/100
                        <SeverityBadge severity={severityFromScore(max)} />
                      </span>
                    )
                  })()}
                </StatRow>
              </CardBody>

              {detail.outbound.length ? (
                <>
                  <div className="border-t border-border px-4 pt-3">
                    <SectionLabel>Moved to · {detail.outbound.length}</SectionLabel>
                  </div>
                  <MovementList edges={detail.outbound} dir="out" onPick={setSelected} />
                </>
              ) : null}
              {detail.inbound.length ? (
                <>
                  <div className="border-t border-border px-4 pt-3">
                    <SectionLabel>Reached from · {detail.inbound.length}</SectionLabel>
                  </div>
                  <MovementList edges={detail.inbound} dir="in" onPick={setSelected} />
                </>
              ) : null}
            </Card>
          ) : (
            <Card>
              <CardHeader>
                <CardTitle>Hosts</CardTitle>
                <CardMeta>{filtered.length} in view</CardMeta>
              </CardHeader>
              <div className="flex items-center gap-2 border-b border-border px-4 py-2">
                <Search className="size-3.5 text-faint" aria-hidden />
                <input
                  value={q}
                  onChange={(e) => setQ(e.target.value)}
                  placeholder="find host"
                  aria-label="Find host"
                  className="w-full bg-transparent font-mono text-xs text-text outline-none placeholder:text-faint focus-visible:outline-2 focus-visible:outline-accent"
                />
              </div>
              {filtered.length ? (
                <div className="max-h-[360px] overflow-y-auto">
                  {filtered.slice(0, 200).map((n) => (
                    <button
                      key={n.id}
                      type="button"
                      onClick={() => setSelected(n.id)}
                      className="flex w-full items-center gap-2 border-b border-border px-4 py-1.5 text-left last:border-0 hover:bg-surface-2"
                    >
                      <i
                        className={`size-2 shrink-0 rounded-full ${ROLE_SWATCH[n.role]}`}
                        aria-hidden
                      />
                      <span className="font-mono text-xs text-text">{n.id}</span>
                      <span className="truncate text-xs text-faint">
                        {n.roles.map((r) => ROLE_LABEL[r]).join(' · ')}
                      </span>
                      <span className="ml-auto font-mono text-xs tabular-nums text-dim">
                        {n.degree}
                      </span>
                    </button>
                  ))}
                  {filtered.length > 200 ? (
                    <p className="px-4 py-2 text-xs text-faint">
                      +{filtered.length - 200} more — narrow the search.
                    </p>
                  ) : null}
                </div>
              ) : (
                <EmptyState
                  title="No host matches that search"
                  detail="Clear the box to see every host in view."
                />
              )}
            </Card>
          )}

          <Card>
            <CardHeader>
              <CardTitle>Blast-radius analysis</CardTitle>
              <CardMeta>deterministic · NetworkX</CardMeta>
            </CardHeader>
            <CardBody className="space-y-1">
              <StatRow label="Entry host">
                {data.entry_host ?? (
                  <NotMeasured why="No entry point could be identified." />
                )}
              </StatRow>
              <StatRow label="Attacker pivots">
                {data.attacker_pivots?.length ? (
                  data.attacker_pivots.join(' · ')
                ) : (
                  <NotMeasured why="No attacker-controlled source host was identified." />
                )}
              </StatRow>
              <StatRow label="Crown jewels at risk">
                {criticalAssets?.length ? (
                  <span className="text-sev-critical">
                    {criticalAssets.length}
                  </span>
                ) : criticalAssets ? (
                  <span className="text-faint">none marked reachable</span>
                ) : (
                  <NotMeasured why="The graph response did not include critical-asset reachability." />
                )}
              </StatRow>
              <StatRow label="Choke points">
                {data.choke_points?.length ? (
                  data.choke_points.join(' · ')
                ) : (
                  <NotMeasured why="Betweenness centrality needs more than two nodes." />
                )}
              </StatRow>
              <StatRow label="Recommended isolation">
                {data.recommended_isolation ?? (
                  <NotMeasured why="No single host removal improved containment." />
                )}
              </StatRow>
              <StatRow label="Systems removed from reach">
                {data.isolation_cuts != null ? data.isolation_cuts : <NotMeasured />}
              </StatRow>
              <StatRow label="Graph">
                {data.n_nodes} nodes · {data.n_edges} edges
              </StatRow>
            </CardBody>
            <div className="border-t border-border px-4 py-2.5 text-xs text-faint">
              Reachability is computed from every attacker pivot, not just the busiest
              one. Isolation is a proposal for a human to approve; nothing on this screen
              contacts a host.
            </div>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Paths to crown jewels</CardTitle>
              <CardMeta>
                {Object.keys(data.paths_to_critical ?? {}).length} target
                {Object.keys(data.paths_to_critical ?? {}).length === 1 ? '' : 's'}
              </CardMeta>
            </CardHeader>
            {Object.keys(data.paths_to_critical ?? {}).length ? (
              <Table>
                <THead>
                  <TR>
                    <TH>Crown jewel</TH>
                    <TH>Shortest path from a pivot</TH>
                  </TR>
                </THead>
                <TBody>
                  {Object.entries(data.paths_to_critical).map(([target, path]) => (
                    <TR key={target}>
                      <TDMono className="text-sev-critical">{target}</TDMono>
                      <TDMono className="text-dim">
                        {Array.isArray(path) ? path.join('  →  ') : <NotMeasured />}
                      </TDMono>
                    </TR>
                  ))}
                </TBody>
              </Table>
            ) : (
              <EmptyState
                title="No path to a crown jewel"
                detail="No designated critical asset is reachable from an attacker pivot on this graph."
              />
            )}
          </Card>
        </div>
      </div>
    </>
  )
}

function MovementList({
  edges,
  dir,
  onPick,
}: {
  edges: GraphEdge[]
  dir: 'in' | 'out'
  onPick: (id: string) => void
}) {
  return (
    <div className="max-h-[220px] overflow-y-auto">
      {edges.slice(0, 40).map((e, i) => {
        const other = dir === 'in' ? e.from : e.to
        const score = typeof e.score === 'number' ? e.score : null
        return (
          <button
            key={`${other}-${i}`}
            type="button"
            onClick={() => onPick(other)}
            className="flex w-full items-baseline gap-2 border-b border-border px-4 py-1.5 text-left last:border-0 hover:bg-surface-2"
          >
            <span className="font-mono text-xs text-faint">{dir === 'in' ? '←' : '→'}</span>
            <span className="font-mono text-xs text-text">{other}</span>
            <span className="font-mono text-xs text-dim">{e.technique ?? '—'}</span>
            <span className="ml-auto font-mono text-xs tabular-nums text-dim">
              {score != null ? score : <NotMeasured />}
            </span>
            {typeof e.event_count === 'number' && e.event_count > 1 ? (
              <span className="font-mono text-xs text-faint">×{e.event_count}</span>
            ) : null}
            {typeof e.first_seen === 'number' ? (
              <span className="font-mono text-xs text-faint">{fmtTime(e.first_seen)}</span>
            ) : null}
          </button>
        )
      })}
      {edges.length > 40 ? (
        <p className="px-4 py-2 text-xs text-faint">+{edges.length - 40} more</p>
      ) : null}
    </div>
  )
}
