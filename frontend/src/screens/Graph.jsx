import { useEffect, useMemo, useRef, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import ForceGraph2D from 'react-force-graph-2d'
import { Route, X, Search, Crosshair } from 'lucide-react'
import { getGraph, getAttackers, analyze } from '../api.js'
import { useFetch } from '../lib/useFetch.js'
import { useScreenData, useAnalysis } from '../lib/analysis.jsx'
import { Card, CardHeader, Loading, ErrorBox } from '../components/Card.jsx'
import { useTheme } from '../lib/theme.jsx'
import { cssVar, fmtTime, severityFromScore } from '../lib/format.js'

function useMeasuredWidth() {
  const ref = useRef(null)
  const [w, setW] = useState(760)
  useEffect(() => {
    if (!ref.current) return
    const ro = new ResizeObserver((entries) => {
      const cw = entries[0]?.contentRect?.width
      if (cw) setW(Math.max(320, Math.floor(cw)))
    })
    ro.observe(ref.current)
    return () => ro.disconnect()
  }, [])
  return [ref, w]
}

// Everything known about one host, derived from the movements touching it.
function hostFacts(id, edges) {
  const inbound = edges.filter((e) => e.to === id)
  const outbound = edges.filter((e) => e.from === id)
  const accounts = [...new Set([...inbound, ...outbound].flatMap((e) => e.users || []))]
  const techniques = [...new Set([...inbound, ...outbound].map((e) => e.technique).filter((t) => t && t !== '-'))]
  const events = [...inbound, ...outbound].reduce((n, e) => n + (e.event_count || 1), 0)
  const maxScore = Math.max(0, ...[...inbound, ...outbound].map((e) => e.score || 0))
  return { inbound, outbound, accounts, techniques, events, maxScore }
}

function MovementRow({ e, dir, onPick }) {
  const other = dir === 'in' ? e.from : e.to
  const sev = severityFromScore(e.score)
  return (
    <button className="movement" onClick={() => onPick(other)} title={`Focus ${other}`}>
      <span className="mono dir">{dir === 'in' ? '←' : '→'}</span>
      <span className="mono host">{other}</span>
      <span className="mono tid">{e.technique}</span>
      <span className={`num s-${sev}`}>{e.score}</span>
      {e.event_count > 1 && <span className="chip">×{e.event_count}</span>}
    </button>
  )
}

function HostDetail({ id, data, onClose, onPick }) {
  const f = hostFacts(id, data.edges)
  const node = data.nodes.find((n) => n.id === id)
  const role = node?.pivot ? 'attacker pivot' : node?.critical ? 'CRITICAL asset' : 'reached host'
  const roleSev = node?.pivot ? 'low' : node?.critical ? 'critical' : 'normal'
  return (
    <Card>
      <CardHeader title={<span className="mono">{id}</span>} meta={`${f.events} authentication${f.events > 1 ? 's' : ''}`}>
        <button className="btn" onClick={onClose} aria-label="Close host detail"
          style={{ padding: '2px 7px', display: 'inline-flex', alignItems: 'center' }}>
          <X size={12} />
        </button>
      </CardHeader>
      <div className="kv">
        <div className="row"><span className="k">Role</span>
          <span className={`v s-${roleSev}`} style={{ fontWeight: 600 }}>{role}</span></div>
        <div className="row"><span className="k">Movements</span>
          <span className="v">{f.inbound.length} in · {f.outbound.length} out</span></div>
        <div className="row"><span className="k">Accounts seen</span>
          <span className="v mono" style={{ fontSize: 12 }}>
            {f.accounts.length > 3 ? `${f.accounts.length} accounts` : (f.accounts.join(', ') || '—')}</span></div>
        <div className="row"><span className="k">Techniques</span>
          <span className="v mono" style={{ fontSize: 12 }}>{f.techniques.join(' ') || '—'}</span></div>
        <div className="row"><span className="k">Max anomaly</span>
          <span className={`v s-${severityFromScore(f.maxScore)}`}>{f.maxScore}/100</span></div>
      </div>

      {f.outbound.length > 0 && (
        <>
          <div className="section-label" style={{ padding: '8px 14px 0' }}>Moved to · {f.outbound.length}</div>
          <div className="movements">
            {f.outbound.slice(0, 40).map((e) => (
              <MovementRow key={`o-${e.to}`} e={e} dir="out" onPick={onPick} />
            ))}
            {f.outbound.length > 40 && <div className="more">+{f.outbound.length - 40} more</div>}
          </div>
        </>
      )}
      {f.inbound.length > 0 && (
        <>
          <div className="section-label" style={{ padding: '8px 14px 0' }}>Reached from · {f.inbound.length}</div>
          <div className="movements">
            {f.inbound.slice(0, 40).map((e) => (
              <MovementRow key={`i-${e.from}`} e={e} dir="in" onPick={onPick} />
            ))}
          </div>
        </>
      )}
      <div className="note">
        Click any row to jump to that host. Times:{' '}
        {fmtTime(Math.min(...[...f.inbound, ...f.outbound].map((e) => e.first_seen)))} –{' '}
        {fmtTime(Math.max(...[...f.inbound, ...f.outbound].map((e) => e.last_seen)))}
      </div>
    </Card>
  )
}

const CAMPAIGN_SCENARIO = 'lanl_campaign_all'

export default function Graph() {
  const { data, error, loading } = useScreenData('graph', getGraph)
  const { bundle, setBundle, clear } = useAnalysis()
  const { theme } = useTheme()
  const [wrapRef, width] = useMeasuredWidth()
  const [showPath, setShowPath] = useState(false)
  const [selected, setSelected] = useState(null)   // host id
  const [q, setQ] = useState('')
  const [busy, setBusy] = useState(false)
  const fgRef = useRef(null)
  const fitted = useRef(null)

  // techniques to spotlight, arriving from a Threat Radar "highlight these" link
  const [params, setParams] = useSearchParams()
  const techFocus = useMemo(() => {
    const raw = params.get('techniques')
    return raw ? new Set(raw.split(',').filter(Boolean)) : null
  }, [params])

  // Full campaign roster for the picker — the loaded graph may be scoped to one
  // account, which would otherwise leave no way back to the others.
  const { data: roster } = useFetch(() => getAttackers().then((d) => d.attackers))
  const account = bundle?.meta?.account || 'all'

  // Switching account runs a REAL analysis for that account. Client-side filtering
  // could hide edges, but blast radius / choke points / SOAR are graph algorithms —
  // they must be recomputed server-side or they'd silently stay campaign-wide.
  async function pickAccount(value) {
    setSelected(null); setBusy(true)
    try {
      if (value === 'all') clear()
      else {
        setBundle(await analyze({
          scenario: CAMPAIGN_SCENARIO, account: value,  // crown jewels: backend default (derived)
        }))
      }
    } finally { setBusy(false) }
  }

  const highlight = useMemo(() => {
    const nodes = new Set(); const edges = new Set()
    for (const arr of Object.values(data?.paths_to_critical || {})) {
      arr.forEach((n) => nodes.add(n))
      for (let i = 0; i < arr.length - 1; i++) edges.add(`${arr[i]}->${arr[i + 1]}`)
    }
    return { nodes, edges }
  }, [data])

  const accounts = useMemo(() => (roster || []).map((a) => a.user), [roster])

  // Base view = the loaded analysis (campaign, or one account).
  const base = useMemo(() => (
    data ? { nodes: data.nodes, edges: data.edges } : { nodes: [], edges: [] }
  ), [data])

  // A technique drill-in from Threat Radar reduces the canvas to JUST those
  // movements (and the hosts they touch) — a focused subgraph, not an overlay on
  // the whole campaign.
  const view = useMemo(() => {
    if (!techFocus) return base
    const edges = base.edges.filter((e) => techFocus.has(e.technique))
    const keep = new Set(edges.flatMap((e) => [e.from, e.to]))
    return { nodes: base.nodes.filter((n) => keep.has(n.id)), edges }
  }, [base, techFocus])

  const graphData = useMemo(() => ({
    nodes: view.nodes.map((n) => ({ ...n })),
    links: view.edges.map((e) => ({ ...e, source: e.from, target: e.to })),
  }), [view])

  const hostRows = useMemo(() => {
    const deg = new Map()
    for (const e of view.edges) {
      deg.set(e.from, (deg.get(e.from) || 0) + 1)
      deg.set(e.to, (deg.get(e.to) || 0) + 1)
    }
    const needle = q.trim().toLowerCase()
    return view.nodes
      .map((n) => ({ ...n, degree: deg.get(n.id) || 0 }))
      .filter((n) => !needle || n.id.toLowerCase().includes(needle))
      .sort((a, b) => (b.pivot - a.pivot) || (b.critical - a.critical) || b.degree - a.degree)
  }, [view, q])

  useEffect(() => {
    if (fgRef.current) {
      // Small subgraphs (a Threat-Radar drill-in) have disconnected components;
      // strong repulsion flings them apart and zoomToFit then shows a mostly-empty
      // canvas. Scale repulsion + link distance down for small graphs so the pieces
      // stay together and fill the frame. Guarded — a missing d3 method must never
      // blank the page.
      try {
        const small = graphData.nodes.length < 160
        const charge = fgRef.current.d3Force('charge')
        charge?.strength?.(small ? -34 : -120)
        charge?.distanceMax?.(small ? 180 : 400)
        fgRef.current.d3Force('link')?.distance?.(small ? 18 : 28)
        fgRef.current.d3Force('center')?.strength?.(small ? 0.4 : 0.08)
        fgRef.current.d3ReheatSimulation?.()
      } catch { /* keep default forces */ }
    }
    fitted.current = null            // refit when the graph changes
    // fallback fit in case the sim settles before onEngineStop refires
    const t = setTimeout(() => fgRef.current?.zoomToFit(500, 55), 800)
    return () => clearTimeout(t)
  }, [graphData, theme])

  const focus = (id) => {
    setSelected(id)
    const n = graphData.nodes.find((x) => x.id === id)
    if (n && Number.isFinite(n.x)) fgRef.current?.centerAt(n.x, n.y, 600)
    fgRef.current?.zoom(3, 600)
  }

  if (loading) return <Loading />
  if (error) return <ErrorBox error={error} />

  const neighbours = selected
    ? new Set(view.edges.filter((e) => e.from === selected || e.to === selected)
        .flatMap((e) => [e.from, e.to]))
    : null

  const nodeColor = (n) => {
    if (selected && n.id === selected) return cssVar('--accent')
    if (n.pivot) return cssVar('--accent')
    if (n.critical) return cssVar('--sev-critical')
    if (techFocus) return cssVar('--sev-high')             // subgraph: all in-focus
    if (selected && neighbours.has(n.id)) return cssVar('--sev-high')
    if (showPath && highlight.nodes.has(n.id)) return cssVar('--sev-high')
    return cssVar('--sev-normal')
  }
  const nodeVal = (n) => (n.id === selected ? 12 : n.pivot ? 9 : n.critical ? 7 : 3)
  const touchesSel = (l) => selected &&
    ((l.source.id || l.source) === selected || (l.target.id || l.target) === selected)
  const linkColor = (l) => {
    if (techFocus) return cssVar('--sev-high')             // every edge here matches
    if (touchesSel(l)) return cssVar('--accent')
    const key = `${l.source.id || l.source}->${l.target.id || l.target}`
    if (showPath && highlight.edges.has(key)) return cssVar('--sev-high')
    return cssVar('--grid')
  }
  const linkWidth = (l) => {
    if (techFocus) return 2
    if (touchesSel(l)) return 3
    const key = `${l.source.id || l.source}->${l.target.id || l.target}`
    return showPath && highlight.edges.has(key) ? 3 : 1
  }

  const focusCount = view.edges.length
  // pivots / crown jewels actually present in the current view (subgraph or full)
  const viewPivots = view.nodes.filter((n) => n.pivot).map((n) => n.id)
  const viewCrown = view.nodes.filter((n) => n.critical).map((n) => n.id)

  return (
    <>
      {techFocus && (
        <div className="note" style={{
          margin: '0 0 12px', display: 'flex', alignItems: 'center', gap: 10,
          borderLeft: '3px solid var(--sev-high)',
        }}>
          <Crosshair size={14} aria-hidden="true" style={{ color: 'var(--sev-high)' }} />
          <span>Focused subgraph: <b>{focusCount}</b> movement{focusCount !== 1 ? 's' : ''} using{' '}
            <b className="mono">{[...techFocus].join(', ')}</b> across <b>{view.nodes.length}</b> hosts —
            the technique from that threat-radar hit.</span>
          <button className="btn" onClick={() => setParams({})}
            style={{ marginLeft: 'auto', padding: '2px 8px', fontSize: 11 }}>Clear</button>
        </div>
      )}
      <div className="grid2" style={{ gridTemplateColumns: '1.4fr 1fr' }}>
        <Card>
          <CardHeader title="Attack-path graph"
            meta={busy ? 'analyzing…' : `${view.nodes.length} hosts · ${view.edges.length} movements`}>
            <select value={account} onChange={(e) => pickAccount(e.target.value)} disabled={busy}
              aria-label="Analyze one account"
              style={{ fontSize: 12, padding: '4px 8px', marginRight: 8, maxWidth: 190 }}>
              <option value="all">All accounts — full campaign</option>
              {accounts.map((a) => <option key={a} value={a}>{a}</option>)}
            </select>
            <button className="btn" onClick={() => setShowPath((v) => !v)}
              style={{ display: 'inline-flex', gap: 6, alignItems: 'center' }}
              aria-pressed={showPath}>
              <Route size={13} aria-hidden="true" />
              {showPath ? 'Hide path' : 'Path to crown jewel'}
            </button>
          </CardHeader>
          <div className="graphwrap" ref={wrapRef}>
            <ForceGraph2D
              key={theme}
              ref={fgRef}
              graphData={graphData}
              width={width}
              height={440}
              backgroundColor="transparent"
              nodeColor={nodeColor}
              nodeVal={nodeVal}
              nodeRelSize={4}
              nodeLabel={(n) => `${n.id}${n.pivot ? ' · attacker pivot' : n.critical ? ' · CRITICAL' : ''} — click for detail`}
              linkColor={linkColor}
              linkWidth={linkWidth}
              linkLabel={(l) => `${l.from} → ${l.to} · ${l.technique} · score ${l.score}` +
                (l.event_count > 1 ? ` · ${l.event_count} auths` : '')}
              linkDirectionalParticles={showPath ? 2 : 0}
              linkDirectionalParticleWidth={2}
              cooldownTicks={120}
              onEngineStop={() => {
                // keep every node inside the canvas (they used to drift off-screen).
                // Key on node count + focus so a filter change always refits.
                const sig = `${graphData.nodes.length}:${techFocus ? [...techFocus].join(',') : ''}`
                if (fitted.current !== sig) {
                  fitted.current = sig
                  fgRef.current?.zoomToFit(500, 60)
                }
              }}
              onNodeClick={(n) => focus(n.id)}
              onBackgroundClick={() => setSelected(null)}
              enableNodeDrag={false}
            />
          </div>
          <div className="legend">
            <span><i style={{ background: 'var(--accent)' }} />
              Attacker pivot ×{viewPivots.length} ({viewPivots.join(', ') || '—'})</span>
            <span><i style={{ background: 'var(--sev-critical)' }} />
              Crown jewel ×{viewCrown.length}</span>
            <span><i style={{ background: 'var(--sev-high)' }} />
              {techFocus ? 'In-focus movement' : 'Connected / path'}</span>
            <span><i style={{ background: 'var(--sev-normal)' }} />Reached host</span>
          </div>
        </Card>

        <div className="stack">
          {selected
            ? <HostDetail id={selected} data={view} onClose={() => setSelected(null)} onPick={focus} />
            : (
              <Card>
                <CardHeader title="Hosts" meta={`${hostRows.length} in view`}>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                    <Search size={13} aria-hidden="true" style={{ color: 'var(--text-faint)' }} />
                    <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="find host"
                      aria-label="Find host" style={{ fontSize: 12, padding: '4px 8px', width: 130 }} />
                  </span>
                </CardHeader>
                <div className="hostlist">
                  {hostRows.slice(0, 200).map((n) => (
                    <button key={n.id} className="hostrow" onClick={() => focus(n.id)}>
                      <span className={`dotm ${n.pivot ? 'bg-low' : n.critical ? 'bg-critical' : 'bg-normal'}`} />
                      <span className="mono id">{n.id}</span>
                      {n.pivot && <span className="chip">pivot</span>}
                      {n.critical && <span className="chip crit">crown jewel</span>}
                      <span className="deg">{n.degree}</span>
                    </button>
                  ))}
                  {hostRows.length > 200 && <div className="more">+{hostRows.length - 200} more — refine the search</div>}
                </div>
                <div className="note">
                  Sorted by connections. Click a host (here or in the graph) to see every
                  authentication that touched it.
                </div>
              </Card>
            )}

          <Card>
            <CardHeader title="Blast-radius analysis"
              meta={techFocus ? 'whole incident' : undefined} />
            <div className="kv">
              <div className="row"><span className="k">Attacker pivots</span>
                <span className="v mono">{(data.attacker_pivots || [data.entry_host]).join(' · ')}</span></div>
              <div className="row"><span className="k">Crown jewels at risk</span>
                <span className="v s-critical mono">
                  {data.critical_assets_at_risk.length}: {data.critical_assets_at_risk.join(', ') || '—'}</span></div>
              <div className="row"><span className="k">Choke points</span><span className="v mono">{data.choke_points.join(' · ')}</span></div>
              <div className="row"><span className="k">Total exposure</span>
                <span className="v">{data.blast_radius_size} hosts reachable from any pivot</span></div>
              <div className="row"><span className="k">Recommended isolation</span><span className="v s-high mono">{data.recommended_isolation}</span></div>
              <div className="row"><span className="k">Graph</span><span className="v">{data.n_nodes} nodes · {data.n_edges} edges</span></div>
            </div>
            <div className="note">
              Isolating <b className="mono">{data.recommended_isolation}</b> severs{' '}
              <b>{data.isolation_cuts ?? data.blast_radius_size}</b> hosts — of{' '}
              {data.blast_radius_size} exposed across {data.n_pivots ?? 1} pivot
              {(data.n_pivots ?? 1) > 1 ? 's' : ''}. Reachability is computed from every
              attacker pivot, not just the busiest one.
            </div>
          </Card>
        </div>
      </div>
    </>
  )
}
