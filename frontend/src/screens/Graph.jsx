import { useEffect, useMemo, useRef, useState } from 'react'
import ForceGraph2D from 'react-force-graph-2d'
import { Route, X, Search, Crosshair } from 'lucide-react'
import { getGraph } from '../api.js'
import { useScreenData } from '../lib/analysis.jsx'
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

export default function Graph() {
  const { data, error, loading } = useScreenData('graph', getGraph)
  const { theme } = useTheme()
  const [wrapRef, width] = useMeasuredWidth()
  const [showPath, setShowPath] = useState(false)
  const [selected, setSelected] = useState(null)   // host id
  const [account, setAccount] = useState('all')
  const [q, setQ] = useState('')
  const fgRef = useRef(null)

  const highlight = useMemo(() => {
    const nodes = new Set(); const edges = new Set()
    for (const arr of Object.values(data?.paths_to_critical || {})) {
      arr.forEach((n) => nodes.add(n))
      for (let i = 0; i < arr.length - 1; i++) edges.add(`${arr[i]}->${arr[i + 1]}`)
    }
    return { nodes, edges }
  }, [data])

  const accounts = useMemo(() => {
    const s = new Set((data?.edges || []).flatMap((e) => e.users || []))
    return [...s].sort()
  }, [data])

  // Filtering by account keeps only that account's movements and the hosts they touch.
  const view = useMemo(() => {
    if (!data) return { nodes: [], edges: [] }
    const edges = account === 'all'
      ? data.edges
      : data.edges.filter((e) => (e.users || []).includes(account))
    const keep = new Set(edges.flatMap((e) => [e.from, e.to]))
    const nodes = account === 'all' ? data.nodes : data.nodes.filter((n) => keep.has(n.id))
    return { nodes, edges }
  }, [data, account])

  const graphData = useMemo(() => ({
    nodes: view.nodes.map((n) => ({ ...n })),
    links: view.edges.map((e) => ({ ...e, source: e.from, target: e.to })),
  }), [view])

  // Host list beside the graph — 480 nodes are impossible to hunt visually.
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
      fgRef.current.d3Force('charge')?.strength(-70)
      fgRef.current.d3ReheatSimulation?.()
    }
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
    if (selected && neighbours.has(n.id)) return cssVar('--sev-high')
    if (showPath && highlight.nodes.has(n.id)) return cssVar('--sev-high')
    return cssVar('--sev-normal')
  }
  const nodeVal = (n) => (n.id === selected ? 12 : n.pivot ? 9 : n.critical ? 7 : 2)
  const touchesSel = (l) => selected &&
    ((l.source.id || l.source) === selected || (l.target.id || l.target) === selected)
  const linkColor = (l) => {
    if (touchesSel(l)) return cssVar('--accent')
    const key = `${l.source.id || l.source}->${l.target.id || l.target}`
    if (showPath && highlight.edges.has(key)) return cssVar('--sev-high')
    return cssVar('--grid')
  }
  const linkWidth = (l) => {
    if (touchesSel(l)) return 3
    const key = `${l.source.id || l.source}->${l.target.id || l.target}`
    return showPath && highlight.edges.has(key) ? 3 : 1
  }

  return (
    <>
      <div className="grid2" style={{ gridTemplateColumns: '1.4fr 1fr' }}>
        <Card>
          <CardHeader title="Attack-path graph"
            meta={`${view.nodes.length} hosts · ${view.edges.length} movements`}>
            <select value={account} onChange={(e) => { setAccount(e.target.value); setSelected(null) }}
              aria-label="Filter by account"
              style={{ fontSize: 12, padding: '4px 8px', marginRight: 8, maxWidth: 190 }}>
              <option value="all">All accounts ({accounts.length})</option>
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
              onNodeClick={(n) => focus(n.id)}
              onBackgroundClick={() => setSelected(null)}
              enableNodeDrag={false}
            />
          </div>
          <div className="legend">
            <span><i style={{ background: 'var(--accent)' }} />Attacker pivot / selected</span>
            <span><i style={{ background: 'var(--sev-critical)' }} />Crown jewel ({data.critical_assets_at_risk.join(', ') || '—'})</span>
            <span><i style={{ background: 'var(--sev-high)' }} />Connected / path</span>
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
            <CardHeader title="Blast-radius analysis" />
            <div className="kv">
              <div className="row"><span className="k">Entry host</span><span className="v mono">{data.entry_host}</span></div>
              <div className="row"><span className="k">Critical assets at risk</span><span className="v s-critical mono">{data.critical_assets_at_risk.join(', ') || '—'}</span></div>
              <div className="row"><span className="k">Choke points</span><span className="v mono">{data.choke_points.join(' · ')}</span></div>
              <div className="row"><span className="k">Blast radius</span><span className="v">{data.blast_radius_size} hosts</span></div>
              <div className="row"><span className="k">Recommended isolation</span><span className="v s-high mono">{data.recommended_isolation}</span></div>
              <div className="row"><span className="k">Full campaign graph</span><span className="v">{data.n_nodes} nodes · {data.n_edges} edges</span></div>
            </div>
            <div className="note">
              Isolating <b className="mono">{data.recommended_isolation}</b> severs{' '}
              {data.blast_radius_size} downstream hosts.
            </div>
          </Card>
        </div>
      </div>
    </>
  )
}
