import { useEffect, useMemo, useRef, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import ForceGraph2D from 'react-force-graph-2d'
import { Route, X, Search, Crosshair, Play, Pause, SkipForward, SkipBack, RotateCcw, Sparkles, ShieldAlert } from 'lucide-react'
import { getGraph, getAttackers, analyze } from '../api.js'
import { useFetch } from '../lib/useFetch.js'
import { useScreenData, useAnalysis } from '../lib/analysis.jsx'
import { Card, CardHeader, Loading, ErrorBox } from '../components/Card.jsx'
import CalibrationBadge from '../components/CalibrationBadge.jsx'
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
function hostFacts(id, edges = []) {
  const inbound = (edges || []).filter((e) => e && e.to === id)
  const outbound = (edges || []).filter((e) => e && e.from === id)
  const accounts = [...new Set([...inbound, ...outbound].flatMap((e) => e?.users || []))]
  const techniques = [...new Set([...inbound, ...outbound].map((e) => e?.technique).filter((t) => t && t !== '-'))]
  const events = [...inbound, ...outbound].reduce((n, e) => n + (e?.event_count || 1), 0)
  const scores = [...inbound, ...outbound].map((e) => e?.score || 0)
  const maxScore = scores.length ? Math.max(0, ...scores) : 0
  return { inbound, outbound, accounts, techniques, events, maxScore }
}

function MovementRow({ e, dir, onPick }) {
  if (!e) return null
  const other = dir === 'in' ? e.from : e.to
  const sev = severityFromScore(e.score || 0)
  return (
    <button className="movement" onClick={() => onPick(other)} title={`Focus ${other}`}>
      <span className="mono dir">{dir === 'in' ? '←' : '→'}</span>
      <span className="mono host">{other}</span>
      <span className="mono tid">{e.technique || '—'}</span>
      <span className={`num s-${sev}`}>{e.score || 0}</span>
      {(e.event_count || 0) > 1 && <span className="chip">×{e.event_count}</span>}
    </button>
  )
}

function HostDetail({ id, data, onClose, onPick }) {
  const f = hostFacts(id, data?.edges || [])
  const node = (data?.nodes || []).find((n) => n?.id === id)
  const role = node?.pivot ? 'attacker pivot' : node?.critical ? 'CRITICAL asset' : 'reached host'
  const roleSev = node?.pivot ? 'low' : node?.critical ? 'critical' : 'normal'
  const allMoves = [...f.inbound, ...f.outbound]
  const firstSeens = allMoves.map((e) => e?.first_seen).filter((t) => typeof t === 'number' && Number.isFinite(t))
  const lastSeens = allMoves.map((e) => e?.last_seen).filter((t) => typeof t === 'number' && Number.isFinite(t))
  const firstSeen = firstSeens.length ? Math.min(...firstSeens) : null
  const lastSeen = lastSeens.length ? Math.max(...lastSeens) : null

  return (
    <Card>
      <CardHeader title={<span className="mono">{id}</span>} meta={`${f.events} authentication${f.events !== 1 ? 's' : ''}`}>
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
        {/* A score is meaningless without the scale it was produced on, so the
            badge rides beside it (it reads meta.calibration itself). */}
        <div className="row"><span className="k">Max anomaly</span>
          <span className={`v s-${severityFromScore(f.maxScore)}`}>{f.maxScore}/100</span>
          <CalibrationBadge label="max anomaly scale" /></div>
      </div>

      {f.outbound.length > 0 && (
        <>
          <div className="section-label" style={{ padding: '8px 14px 0' }}>Moved to · {f.outbound.length}</div>
          <div className="movements">
            {f.outbound.slice(0, 40).map((e, idx) => (
              <MovementRow key={`o-${e.to || idx}`} e={e} dir="out" onPick={onPick} />
            ))}
            {f.outbound.length > 40 && <div className="more">+{f.outbound.length - 40} more</div>}
          </div>
        </>
      )}
      {f.inbound.length > 0 && (
        <>
          <div className="section-label" style={{ padding: '8px 14px 0' }}>Reached from · {f.inbound.length}</div>
          <div className="movements">
            {f.inbound.slice(0, 40).map((e, idx) => (
              <MovementRow key={`i-${e.from || idx}`} e={e} dir="in" onPick={onPick} />
            ))}
          </div>
        </>
      )}
      {firstSeen != null && lastSeen != null && (
        <div className="note">
          Click any row to jump to that host. Times: {fmtTime(firstSeen)} – {fmtTime(lastSeen)}
        </div>
      )}
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
      if (!Array.isArray(arr)) continue
      arr.forEach((n) => nodes.add(n))
      for (let i = 0; i < arr.length - 1; i++) edges.add(`${arr[i]}->${arr[i + 1]}`)
    }
    return { nodes, edges }
  }, [data])

  const accounts = useMemo(() => (roster || []).map((a) => a?.user).filter(Boolean), [roster])

  // Base view = the loaded analysis (campaign, or one account).
  const base = useMemo(() => (
    data ? { nodes: data.nodes || [], edges: data.edges || [] } : { nodes: [], edges: [] }
  ), [data])

  // A technique drill-in from Threat Radar reduces the canvas to JUST those
  // movements (and the hosts they touch) — a focused subgraph, not an overlay on
  // the whole campaign.
  const view = useMemo(() => {
    if (!techFocus) return base
    const edges = (base.edges || []).filter((e) => techFocus.has(e?.technique))
    const keep = new Set(edges.flatMap((e) => [e?.from, e?.to]))
    return { nodes: (base.nodes || []).filter((n) => keep.has(n?.id)), edges }
  }, [base, techFocus])

  const graphData = useMemo(() => {
    let nodes = view.nodes || [], edges = view.edges || []
    // In a focused exposure view, collapse dead-end hosts (a pivot's leaf targets)
    // into one bubble per pivot — otherwise a 94-leaf star renders as a blob. The
    // full host list on the right still names every host.
    if (techFocus) {
      const deg = {}
      edges.forEach((e) => {
        if (e?.from) deg[e.from] = (deg[e.from] || 0) + 1
        if (e?.to) deg[e.to] = (deg[e.to] || 0) + 1
      })
      const byId = Object.fromEntries(nodes.map((n) => [n.id, n]))
      const isLeaf = (id) => deg[id] === 1 && !byId[id]?.pivot && !byId[id]?.critical
      const bubbles = {}, kept = [], removed = new Set()
      edges.forEach((e) => {
        const leaf = isLeaf(e.to) ? e.to : (isLeaf(e.from) ? e.from : null)
        if (leaf) { const p = leaf === e.to ? e.from : e.to; bubbles[p] = (bubbles[p] || 0) + 1; removed.add(leaf) }
        else kept.push(e)
      })
      const keptNodes = nodes.filter((n) => !removed.has(n.id))
      const bubbleEdges = []
      const tech = [...techFocus][0]
      Object.entries(bubbles).forEach(([parent, count]) => {
        const id = `${parent}→${count} hosts`
        keptNodes.push({ id, bubble: true, count })
        bubbleEdges.push({ from: parent, to: id, technique: tech, score: 0, event_count: count })
      })
      nodes = keptNodes; edges = [...kept, ...bubbleEdges]
    }
    return {
      nodes: nodes.map((n) => ({ ...n })),
      links: edges.map((e) => ({ ...e, source: e.from, target: e.to })),
    }
  }, [view, techFocus])

  // --- Attack Propagation Simulation derived from Prioritization Agent ---
  const [simPlaying, setSimPlaying] = useState(false)
  const [simStep, setSimStep] = useState(0)
  const [simSpeed, setSimSpeed] = useState(1)

  const simSteps = useMemo(() => {
    const rankedChains = bundle?.meta?.agent_pipeline?.ranked_chains || bundle?.agent_pipeline?.ranked_chains || []
    if (rankedChains.length > 0) {
      const steps = []
      rankedChains.forEach((chain, cIdx) => {
        const entity = chain.entity
        const techniques = chain.technique_ids || []
        const tactics = chain.tactic_chain || []
        const risk = chain.risk_score || 0.85
        const blast = chain.blast_radius || 1
        steps.push({
          step: steps.length + 1,
          node: entity,
          title: `Step ${steps.length + 1}: Breach vector on ${entity}`,
          tactic: tactics[0] || 'Initial Access',
          technique: techniques[0] || 'T1078',
          description: `Prioritization Agent chain #${cIdx + 1} (${(chain.risk_band || 'high').toUpperCase()} risk, ${Math.round(risk * 100)}% score). Blast radius: ${blast} host(s).`,
          riskBand: chain.risk_band || 'high',
        })
      })
      for (const [target, path] of Object.entries(data?.paths_to_critical || {})) {
        if (!Array.isArray(path)) continue
        for (let i = 0; i < path.length - 1; i++) {
          const from = path[i], to = path[i + 1]
          if (!steps.some((s) => s.from === from && s.to === to)) {
            steps.push({
              step: steps.length + 1,
              node: to,
              from,
              to,
              title: `Step ${steps.length + 1}: Lateral Pivot ${from} → ${to}`,
              tactic: 'Lateral Movement',
              technique: 'T1021',
              description: `Adversary traverses ${from} to ${to}, advancing directly toward crown jewel ${target}.`,
              riskBand: to === target ? 'critical' : 'high',
            })
          }
        }
      }
      return steps
    }

    const steps = []
    const paths = data?.paths_to_critical || {}
    const entry = data?.entry_host || view?.nodes?.find((n) => n?.pivot)?.id || view?.nodes?.[0]?.id
    if (entry) {
      steps.push({
        step: 1,
        node: entry,
        title: `Step 1: Initial Foothold on ${entry}`,
        tactic: 'Initial Access',
        technique: 'T1566.001',
        description: `Adversary compromises credentials to establish foothold on entry host ${entry}.`,
        riskBand: 'high',
      })
    }
    for (const [target, path] of Object.entries(paths)) {
      if (!Array.isArray(path)) continue
      for (let i = 0; i < path.length - 1; i++) {
        const from = path[i], to = path[i + 1]
        steps.push({
          step: steps.length + 1,
          node: to,
          from,
          to,
          title: `Step ${steps.length + 1}: Traversing ${from} → ${to}`,
          tactic: to === target ? 'Impact / Target Reached' : 'Lateral Movement',
          technique: to === target ? 'T1486' : 'T1021',
          description:
            to === target
              ? `Adversary reaches critical crown jewel ${to}. Immediate isolation required!`
              : `Adversary leverages administrative protocols to pivot deeper into subnet.`,
          riskBand: to === target ? 'critical' : 'high',
        })
      }
    }
    return steps.length
      ? steps
      : [
          {
            step: 1,
            node: view?.nodes?.[0]?.id || 'WARD-PC-013',
            title: 'Step 1: Topology Baseline',
            tactic: 'Discovery',
            technique: 'T1087',
            description: 'Attack graph initialized. Prioritization Agent active.',
            riskBand: 'low',
          },
        ]
  }, [bundle, data, view])

  const activeSimStep = simSteps[simStep] || simSteps[0]

  useEffect(() => {
    let timer = null
    if (simPlaying) {
      timer = setInterval(() => {
        setSimStep((prev) => {
          if (prev >= simSteps.length - 1) {
            setSimPlaying(false)
            return prev
          }
          const next = prev + 1
          const nextItem = simSteps[next]
          if (nextItem?.node) focus(nextItem.node)
          return next
        })
      }, 1600 / simSpeed)
    }
    return () => clearInterval(timer)
  }, [simPlaying, simSteps, simSpeed])

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
        const charge = fgRef.current.d3Force('charge')
        charge?.strength?.(-90)
        charge?.distanceMax?.(500)
        fgRef.current.d3Force('link')?.distance?.(32)
        fgRef.current.d3ReheatSimulation?.()
      } catch { /* keep default forces */ }
    }
    fitted.current = null            // refit when the graph changes
    // fallback fit in case the sim settles before onEngineStop refires
    const t = setTimeout(() => fgRef.current?.zoomToFit(500, 55), 800)
    return () => clearTimeout(t)
  }, [graphData, theme])

  const focus = (id) => {
    if (!id || !graphData?.nodes?.length) return
    const n = graphData.nodes.find((x) => x.id === id)
    setSelected(n?.bubble ? null : id)                     // bubbles have no detail
    if (n && typeof n.x === 'number' && typeof n.y === 'number' && Number.isFinite(n.x) && Number.isFinite(n.y)) {
      try {
        fgRef.current?.centerAt(n.x, n.y, 500)
        fgRef.current?.zoom(2.8, 500)
      } catch { /* canvas not initialized yet */ }
    }
  }

  if (loading) return <Loading />
  if (error) return <ErrorBox error={error} />
  if (!data) return <div style={{ padding: 24, color: 'var(--text-muted)' }}>No graph data loaded.</div>

  const neighbours = selected
    ? new Set((view?.edges || []).filter((e) => e.from === selected || e.to === selected)
        .flatMap((e) => [e.from, e.to]))
    : null

  const nodeColor = (n) => {
    if (!n) return cssVar('--sev-normal')
    if (n.bubble) return cssVar('--sev-normal')            // collapsed dead-end hosts
    if (activeSimStep?.node === n.id) return cssVar('--sev-critical') // Active simulation step
    if (selected && n.id === selected) return cssVar('--accent')
    if (n.pivot) return cssVar('--accent')
    if (n.critical) return cssVar('--sev-critical')
    if (techFocus) return cssVar('--sev-high')             // subgraph: all in-focus
    if (selected && neighbours?.has(n.id)) return cssVar('--sev-high')
    if (showPath && highlight.nodes.has(n.id)) return cssVar('--sev-high')
    return cssVar('--sev-normal')
  }
  const nodeVal = (n) => (!n ? 3 : activeSimStep?.node === n.id ? 14 : n.bubble ? 7 : n.id === selected ? 12 : n.pivot ? 9 : n.critical ? 7 : 3)
  const touchesSel = (l) => {
    if (!selected || !l) return false
    const s = typeof l.source === 'object' ? l.source?.id : l.source
    const t = typeof l.target === 'object' ? l.target?.id : l.target
    return s === selected || t === selected
  }
  const isSimEdge = (l) => {
    if (!l || !activeSimStep?.from || !activeSimStep?.to) return false
    const s = typeof l.source === 'object' ? l.source?.id : l.source
    const t = typeof l.target === 'object' ? l.target?.id : l.target
    return (s === activeSimStep.from && t === activeSimStep.to) ||
           (s === activeSimStep.to && t === activeSimStep.from)
  }
  const linkColor = (l) => {
    if (!l) return cssVar('--grid')
    if (isSimEdge(l)) return cssVar('--sev-critical')
    if (techFocus) return cssVar('--sev-high')             // every edge here matches
    if (touchesSel(l)) return cssVar('--accent')
    const s = typeof l.source === 'object' ? l.source?.id : l.source
    const t = typeof l.target === 'object' ? l.target?.id : l.target
    const key = `${s}->${t}`
    if (showPath && highlight.edges.has(key)) return cssVar('--sev-high')
    return cssVar('--grid')
  }
  const linkWidth = (l) => {
    if (!l) return 1
    if (isSimEdge(l)) return 4
    if (techFocus) return 2
    if (touchesSel(l)) return 3
    const s = typeof l.source === 'object' ? l.source?.id : l.source
    const t = typeof l.target === 'object' ? l.target?.id : l.target
    const key = `${s}->${t}`
    return showPath && highlight.edges.has(key) ? 3 : 1
  }

  const focusCount = view?.edges?.length || 0
  // pivots / crown jewels actually present in the current view (subgraph or full)
  const viewPivots = (view?.nodes || []).filter((n) => n?.pivot).map((n) => n.id)
  const viewCrown = (view?.nodes || []).filter((n) => n?.critical).map((n) => n.id)

  const critList = data?.critical_assets_at_risk || []
  const chokeList = data?.choke_points || []
  const pivotList = data?.attacker_pivots || (data?.entry_host ? [data.entry_host] : [])

  return (
    <>
      {techFocus && (
        <div className="note" style={{
          margin: '0 0 12px', display: 'flex', alignItems: 'center', gap: 10,
          borderLeft: '3px solid var(--sev-high)',
        }}>
          <Crosshair size={14} aria-hidden="true" style={{ color: 'var(--sev-high)' }} />
          <span>Focused subgraph: <b>{focusCount}</b> movement{focusCount !== 1 ? 's' : ''} using{' '}
            <b className="mono">{[...techFocus].join(', ')}</b> across <b>{view?.nodes?.length || 0}</b> hosts —
            the technique from that threat-radar hit.</span>
          <button className="btn" onClick={() => setParams({})}
            style={{ marginLeft: 'auto', padding: '2px 8px', fontSize: 11 }}>Clear</button>
        </div>
      )}
      <div className="grid2" style={{ gridTemplateColumns: '1.4fr 1fr' }}>
        <Card>
          <CardHeader title={techFocus ? 'Your exposure — attack path' : 'Attack-path graph'}
            meta={busy ? 'analyzing…' : `${view?.nodes?.length || 0} hosts · ${view?.edges?.length || 0} movements`}>
            {!techFocus && (
              <select value={account} onChange={(e) => pickAccount(e.target.value)} disabled={busy}
                aria-label="Analyze one account"
                style={{ fontSize: 12, padding: '4px 8px', marginRight: 8, maxWidth: 190 }}>
                <option value="all">All accounts — full campaign</option>
                {accounts.map((a) => <option key={a} value={a}>{a}</option>)}
              </select>
            )}
            <button className="btn" onClick={() => setShowPath((v) => !v)}
              style={{ display: 'inline-flex', gap: 6, alignItems: 'center' }}
              aria-pressed={showPath}>
              <Route size={13} aria-hidden="true" />
              {showPath ? 'Hide path' : 'Path to crown jewel'}
            </button>
          </CardHeader>

          {/* SIMULATION PLAYBACK CONTROL BOX */}
          <div
            style={{
              padding: '10px 14px',
              background: 'var(--surface-sunken)',
              borderBottom: '1px solid var(--border-soft)',
              display: 'flex',
              flexDirection: 'column',
              gap: 8,
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 8 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span className="tag-pill" style={{ background: 'var(--accent-soft)', color: 'var(--accent)', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                  <Sparkles size={11} /> Attack Propagation Simulation
                </span>
                <span className="mono" style={{ fontSize: 12, fontWeight: 600 }}>
                  Step {simStep + 1} of {simSteps.length}
                </span>
              </div>

              {/* Playback Controls */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <button
                  className="btn ghost"
                  style={{ padding: '4px 8px' }}
                  onClick={() => {
                    const prev = Math.max(0, simStep - 1)
                    setSimStep(prev)
                    if (simSteps[prev]?.node) focus(simSteps[prev].node)
                  }}
                  disabled={simStep === 0}
                  title="Step Backward"
                >
                  <SkipBack size={13} />
                </button>

                <button
                  className={`btn ${simPlaying ? 'primary' : ''}`}
                  style={{ padding: '4px 12px', display: 'inline-flex', alignItems: 'center', gap: 5 }}
                  onClick={() => setSimPlaying(!simPlaying)}
                >
                  {simPlaying ? <Pause size={13} /> : <Play size={13} />}
                  <span style={{ fontSize: 12 }}>{simPlaying ? 'Pause' : 'Play'}</span>
                </button>

                <button
                  className="btn ghost"
                  style={{ padding: '4px 8px' }}
                  onClick={() => {
                    const next = Math.min(simSteps.length - 1, simStep + 1)
                    setSimStep(next)
                    if (simSteps[next]?.node) focus(simSteps[next].node)
                  }}
                  disabled={simStep === simSteps.length - 1}
                  title="Step Forward"
                >
                  <SkipForward size={13} />
                </button>

                <button
                  className="btn ghost"
                  style={{ padding: '4px 8px' }}
                  onClick={() => {
                    setSimPlaying(false)
                    setSimStep(0)
                    if (simSteps[0]?.node) focus(simSteps[0].node)
                  }}
                  title="Reset to Step 1"
                >
                  <RotateCcw size={13} />
                </button>

                <button
                  className="btn ghost"
                  style={{ padding: '3px 7px', fontSize: 11 }}
                  onClick={() => setSimSpeed(simSpeed === 1 ? 2 : 1)}
                  title="Toggle playback speed"
                >
                  {simSpeed}x
                </button>
              </div>
            </div>

            {/* Active Simulation Step Information */}
            {activeSimStep && (
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  background: 'var(--surface-raised)',
                  padding: '6px 10px',
                  borderRadius: 4,
                  fontSize: 12,
                  lineHeight: 1.4,
                  borderLeft: `3px solid ${activeSimStep.riskBand === 'critical' ? 'var(--sev-critical)' : 'var(--accent)'}`,
                }}
              >
                <div>
                  <b>{activeSimStep.title}</b> ({activeSimStep.tactic} · <span className="mono">{activeSimStep.technique}</span>):{' '}
                  <span style={{ color: 'var(--text-muted)' }}>{activeSimStep.description}</span>
                </div>
                <span
                  className={`tag-pill ${activeSimStep.riskBand === 'critical' ? 's-critical' : 's-low'}`}
                  style={{ fontSize: 10.5, textTransform: 'uppercase', marginLeft: 8, whiteSpace: 'nowrap' }}
                >
                  {activeSimStep.riskBand} Risk
                </span>
              </div>
            )}
          </div>

          <div className="graphwrap" ref={wrapRef}>
            <ForceGraph2D
              key={theme}
              ref={fgRef}
              graphData={graphData}
              width={width || 760}
              height={440}
              backgroundColor="transparent"
              nodeColor={nodeColor}
              nodeVal={nodeVal}
              nodeRelSize={4}
              nodeLabel={(n) => (!n ? '' : n.bubble
                ? `${n.count || 0} dead-end hosts reached via ${[...(techFocus || [])].join(', ')} (see the host list)`
                : `${n.id || ''}${n.pivot ? ' · attacker pivot' : n.critical ? ' · CRITICAL' : ''} — click for detail`)}
              nodeCanvasObjectMode={(n) => (n && Number.isFinite(n.x) && Number.isFinite(n.y) && (n.bubble || n.pivot || n.critical || activeSimStep?.node === n.id) ? 'after' : undefined)}
              nodeCanvasObject={(n, ctx, scale) => {
                if (!n || !ctx || !Number.isFinite(n.x) || !Number.isFinite(n.y)) return
                try {
                  const label = n.bubble ? `+${n.count || 0} hosts` : (n.id || '')
                  const s = Number.isFinite(scale) && scale > 0 ? scale : 1
                  const size = Math.min(5.5, Math.max(3, 4 / s))
                  ctx.font = `${size}px system-ui, sans-serif`
                  ctx.fillStyle = cssVar('--text-dim') || '#94a3b8'
                  ctx.textAlign = 'center'
                  ctx.textBaseline = 'top'
                  const r = Math.sqrt(Math.max(1, nodeVal(n))) * 4 + 1
                  ctx.fillText(label, n.x, n.y + r)
                } catch { /* safe fallback */ }
              }}
              linkColor={linkColor}
              linkWidth={linkWidth}
              linkLabel={(l) => {
                if (!l) return ''
                return `${l.from || ''} → ${l.to || ''} · ${l.technique || ''} · score ${l.score || 0}` +
                  ((l.event_count || 0) > 1 ? ` · ${l.event_count} auths` : '')
              }}
              linkDirectionalParticles={(l) => {
                try {
                  return isSimEdge(l) ? 6 : showPath ? 2 : 0
                } catch {
                  return 0
                }
              }}
              linkDirectionalParticleWidth={(l) => {
                try {
                  return isSimEdge(l) ? 3.5 : 2
                } catch {
                  return 2
                }
              }}
              linkDirectionalParticleSpeed={(l) => {
                try {
                  return isSimEdge(l) ? 0.015 : 0.006
                } catch {
                  return 0.006
                }
              }}
              cooldownTicks={120}
              onEngineStop={() => {
                if (!graphData?.nodes?.length) return
                const sig = `${graphData.nodes.length}:${techFocus ? [...techFocus].join(',') : ''}`
                if (fitted.current !== sig) {
                  fitted.current = sig
                  try {
                    fgRef.current?.zoomToFit(500, 60)
                  } catch { /* ignore */ }
                }
              }}
              onNodeClick={(n) => { if (n?.id) focus(n.id) }}
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

          {techFocus ? (
            <Card>
              <CardHeader title="Exposure summary" meta={[...techFocus].join(', ')} />
              <div className="kv">
                <div className="row"><span className="k">Technique</span>
                  <span className="v mono">{[...techFocus].join(', ')}</span></div>
                <div className="row"><span className="k">Your movements using it</span>
                  <span className="v">{view?.edges?.length || 0}</span></div>
                <div className="row"><span className="k">Hosts involved</span>
                  <span className="v">{view?.nodes?.length || 0}</span></div>
                <div className="row"><span className="k">Attacker pivots here</span>
                  <span className="v mono">{viewPivots.join(' · ') || '—'}</span></div>
                <div className="row"><span className="k">Crown jewels touched</span>
                  <span className="v s-critical mono">{viewCrown.join(', ') || 'none'}</span></div>
              </div>
              <div className="note">
                This is <b>only your exposure to that threat-radar hit</b> — the movements in
                your own network using this technique. <b onClick={() => setParams({})}
                  style={{ color: 'var(--accent)', cursor: 'pointer' }}>Clear</b> to return to the
                  full campaign graph.
              </div>
            </Card>
          ) : (
            <Card>
              <CardHeader title="Blast-radius analysis" />
              <div className="kv">
                <div className="row"><span className="k">Attacker pivots</span>
                  <span className="v mono">{pivotList.join(' · ') || '—'}</span></div>
                <div className="row"><span className="k">Crown jewels at risk</span>
                  <span className="v s-critical mono">
                    {critList.length}: {critList.join(', ') || '—'}</span></div>
                <div className="row"><span className="k">Choke points</span><span className="v mono">{chokeList.join(' · ') || '—'}</span></div>
                <div className="row"><span className="k">Total exposure</span>
                  <span className="v">{data?.blast_radius_size || 0} hosts reachable from any pivot</span></div>
                <div className="row"><span className="k">Recommended isolation</span><span className="v s-high mono">{data?.recommended_isolation || '—'}</span></div>
                <div className="row"><span className="k">Graph</span><span className="v">{data?.n_nodes || 0} nodes · {data?.n_edges || 0} edges</span></div>
              </div>
              <div className="note">
                Isolating <b className="mono">{data?.recommended_isolation || 'pivot'}</b> severs{' '}
                <b>{data?.isolation_cuts ?? data?.blast_radius_size ?? 0}</b> hosts — of{' '}
                {data?.blast_radius_size ?? 0} exposed across {data?.n_pivots ?? 1} pivot
                {(data?.n_pivots ?? 1) > 1 ? 's' : ''}. Reachability is computed from every
                attacker pivot, not just the busiest one.
              </div>
            </Card>
          )}
        </div>
      </div>
    </>
  )
}
