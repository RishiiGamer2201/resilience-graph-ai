import { useEffect, useMemo, useRef, useState } from 'react'
import ForceGraph2D from 'react-force-graph-2d'
import { Route } from 'lucide-react'
import { getGraph } from '../api.js'
import { useScreenData } from '../lib/analysis.jsx'
import { Card, CardHeader, Loading, ErrorBox } from '../components/Card.jsx'
import { useTheme } from '../lib/theme.jsx'
import { cssVar } from '../lib/format.js'

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

export default function Graph() {
  const { data, error, loading } = useScreenData('graph', getGraph)
  const { theme } = useTheme()
  const [wrapRef, width] = useMeasuredWidth()
  const [showPath, setShowPath] = useState(false)
  const fgRef = useRef(null)

  // Precompute highlighted node/edge sets from paths_to_critical.
  const highlight = useMemo(() => {
    const nodes = new Set()
    const edges = new Set()
    const paths = data?.paths_to_critical || {}
    for (const arr of Object.values(paths)) {
      arr.forEach((n) => nodes.add(n))
      for (let i = 0; i < arr.length - 1; i++) edges.add(`${arr[i]}->${arr[i + 1]}`)
    }
    return { nodes, edges }
  }, [data])

  const graphData = useMemo(() => {
    if (!data) return { nodes: [], links: [] }
    return {
      nodes: data.nodes.map((n) => ({ ...n })),
      links: data.edges.map((e) => ({
        source: e.from, target: e.to, technique: e.technique, tactic: e.tactic, score: e.score,
      })),
    }
  }, [data])

  useEffect(() => {
    if (fgRef.current) {
      fgRef.current.d3Force('charge')?.strength(-70)
      fgRef.current.d3ReheatSimulation?.()
    }
  }, [graphData, theme])

  if (loading) return <Loading />
  if (error) return <ErrorBox error={error} />

  const nodeColor = (n) => {
    if (n.pivot) return cssVar('--accent')
    if (n.critical) return cssVar('--sev-critical')
    if (showPath && highlight.nodes.has(n.id)) return cssVar('--sev-high')
    return cssVar('--sev-normal')
  }
  const nodeVal = (n) => (n.pivot ? 9 : n.critical ? 7 : 2)
  const linkColor = (l) => {
    const key = `${l.source.id || l.source}->${l.target.id || l.target}`
    if (showPath && highlight.edges.has(key)) return cssVar('--sev-high')
    return cssVar('--grid')
  }
  const linkWidth = (l) => {
    const key = `${l.source.id || l.source}->${l.target.id || l.target}`
    return showPath && highlight.edges.has(key) ? 3 : 1
  }

  return (
    <>
      <div className="grid2" style={{ gridTemplateColumns: '1.4fr 1fr' }}>
        <Card>
          <CardHeader title="Attack-path graph"
            meta={`${data.n_nodes} hosts · pivot ${data.entry_host}`}>
            <button className="btn" onClick={() => setShowPath((v) => !v)}
              style={{ display: 'inline-flex', gap: 6, alignItems: 'center' }}
              aria-pressed={showPath}>
              <Route size={13} aria-hidden="true" />
              {showPath ? 'Hide path' : 'Show path to critical asset'}
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
              nodeLabel={(n) => `${n.id}${n.pivot ? ' · pivot' : n.critical ? ' · CRITICAL' : ''}`}
              linkColor={linkColor}
              linkWidth={linkWidth}
              linkDirectionalParticles={showPath ? 2 : 0}
              linkDirectionalParticleWidth={2}
              cooldownTicks={120}
              onNodeClick={(n) => fgRef.current?.centerAt(n.x, n.y, 600)}
              enableNodeDrag={false}
            />
          </div>
          <div className="legend">
            <span><i style={{ background: 'var(--accent)' }} />Pivot host ({data.entry_host})</span>
            <span><i style={{ background: 'var(--sev-critical)' }} />Critical asset ({data.critical_assets_at_risk.join(', ')})</span>
            <span><i style={{ background: 'var(--sev-normal)' }} />Reached host</span>
            <span><i style={{ background: 'var(--sev-high)' }} />Highlighted path</span>
          </div>
        </Card>

        <div className="stack">
          <Card>
            <CardHeader title="Blast-radius analysis" />
            <div className="kv">
              <div className="row"><span className="k">Entry host</span><span className="v">{data.entry_host}</span></div>
              <div className="row"><span className="k">Critical assets at risk</span><span className="v s-critical">{data.critical_assets_at_risk.join(', ')}</span></div>
              <div className="row"><span className="k">Choke points</span><span className="v">{data.choke_points.join(' · ')}</span></div>
              <div className="row"><span className="k">Blast radius size</span><span className="v">{data.blast_radius_size} hosts</span></div>
              <div className="row"><span className="k">Recommended isolation</span><span className="v s-high">{data.recommended_isolation}</span></div>
              <div className="row"><span className="k">Graph size</span><span className="v">{data.n_nodes} nodes · {data.n_edges} edges</span></div>
            </div>
          </Card>

          <Card>
            <CardHeader title="Path to critical asset" />
            <div className="card-b pad" style={{ fontSize: 13, color: 'var(--text-dim)', lineHeight: 1.6 }}>
              {Object.entries(data.paths_to_critical).map(([asset, path]) => (
                <div key={asset} style={{ marginBottom: 8 }}>
                  <span className="s-critical mono" style={{ fontWeight: 700 }}>{asset}</span>
                  <div className="mono" style={{ marginTop: 4, color: 'var(--text)' }}>
                    {path.join('  →  ')}
                  </div>
                </div>
              ))}
              Isolating the single pivot <b className="mono">{data.recommended_isolation}</b> severs
              {' '}{data.blast_radius_size} downstream hosts from the citizen database.
            </div>
          </Card>
        </div>
      </div>
    </>
  )
}
