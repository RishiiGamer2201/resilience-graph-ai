import { useEffect, useMemo, useRef } from 'react'
import ForceGraph2D, { type ForceGraphMethods, type NodeObject } from 'react-force-graph-2d'
import { cssVar } from '@/lib/format'
import { ROLE_LABEL, ROLE_TOKEN, type GraphLink, type GraphNode } from '@/lib/graphRoles'

export interface AttackGraph2DProps {
  nodes: GraphNode[]
  links: GraphLink[]
  selected: string | null
  onSelect: (id: string | null) => void
  showPaths: boolean
  reducedMotion: boolean
  height: number
  width: number
}

type FGNode = NodeObject<GraphNode>
type FGLink = GraphLink & { source?: string | FGNode; target?: string | FGNode }

const severityToken = (score: number): string =>
  score >= 90 ? '--sev-critical' : score >= 70 ? '--sev-high' : score >= 45 ? '--sev-medium' : '--sev-normal'

export default function AttackGraph2D({ nodes, links, selected, onSelect, showPaths, reducedMotion, height, width }: AttackGraph2DProps) {
  const graphRef = useRef<ForceGraphMethods<FGNode, FGLink> | undefined>(undefined)
  const fitted = useRef<string | null>(null)
  const graphData = useMemo<{
    nodes: (GraphNode & { x?: number; y?: number })[]
    links: GraphLink[]
  }>(() => ({ nodes: nodes.map((node) => ({ ...node })), links: links.map((link) => ({ ...link })) }), [nodes, links])
  const signature = useMemo(() => `${nodes.map((node) => node.id).join('|')}::${links.map((link) => `${link.source}>${link.target}`).join('|')}`, [nodes, links])

  useEffect(() => {
    const graph = graphRef.current
    if (!graph) return
    fitted.current = null
    const charge = graph.d3Force('charge')
    if (charge && typeof charge.strength === 'function') charge.strength(-75)
    const link = graph.d3Force('link')
    if (link && typeof link.distance === 'function') link.distance(38)
    graph.d3ReheatSimulation()
  }, [signature])

  useEffect(() => {
    const graph = graphRef.current
    if (!graph || !selected) return
    const node = graphData.nodes.find((item) => item.id === selected)
    if (!node || !Number.isFinite(node.x) || !Number.isFinite(node.y)) return
    graph.centerAt(node.x, node.y, reducedMotion ? 0 : 280)
    graph.zoom(2.6, reducedMotion ? 0 : 280)
  }, [graphData.nodes, reducedMotion, selected])

  return (
    <ForceGraph2D<GraphNode, GraphLink>
      ref={graphRef}
      graphData={graphData}
      width={width}
      height={height}
      backgroundColor="rgba(0,0,0,0)"
      nodeRelSize={4}
      nodeVal={(node) => 1 + Math.sqrt(node.degree ?? 0)}
      nodeColor={(node) => node.id === selected ? cssVar('--text', '#e6ecf5') : cssVar(ROLE_TOKEN[node.role ?? 'reached'], '#5b6678')}
      nodeLabel={(node) => `${node.id} — ${(node.roles ?? []).map((role) => ROLE_LABEL[role]).join(', ')} · ${node.degree ?? 0} movement${node.degree === 1 ? '' : 's'}${node.recommendedIsolation ? ' · recommended isolation' : ''}`}
      nodeCanvasObjectMode={() => 'after'}
      nodeCanvasObject={(node, context, globalScale) => {
        if (!node.recommendedIsolation && node.id !== selected) return
        const radius = (5 + Math.sqrt(node.degree ?? 0)) / globalScale
        context.beginPath()
        context.arc(node.x ?? 0, node.y ?? 0, radius, 0, Math.PI * 2)
        context.strokeStyle = node.id === selected ? cssVar('--text', '#e6ecf5') : cssVar('--accent', '#4c8dff')
        context.lineWidth = 2 / globalScale
        context.stroke()
      }}
      linkColor={(link) => showPaths && link.onPath ? cssVar('--accent', '#4c8dff') : cssVar(severityToken(link.score ?? 0), '#5b6678')}
      linkWidth={(link) => showPaths && link.onPath ? 2 : Math.min(1.5, 0.45 + Math.log2(1 + (link.eventCount ?? 1)) / 6)}
      linkDirectionalArrowLength={4}
      linkDirectionalArrowRelPos={1}
      linkDirectionalArrowColor={(link) => cssVar(severityToken(link.score ?? 0), '#5b6678')}
      linkDirectionalParticles={0}
      enableNodeDrag={false}
      minZoom={0.15}
      maxZoom={8}
      warmupTicks={reducedMotion ? 120 : 0}
      cooldownTicks={reducedMotion ? 0 : 120}
      onEngineStop={() => {
        if (fitted.current === signature) return
        fitted.current = signature
        graphRef.current?.zoomToFit(reducedMotion ? 0 : 350, 44)
      }}
      onNodeClick={(node) => {
        const id = typeof node.id === 'string' ? node.id : null
        onSelect(id)
        if (id) window.dispatchEvent(new CustomEvent('context-help', { detail: `${id} is a computer in the 2D attack map. Its color shows its role and its size shows how many attacker movements touched it.` }))
      }}
      onBackgroundClick={() => onSelect(null)}
    />
  )
}
