/**
 * The attack graph in three dimensions.
 *
 * This module is the ONLY place three.js is imported, and `Graph.tsx` pulls it
 * in with `React.lazy` so the whole renderer lands in its own chunk and never
 * reaches the entry bundle.
 *
 * It renders the graph the backend returned and nothing else. There are no
 * synthetic nodes, no filler hosts, no decorative particles and no ambient
 * animation: every sphere is a host that appears in `/api/graph`, every line is
 * an aggregated authentication pair, and the encoding is stated in the legend
 * that `Graph.tsx` renders beside it.
 *
 * Colour  = the host's role in the incident (severity/accent tokens only).
 * Size    = degree, the number of movements that touched the host.
 * Ring    = `recommended_isolation`, the one host the backend proposes cutting.
 *
 * Orbit is opt-in and the parent refuses to enable it under
 * `prefers-reduced-motion`. Nothing spins on its own.
 */
import { useEffect, useMemo, useRef } from 'react'
import ForceGraph3D, {
  type ForceGraphMethods,
  type NodeObject,
} from 'react-force-graph-3d'
import { Mesh, MeshBasicMaterial, Object3D, TorusGeometry } from 'three'
import { cssVar } from '@/lib/format'
import {
  ROLE_LABEL,
  ROLE_TOKEN,
  type Graph3DLink,
  type Graph3DNode,
} from '@/lib/graphRoles'

export interface AttackGraph3DProps {
  nodes: Graph3DNode[]
  links: Graph3DLink[]
  selected: string | null
  onSelect: (id: string | null) => void
  /** Highlight the backend's `paths_to_critical` edges. */
  showPaths: boolean
  /** Opt-in camera orbit. The parent never passes true under reduced motion. */
  orbit: boolean
  reducedMotion: boolean
  height: number
  width: number
}

type FGNode = NodeObject<NodeObject<Graph3DNode>>
type FGLink = { score?: number; onPath?: boolean; eventCount?: number }

const sevToken = (score: number): string =>
  score >= 90
    ? '--sev-critical'
    : score >= 70
      ? '--sev-high'
      : score >= 45
        ? '--sev-medium'
        : '--sev-normal'

export default function AttackGraph3D({
  nodes,
  links,
  selected,
  onSelect,
  showPaths,
  orbit,
  reducedMotion,
  height,
  width,
}: AttackGraph3DProps) {
  const fgRef = useRef<ForceGraphMethods<FGNode, FGLink> | undefined>(undefined)
  const fitted = useRef<string | null>(null)

  // force-graph mutates what it is handed (it writes x/y/z onto nodes and swaps
  // link endpoints for node objects), so it gets its own copies.
  const graphData = useMemo<{
    nodes: (Graph3DNode & { x?: number; y?: number; z?: number })[]
    links: Graph3DLink[]
  }>(
    () => ({ nodes: nodes.map((n) => ({ ...n })), links: links.map((l) => ({ ...l })) }),
    [nodes, links],
  )

  // Counts alone are not an identity: account-scoped graphs can replace every
  // host/edge while retaining the same totals. Include the topology so a route
  // data change always reheats and refits the new graph.
  const signature = useMemo(
    () =>
      `${nodes.map((node) => node.id).join('\u001f')}\u001e${links
        .map((link) => `${link.source}\u001f${link.target}`)
        .join('\u001e')}`,
    [nodes, links],
  )

  // Loosen repulsion: 400+ hosts at the default charge fling the components
  // apart and zoomToFit then frames mostly empty space.
  useEffect(() => {
    const fg = fgRef.current
    if (!fg) return
    fitted.current = null
    const charge = fg.d3Force('charge')
    if (charge && typeof charge.strength === 'function') charge.strength(-60)
    const link = fg.d3Force('link')
    if (link && typeof link.distance === 'function') link.distance(28)
    fg.d3ReheatSimulation()
  }, [signature])

  // Camera orbit. Opt-in, and stopped the moment the flag clears — there is no
  // idle animation loop in this component.
  useEffect(() => {
    if (!orbit || reducedMotion) return
    let raf = 0
    const tick = () => {
      const fg = fgRef.current
      if (fg) {
        const pos = fg.camera().position
        const r = Math.hypot(pos.x, pos.z)
        const a = Math.atan2(pos.x, pos.z) + 0.0025
        fg.cameraPosition({ x: r * Math.sin(a), z: r * Math.cos(a) })
      }
      raf = requestAnimationFrame(tick)
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [orbit, reducedMotion])

  // Fly to the selected host. Selection is a state change, so it may animate;
  // under reduced motion it cuts instead.
  useEffect(() => {
    const fg = fgRef.current
    if (!fg || !selected) return
    const n = graphData.nodes.find((x) => x.id === selected)
    if (!n || !Number.isFinite(n.x) || !Number.isFinite(n.y) || !Number.isFinite(n.z)) return
    const x = n.x ?? 0
    const y = n.y ?? 0
    const z = n.z ?? 0
    const d = 1 + 120 / Math.max(1, Math.hypot(x, y, z))
    fg.cameraPosition(
      { x: x * d, y: y * d, z: z * d },
      { x, y, z },
      reducedMotion ? 0 : 320,
    )
  }, [selected, graphData, reducedMotion])

  return (
    <ForceGraph3D<Graph3DNode, Graph3DLink>
      ref={fgRef}
      graphData={graphData}
      width={width}
      height={height}
      backgroundColor="rgba(0,0,0,0)"
      showNavInfo={false}
      nodeRelSize={2.5}
      nodeVal={(n: FGNode) => 1 + (n.degree ?? 0)}
      nodeColor={(n: FGNode) =>
        cssVar(ROLE_TOKEN[n.role ?? 'reached'], '#5b6678')
      }
      nodeOpacity={0.92}
      nodeResolution={8}
      nodeLabel={(n: FGNode) =>
        `${n.id} — ${(n.roles ?? []).map((r) => ROLE_LABEL[r]).join(', ')} · ` +
        `${n.degree ?? 0} movement${n.degree === 1 ? '' : 's'}` +
        (n.recommendedIsolation ? ' · recommended isolation' : '')
      }
      // The one host the backend recommends isolating carries a ring rather
      // than a sixth hue: the palette has five distinguishable severity/accent
      // colours and inventing a decorative one would break the token contract.
      nodeThreeObjectExtend
      nodeThreeObject={(n: FGNode) => {
        if (!n.recommendedIsolation) return new Object3D()
        const r = 3 + Math.cbrt(1 + (n.degree ?? 0)) * 2.5
        const ring = new Mesh(
          new TorusGeometry(r, 0.45, 6, 28),
          new MeshBasicMaterial({ color: cssVar('--accent', '#4c8dff') }),
        )
        ring.rotation.x = Math.PI / 2
        return ring
      }}
      linkColor={(l: FGLink) =>
        showPaths && l.onPath
          ? cssVar('--accent', '#4c8dff')
          : cssVar(sevToken(l.score ?? 0), '#5b6678')
      }
      linkOpacity={0.35}
      linkWidth={(l: FGLink) =>
        showPaths && l.onPath ? 1.6 : Math.min(1.2, 0.3 + Math.log2(1 + (l.eventCount ?? 1)) / 6)
      }
      linkDirectionalArrowLength={2.4}
      linkDirectionalArrowRelPos={1}
      linkDirectionalArrowColor={(l: FGLink) =>
        cssVar(sevToken(l.score ?? 0), '#5b6678')
      }
      // Deliberately zero. Travelling dots on every edge are decoration, and
      // this graph has 400+ of them.
      linkDirectionalParticles={0}
      enableNodeDrag={false}
      // Reduced motion gets the settled layout with no visible simulation.
      warmupTicks={reducedMotion ? 120 : 0}
      cooldownTicks={reducedMotion ? 0 : 120}
      onEngineStop={() => {
        if (fitted.current === signature) return
        fitted.current = signature
        fgRef.current?.zoomToFit(reducedMotion ? 0 : 400, 40)
      }}
      onNodeClick={(n: FGNode) => onSelect(typeof n.id === 'string' ? n.id : null)}
      onBackgroundClick={() => onSelect(null)}
    />
  )
}
