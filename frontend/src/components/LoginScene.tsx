/**
 * The login hero: a slowly drifting point-and-line network, authored in code.
 *
 * WHY THIS EXISTS AT ALL. DESIGN.md bans decorative motion and floating blobs,
 * and grants exactly one exception: "The only 3D in the product renders real
 * data or is the login scene." This is that scene. It reads as network topology
 * because that is what the product operates on — nodes and the edges between
 * them — and it is deliberately low contrast so it never competes with the card
 * sitting on top of it. Accent and nothing else: no bloom, no glow, no second
 * hue.
 *
 * NOTE FOR LATER: a Spline export can replace this component wholesale. Keep
 * the same contract — a single default export that fills its positioned parent,
 * renders nothing but the accent token, and is safe to fail — and drop the
 * .splinecode scene in here. It is authored in code today because the build has
 * to work fully offline, with no external asset and no CDN.
 *
 * DEGRADATION. This component is only ever mounted on top of a static
 * `grid-bg` layer that the screen paints unconditionally, so every failure path
 * (no WebGL, a chunk that will not load, a driver that throws) simply leaves
 * that background visible. Under `prefers-reduced-motion` the canvas renders a
 * single still frame and then stops: same picture, no movement.
 */
import { useMemo, useRef } from 'react'
import { Canvas, useFrame } from '@react-three/fiber'
import { useReducedMotion } from 'motion/react'
import type { BufferAttribute, Group } from 'three'

/** Node count and link radius chosen so the graph reads as a sparse estate,
 *  around three or four neighbours a node, not a dense cloud. */
const COUNT = 96
const LINK_DIST = 1.8
const SPREAD: readonly [number, number, number] = [16, 9, 5]
/** Peak excursion of a node from its resting position, in world units. */
const DRIFT = 0.22

/** Deterministic PRNG. The topology must be identical on every load: a login
 *  screen that reshuffles itself between refreshes looks unfinished. */
function mulberry32(seed: number): () => number {
  let a = seed
  return () => {
    a = (a + 0x6d2b79f5) | 0
    let t = Math.imul(a ^ (a >>> 15), 1 | a)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

interface Topology {
  /** Resting positions, xyz per node. */
  base: Float32Array
  /** Per-axis phase offset so nodes do not drift in lockstep. */
  phase: Float32Array
  /** Flat pairs of node indices, two per edge. */
  edges: Uint16Array
}

function buildTopology(): Topology {
  const rnd = mulberry32(0x5eed)
  const base = new Float32Array(COUNT * 3)
  const phase = new Float32Array(COUNT * 3)
  for (let i = 0; i < COUNT; i += 1) {
    for (let axis = 0; axis < 3; axis += 1) {
      base[i * 3 + axis] = (rnd() - 0.5) * SPREAD[axis]
      phase[i * 3 + axis] = rnd() * Math.PI * 2
    }
  }
  const pairs: number[] = []
  const r2 = LINK_DIST * LINK_DIST
  for (let i = 0; i < COUNT; i += 1) {
    for (let j = i + 1; j < COUNT; j += 1) {
      const dx = base[i * 3] - base[j * 3]
      const dy = base[i * 3 + 1] - base[j * 3 + 1]
      const dz = base[i * 3 + 2] - base[j * 3 + 2]
      if (dx * dx + dy * dy + dz * dz < r2) pairs.push(i, j)
    }
  }
  return { base, phase, edges: Uint16Array.from(pairs) }
}

/** Write the node positions at time `t` and mirror them into the edge buffer.
 *  One function so the still frame and the animated frames cannot disagree. */
function sample(topo: Topology, nodes: Float32Array, links: Float32Array, t: number): void {
  const { base, phase, edges } = topo
  for (let i = 0; i < COUNT; i += 1) {
    const k = i * 3
    nodes[k] = base[k] + Math.sin(t * 0.11 + phase[k]) * DRIFT
    nodes[k + 1] = base[k + 1] + Math.cos(t * 0.09 + phase[k + 1]) * DRIFT
    nodes[k + 2] = base[k + 2] + Math.sin(t * 0.07 + phase[k + 2]) * DRIFT
  }
  for (let e = 0; e < edges.length; e += 1) {
    const n = edges[e] * 3
    links[e * 3] = nodes[n]
    links[e * 3 + 1] = nodes[n + 1]
    links[e * 3 + 2] = nodes[n + 2]
  }
}

function Network({ color, animate }: { color: string; animate: boolean }) {
  const topo = useMemo(buildTopology, [])
  const buffers = useMemo(() => {
    const nodes = new Float32Array(COUNT * 3)
    const links = new Float32Array(topo.edges.length * 3)
    sample(topo, nodes, links, 0)
    return { nodes, links }
  }, [topo])

  const group = useRef<Group>(null)
  const nodeAttr = useRef<BufferAttribute>(null)
  const linkAttr = useRef<BufferAttribute>(null)

  useFrame(({ clock }) => {
    if (!animate) return
    const t = clock.getElapsedTime()
    sample(topo, buffers.nodes, buffers.links, t)
    if (nodeAttr.current) nodeAttr.current.needsUpdate = true
    if (linkAttr.current) linkAttr.current.needsUpdate = true
    // A slow sway rather than a spin: parallax, not a turntable.
    if (group.current) group.current.rotation.y = Math.sin(t * 0.035) * 0.18
  })

  return (
    <group ref={group}>
      <lineSegments>
        <bufferGeometry>
          <bufferAttribute
            ref={linkAttr}
            attach="attributes-position"
            args={[buffers.links, 3]}
          />
        </bufferGeometry>
        <lineBasicMaterial color={color} transparent opacity={0.14} depthWrite={false} />
      </lineSegments>
      <points>
        <bufferGeometry>
          <bufferAttribute
            ref={nodeAttr}
            attach="attributes-position"
            args={[buffers.nodes, 3]}
          />
        </bufferGeometry>
        <pointsMaterial
          color={color}
          size={0.055}
          sizeAttenuation
          transparent
          opacity={0.5}
          depthWrite={false}
        />
      </points>
    </group>
  )
}

export default function LoginScene() {
  const reduced = useReducedMotion()
  // The accent token, read once. Never a literal colour: DESIGN.md section 3.
  const accent = useMemo(
    () => getComputedStyle(document.documentElement).getPropertyValue('--accent').trim(),
    [],
  )
  if (!accent) return null

  return (
    <Canvas
      style={{ position: 'absolute', inset: 0 }}
      aria-hidden
      dpr={[1, 1.75]}
      camera={{ position: [0, 0, 9], fov: 45 }}
      // "demand" renders one frame and then stops. A reviewer with reduced
      // motion on gets the same picture, held still.
      frameloop={reduced ? 'demand' : 'always'}
      gl={{ alpha: true, antialias: true, powerPreference: 'low-power' }}
    >
      <Network color={accent} animate={!reduced} />
    </Canvas>
  )
}
