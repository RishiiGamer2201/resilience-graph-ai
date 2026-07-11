// Lightweight filled-area sparkline (SVG). Colors flow through theme vars.
export default function Sparkline({ points, width = 104, height = 42, className = 'spark' }) {
  if (!points || points.length < 2) return null
  const min = Math.min(...points)
  const max = Math.max(...points)
  const span = max - min || 1
  const pad = 4
  const px = (i) => (i / (points.length - 1)) * width
  const py = (v) => height - pad - ((v - min) / span) * (height - pad * 2)
  const line = points.map((v, i) => `${i ? 'L' : 'M'}${px(i).toFixed(1)},${py(v).toFixed(1)}`).join(' ')
  const area = `${line} L${width},${height} L0,${height} Z`
  const last = points[points.length - 1]
  return (
    <svg className={className} viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" aria-hidden="true">
      <path d={area} fill="var(--accent)" opacity="0.14" />
      <path d={line} fill="none" stroke="var(--accent)" strokeWidth="1.8"
        vectorEffect="non-scaling-stroke" strokeLinejoin="round" strokeLinecap="round" />
      <circle cx={px(points.length - 1)} cy={py(last)} r="2.4" fill="var(--accent)" />
    </svg>
  )
}
