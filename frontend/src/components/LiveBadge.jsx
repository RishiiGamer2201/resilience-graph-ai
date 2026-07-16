// Subtle "live" (real backend) vs "cached" (fallback) indicator.
export default function LiveBadge({ live }) {
  return (
    <span className={`badge ${live ? 'on' : 'off'}`} title={live
      ? 'Result from the live model endpoint'
      : 'Backend unreachable: showing deterministic cached fallback'}>
      {live ? '● live' : '○ cached'}
    </span>
  )
}
