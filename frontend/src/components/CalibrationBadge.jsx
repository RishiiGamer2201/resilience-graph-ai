// What scale the anomaly scores on screen are actually on.
//
// A score of 78 from the shipped LANL anchors and a 78 from a within-log ranking
// are different claims, and the number alone cannot tell them apart. This is the
// same job the topbar's LIVE/SAMPLE pill does for data provenance, so it uses the
// same .pill vocabulary.
//
// Every word and number here comes out of `meta.calibration`. Without a live
// bundle there is no calibration block, so nothing renders -- guessing a basis
// is exactly the failure this badge exists to prevent.
import { AlertTriangle, Ruler } from 'lucide-react'
import { useAnalysis } from '../lib/analysis.jsx'

function useCalibration(cal) {
  const { bundle } = useAnalysis()
  return cal || bundle?.meta?.calibration || null
}

export default function CalibrationBadge({ cal: given, label = 'score scale' }) {
  const cal = useCalibration(given)
  if (!cal?.basis) return null
  const ood = !!cal.out_of_distribution
  return (
    <span className={`pill cal ${ood ? 'ood' : 'anchored'}`}
      title={cal.note || 'Fixed calibration anchors: this score means the same thing in any log.'}>
      {ood ? <AlertTriangle size={12} aria-hidden="true" /> : <Ruler size={12} aria-hidden="true" />}
      <span className="sr-only">{label}: </span>
      <span className="calbasis">{cal.basis}</span>
    </span>
  )
}

// The full explanation, one click away. Only out-of-distribution runs carry a
// note, so in-distribution runs render nothing rather than an empty disclosure.
export function CalibrationNote({ cal: given }) {
  const cal = useCalibration(given)
  if (!cal?.note) return null
  return (
    <details className="calnote">
      <summary>Why these scores are not comparable with another log</summary>
      <p>{cal.note}</p>
      <p className="mono">basis: {cal.basis} · rarity shift: {cal.rarity_shift_sigma}σ</p>
    </details>
  )
}
