import { BookOpenCheck } from 'lucide-react'
import type { BaselineStatus } from '@/types/api'

export default function BaselineLearningBanner({ baseline }: { baseline?: BaselineStatus }) {
  if (baseline?.state !== 'learning') return null

  const days = baseline.days ?? 0
  const required = baseline.min_history_days ?? 0
  const progress = Math.max(0, Math.min(100, baseline.progress_percent ?? 0))

  return (
    <section className="mb-4 rounded-lg border border-warn/40 bg-warn/5 p-3" aria-live="polite">
      <div className="flex items-start gap-2.5">
        <BookOpenCheck className="mt-0.5 size-4 shrink-0 text-warn" aria-hidden />
        <div className="min-w-0 flex-1">
          <div className="text-sm font-medium text-text">
            Learning normal behaviour: alerts and response are paused
          </div>
          <div className="mt-0.5 text-xs text-dim">
            {days.toLocaleString()} of {required.toLocaleString()} required days ·{' '}
            {(baseline.users ?? 0).toLocaleString()} accounts ·{' '}
            {(baseline.events ?? 0).toLocaleString()} historical events
          </div>
          <div
            className="mt-2 h-1.5 overflow-hidden rounded-full bg-surface-3"
            role="progressbar"
            aria-label="Entity baseline learning progress"
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={progress}
          >
            <div className="h-full bg-warn" style={{ width: `${progress}%` }} />
          </div>
          <div className="mt-1.5 text-xs text-dim">
            Detector scores are available only as non-operational diagnostics. No incident
            severity, ATT&amp;CK finding, attack path, or containment proposal is generated yet.
          </div>
        </div>
      </div>
    </section>
  )
}
