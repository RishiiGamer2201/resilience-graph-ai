import { BookOpenCheck } from 'lucide-react'
import type { BaselineStatus } from '@/types/api'

export default function BaselineLearningBanner({ baseline }: { baseline?: BaselineStatus }) {
  if (baseline?.state !== 'learning' && baseline?.state !== 'partial') return null

  const partial = baseline.state === 'partial'
  const days = baseline.active_days ?? baseline.days ?? 0
  const required = baseline.minimum_active_days ?? baseline.min_history_days ?? 0
  const requiredEvents = baseline.minimum_events_per_entity ?? 0
  const coverage = baseline.analysis_coverage?.coverage_percent
    ?? baseline.entity_coverage_percent
    ?? 0
  const progress = Math.max(
    0,
    Math.min(100, partial ? coverage : (baseline.progress_percent ?? 0)),
  )

  return (
    <section className="mb-4 rounded-lg border border-warn/40 bg-warn/5 p-3" aria-live="polite">
      <div className="flex items-start gap-2.5">
        <BookOpenCheck className="mt-0.5 size-4 shrink-0 text-warn" aria-hidden />
        <div className="min-w-0 flex-1">
          <div className="text-sm font-medium text-text">
            {partial
              ? 'Some accounts are still learning normal behaviour'
              : 'Learning normal behaviour: alerts and response are paused'}
          </div>
          <div className="mt-0.5 text-xs text-dim">
            {days.toLocaleString()} active days · {(baseline.events ?? 0).toLocaleString()}{' '}
            historical events · requires {required.toLocaleString()} days and{' '}
            {requiredEvents.toLocaleString()} events per entity ·{' '}
            {coverage.toLocaleString()}% current-event coverage
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
            {partial
              ? 'Events from mature accounts and devices remain operational. Events from new or under-observed entities are diagnostic-only and cannot create alerts or containment proposals.'
              : 'Detector scores are available only as non-operational diagnostics. No incident severity, ATT&CK finding, attack path, or containment proposal is generated yet.'}
          </div>
        </div>
      </div>
    </section>
  )
}
