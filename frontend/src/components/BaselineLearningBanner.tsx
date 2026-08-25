import { BookOpenCheck, TriangleAlert } from 'lucide-react'
import type { BaselineStatus } from '@/types/api'

export default function BaselineLearningBanner({ baseline }: { baseline?: BaselineStatus }) {
  // A failed enrolment is reported before anything else. Without this a
  // half-enrolled store reads as `learning` indefinitely: the counts look young
  // and nothing on screen says a batch stopped part-way, so the operator waits
  // for a baseline that is never going to finish maturing.
  if (baseline?.state === 'error') {
    const last = baseline.enrollment?.last
    return (
      <section className="mb-4 rounded-lg border border-bad/40 bg-bad/5 p-3" aria-live="polite">
        <div className="flex items-start gap-2.5">
          <TriangleAlert className="mt-0.5 size-4 shrink-0 text-bad" aria-hidden />
          <div className="min-w-0 flex-1">
            <div className="text-sm font-medium text-text">
              Baseline enrolment failed: history is incomplete
            </div>
            <div className="mt-0.5 font-mono text-xs text-dim">
              {last?.rows_done?.toLocaleString() ?? '?'} of{' '}
              {last?.rows?.toLocaleString() ?? '?'} rows folded in
              {last?.error ? ` · ${last.error}` : ''}
            </div>
            <div className="mt-1.5 text-xs text-dim">
              The rows that did land are counted once and kept. Re-run the same
              enrolment to resume from where it stopped; it will not double-count
              what is already in the store.
            </div>
          </div>
        </div>
      </section>
    )
  }

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
