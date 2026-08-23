/**
 * Score one hand-built event with the trained detector, live.
 *
 * The feature vector is whatever the operator types. There are no "benign" and
 * "malicious" presets any more: those were invented vectors that made the demo
 * look calibrated without any event behind them.
 *
 * The score and the severity band are the backend's. The old widget also
 * generated a client-side paragraph explaining the score from an if-ladder that
 * had never seen the model; that is gone. If the endpoint cannot be reached the
 * widget says so and shows nothing.
 */
import { useState } from 'react'
import { Zap } from 'lucide-react'
import { scoreEvent } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { ErrorState, NotMeasured, SectionLabel, SeverityBadge } from '@/components/primitives'
import type { ScoreFeatures, ScoreResult } from '@/types/api'

/** The seven features `POST /api/score-event` accepts, with what each means. */
const FLAGS: [keyof ScoreFeatures, string, string][] = [
  ['is_fail', 'Sign-in failed', 'The attempted sign-in was rejected.'],
  [
    'new_dst_for_user',
    'New destination for this account',
    'This account has not recently signed in to this computer.',
  ],
  [
    'new_src_for_user',
    'New source for this account',
    'This account has not recently signed in from this computer.',
  ],
  [
    'is_ntlm',
    'NTLM authentication',
    'Older Windows authentication, associated with pass-the-hash activity.',
  ],
]

const NUMBERS: [keyof ScoreFeatures, string, string, number][] = [
  [
    'user_distinct_dst_sofar',
    'Computers contacted so far',
    'Distinct destinations this account has reached in the window.',
    1,
  ],
  [
    'user_fail_rate_sofar',
    'Recent failure rate',
    'Share of this account’s recent sign-ins that failed, 0–1.',
    0.01,
  ],
  [
    'dst_rarity',
    'Destination rarity',
    'Higher means this computer is less common in the baseline.',
    1,
  ],
]

const EMPTY: ScoreFeatures = {
  is_fail: 0,
  new_dst_for_user: 0,
  new_src_for_user: 0,
  user_distinct_dst_sofar: 0,
  user_fail_rate_sofar: 0,
  dst_rarity: 0,
  is_ntlm: 0,
}

export default function LiveScoreWidget() {
  const [feat, setFeat] = useState<ScoreFeatures>(EMPTY)
  const [scored, setScored] = useState<ScoreFeatures | null>(null)
  const [result, setResult] = useState<ScoreResult | null>(null)
  const [error, setError] = useState<unknown>(null)
  const [busy, setBusy] = useState(false)

  const set = (k: keyof ScoreFeatures, v: number) =>
    setFeat((f) => ({ ...f, [k]: Number.isFinite(v) ? v : 0 }))

  async function run() {
    const snapshot = { ...feat }
    setBusy(true)
    setError(null)
    try {
      setResult(await scoreEvent(snapshot))
      setScored(snapshot)
    } catch (e: unknown) {
      setError(e)
      setResult(null)
    } finally {
      setBusy(false)
    }
  }

  const stale =
    result != null && scored != null && JSON.stringify(feat) !== JSON.stringify(scored)

  return (
    <div className="space-y-3 p-4">
      <div className="grid gap-2 sm:grid-cols-2">
        {FLAGS.map(([key, label, help]) => (
          <label
            key={key}
            className="flex cursor-pointer items-start gap-2 rounded-md border border-border bg-surface-2 p-2"
          >
            <input
              type="checkbox"
              checked={feat[key] === 1}
              onChange={(e) => set(key, e.target.checked ? 1 : 0)}
              className="mt-0.5 accent-accent"
            />
            <span>
              <span className="block text-xs text-text">{label}</span>
              <span className="block text-xs text-faint">{help}</span>
              <code className="text-xs text-faint">{key}</code>
            </span>
          </label>
        ))}
        {NUMBERS.map(([key, label, help, step]) => (
          <label
            key={key}
            className="flex flex-col gap-1 rounded-md border border-border bg-surface-2 p-2"
          >
            <span className="text-xs text-text">{label}</span>
            <span className="text-xs text-faint">{help}</span>
            <input
              type="number"
              min={0}
              step={step}
              value={feat[key]}
              onChange={(e) => set(key, Number(e.target.value))}
              className="w-full rounded-md border border-border bg-surface px-2 py-1 font-mono text-xs text-text"
            />
            <code className="text-xs text-faint">{key}</code>
          </label>
        ))}
      </div>

      <div className="flex items-center gap-3">
        <Button size="sm" disabled={busy} onClick={run}>
          <Zap className="size-3.5" />
          {busy ? 'Scoring…' : 'Score event'}
        </Button>
        <Button variant="ghost" size="sm" onClick={() => setFeat(EMPTY)}>
          Reset
        </Button>
        {stale ? (
          <span className="text-xs text-faint">
            Inputs changed since this score was computed.
          </span>
        ) : null}
      </div>

      {error ? <ErrorState error={error} retry={run} /> : null}

      {result ? (
        <div className="flex items-center gap-4 rounded-md border border-border bg-surface-2 p-3">
          <div>
            <SectionLabel>Anomaly score</SectionLabel>
            <div className="font-mono text-2xl tabular-nums text-text">
              {typeof result.anomaly_score === 'number' ? (
                result.anomaly_score
              ) : (
                <NotMeasured />
              )}
              <span className="ml-1 text-sm text-faint">/100</span>
            </div>
          </div>
          <SeverityBadge severity={result.severity} />
          <p className="ml-auto max-w-xs text-xs text-faint">
            Computed by the trained detector behind{' '}
            <code className="text-dim">POST /api/score-event</code>. There is no
            client-side fallback: if the endpoint is down this panel reports the
            failure instead of a plausible number.
          </p>
        </div>
      ) : null}
    </div>
  )
}
