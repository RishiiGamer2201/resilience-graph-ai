import { useState } from 'react'
import { scoreEvent } from '../api.js'
import { severityFromScore } from '../lib/format.js'
import LiveBadge from './LiveBadge.jsx'

const BOOL_FEATURES = [
  ['is_fail', 'Sign-in failed', 'The attempted sign-in was rejected.'],
  ['new_dst_for_user', 'New computer for this account', 'This account has not recently signed in to this destination.'],
  ['new_src_for_user', 'New source computer', 'This account has not recently signed in from this computer.'],
  ['is_ntlm', 'NTLM authentication', 'Older Windows authentication. It can be associated with pass-the-hash activity.'],
]
const NUM_FEATURES = [
  ['user_distinct_dst_sofar', 'Computers contacted so far', 'Number of different computers this account has contacted in the current window.'],
  ['user_fail_rate_sofar', 'Recent failed sign-ins', 'Share of this account’s recent sign-ins that failed.'],
  ['dst_rarity', 'How unusual this computer is', 'Higher values mean this destination is less common in the baseline data.'],
]

const BENIGN = {
  is_fail: 0, new_dst_for_user: 0, new_src_for_user: 0,
  user_distinct_dst_sofar: 40, user_fail_rate_sofar: 0.001, dst_rarity: 4, is_ntlm: 0,
}
const MALICIOUS = {
  is_fail: 1, new_dst_for_user: 1, new_src_for_user: 1,
  user_distinct_dst_sofar: 3, user_fail_rate_sofar: 0.5, dst_rarity: 12, is_ntlm: 1,
}

function scoreBand(score) {
  if (score >= 90) return 'very rare compared with normal sign-in behavior'
  if (score >= 70) return 'strongly unusual and worth fast investigation'
  if (score >= 45) return 'noticeably different from the baseline'
  return 'close to normal baseline activity'
}

function explainScore(features, score) {
  const reasons = []
  if (features.is_ntlm) reasons.push('NTLM authentication is enabled, which is a stronger lateral-movement signal.')
  if (features.is_fail) reasons.push('The sign-in failed, so the model sees possible guessing or misuse.')
  if (features.new_dst_for_user) reasons.push('The account is reaching a computer it does not normally use.')
  if (features.new_src_for_user) reasons.push('The account is coming from a new source computer.')
  if (features.dst_rarity >= 10) reasons.push('The destination computer is rare in the baseline.')
  else if (features.dst_rarity >= 6) reasons.push('The destination computer is somewhat uncommon.')
  if (features.user_fail_rate_sofar >= 0.2) reasons.push('Recent failed sign-ins are high for this account.')
  else if (features.user_fail_rate_sofar >= 0.05) reasons.push('Recent failed sign-ins are elevated.')
  if (features.user_distinct_dst_sofar >= 100) reasons.push('The account has contacted an unusually large number of computers in this window.')
  else if (features.user_distinct_dst_sofar <= 5) reasons.push('The account has contacted only a small set of computers in this window, which can look like focused probing.')

  if (!reasons.length) {
    reasons.push('No major risky switches are enabled, failed sign-ins are low, and the destination is not especially rare.')
  }

  return {
    summary: `A score of ${score} means this event is ${scoreBand(score)}.`,
    reasons: reasons.slice(0, 4),
  }
}

function Switch({ checked, onChange, id, label }) {
  return (
    <button
      type="button"
      className={`sw${checked ? ' on' : ''}`}
      id={id}
      role="switch"
      aria-checked={checked}
      aria-label={label}
      onClick={(event) => {
        event.stopPropagation()
        onChange(checked ? 0 : 1)
      }}
    >
      <span className="track" /><span className="knob" />
    </button>
  )
}

export default function LiveScoreWidget() {
  const [feat, setFeat] = useState(BENIGN)
  const [result, setResult] = useState(null)
  const [scoredFeat, setScoredFeat] = useState(null)
  const [busy, setBusy] = useState(false)
  const set = (k, v) => setFeat((f) => ({ ...f, [k]: v }))

  async function run(next = feat) {
    const snapshot = { ...next }
    setBusy(true)
    try {
      setResult(await scoreEvent(snapshot))
      setScoredFeat(snapshot)
    } finally {
      setBusy(false)
    }
  }

  function preset(p) {
    setFeat({ ...p })
  }

  const sev = result ? (result.severity || severityFromScore(result.anomaly_score)) : null
  const scoreExplanation = result && scoredFeat ? explainScore(scoredFeat, result.anomaly_score) : null
  const inputsChanged = result && scoredFeat && JSON.stringify(feat) !== JSON.stringify(scoredFeat)
  const displayValue = (key) => key === 'user_fail_rate_sofar' ? Number((feat[key] * 100).toFixed(1)) : feat[key]
  const updateNumber = (key, value) => {
    const number = value === '' ? 0 : Number(value)
    set(key, key === 'user_fail_rate_sofar' ? number / 100 : number)
  }

  return (
    <div className="livewidget">
      <div className="presets">
        <button className="btn" onClick={() => preset(MALICIOUS)}>Malicious-like</button>
        <button className="btn" onClick={() => preset(BENIGN)}>Benign-like</button>
      </div>

      <div className="feat-grid">
        {BOOL_FEATURES.map(([key, label, help]) => (
          <div className="feat feat-clickable" key={key} onClick={() => set(key, feat[key] ? 0 : 1)}>
            <div className="feature-copy"><span>{label}</span><small>{help}</small></div>
            <Switch id={`sw-${key}`} checked={!!feat[key]} onChange={(value) => set(key, value)} label={`${label}: ${help}`} />
          </div>
        ))}
        {NUM_FEATURES.map(([key, label, help]) => (
          <div className="feat" key={key}>
            <label htmlFor={`in-${key}`}><span>{label}</span><small>{help}</small></label>
            <div className="feature-input">
              <input id={`in-${key}`} type="number" min="0" step={key === 'user_fail_rate_sofar' ? '0.1' : '1'} value={displayValue(key)} onChange={(e) => updateNumber(key, e.target.value)} />
              {key === 'user_fail_rate_sofar' && <span>%</span>}
            </div>
          </div>
        ))}
      </div>

      <details className="technical-details">
        <summary>Technical field names</summary>
        <div>{[...BOOL_FEATURES, ...NUM_FEATURES].map(([key, label]) => <div key={key}><code>{key}</code>: {label}</div>)}</div>
      </details>

      <button className="btn primary" onClick={() => run()} disabled={busy} style={{ alignSelf: 'flex-start' }}>
        {busy ? 'Scoring…' : 'Score event'}
      </button>

      {inputsChanged && (
        <div className="score-pending">Inputs changed. Click Score event to calculate a new score.</div>
      )}

      {result && (
        <div className="score-out">
          <div><div className={`big s-${sev}`}>{result.anomaly_score}</div><div className={`sevlabel s-${sev}`}>{sev}</div></div>
          <div className="score-explain">
            <div className="score-explain-title">Why this score?</div>
            <p>{scoreExplanation.summary}</p>
            <ul>
              {scoreExplanation.reasons.map((reason) => <li key={reason}>{reason}</li>)}
            </ul>
          </div>
          <div className="score-model">
            <LiveBadge live={result.live} />
            <div style={{ fontSize: 11, color: 'var(--text-faint)', marginTop: 8 }}>Isolation-Forest · LANL model</div>
          </div>
        </div>
      )}
    </div>
  )
}
