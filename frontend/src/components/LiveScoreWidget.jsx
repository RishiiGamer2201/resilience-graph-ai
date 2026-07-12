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

function Switch({ checked, onChange, id, label }) {
  return (
    <span className="sw">
      <input type="checkbox" id={id} checked={checked} onChange={(e) => onChange(e.target.checked ? 1 : 0)} aria-label={label} />
      <span className="track" /><span className="knob" />
    </span>
  )
}

export default function LiveScoreWidget() {
  const [feat, setFeat] = useState(BENIGN)
  const [result, setResult] = useState(null)
  const [busy, setBusy] = useState(false)
  const set = (k, v) => setFeat((f) => ({ ...f, [k]: v }))

  async function run(next = feat) {
    setBusy(true)
    try {
      setResult(await scoreEvent(next))
    } finally {
      setBusy(false)
    }
  }

  function preset(p) {
    setFeat(p)
    run(p)
  }

  const sev = result ? (result.severity || severityFromScore(result.anomaly_score)) : null
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
          <div className="feat" key={key}>
            <label htmlFor={`sw-${key}`}><span>{label}</span><small>{help}</small></label>
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
        <div>{[...BOOL_FEATURES, ...NUM_FEATURES].map(([key, label]) => <div key={key}><code>{key}</code> — {label}</div>)}</div>
      </details>

      <button className="btn primary" onClick={() => run()} disabled={busy} style={{ alignSelf: 'flex-start' }}>
        {busy ? 'Scoring…' : 'Score event'}
      </button>

      {result && (
        <div className="score-out">
          <div><div className={`big s-${sev}`}>{result.anomaly_score}</div><div className={`sevlabel s-${sev}`}>{sev}</div></div>
          <div style={{ marginLeft: 'auto', textAlign: 'right' }}>
            <LiveBadge live={result.live} />
            <div style={{ fontSize: 11, color: 'var(--text-faint)', marginTop: 8 }}>Isolation-Forest · LANL model</div>
          </div>
        </div>
      )}
    </div>
  )
}
