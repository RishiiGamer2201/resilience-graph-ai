import { useState } from 'react'
import { scoreEvent } from '../api.js'
import { severityFromScore } from '../lib/format.js'
import LiveBadge from './LiveBadge.jsx'

const BOOL_FEATURES = [
  ['is_fail', 'authentication failed'],
  ['new_dst_for_user', 'first time to this host'],
  ['new_src_for_user', 'first time from this host'],
  ['is_ntlm', 'NTLM / pass-the-hash auth'],
]
const NUM_FEATURES = [
  ['user_distinct_dst_sofar', 'distinct hosts so far'],
  ['user_fail_rate_sofar', 'running fail rate'],
  ['dst_rarity', 'destination rarity'],
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
      <input type="checkbox" id={id} checked={checked} onChange={(e) => onChange(e.target.checked ? 1 : 0)}
        aria-label={label} />
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
      const r = await scoreEvent(next)
      setResult(r)
    } finally {
      setBusy(false)
    }
  }

  function preset(p) {
    setFeat(p)
    run(p)
  }

  const sev = result ? (result.severity || severityFromScore(result.anomaly_score)) : null

  return (
    <div className="livewidget">
      <div className="presets">
        <button className="btn" onClick={() => preset(MALICIOUS)}>Malicious-like</button>
        <button className="btn" onClick={() => preset(BENIGN)}>Benign-like</button>
      </div>

      <div className="feat-grid">
        {BOOL_FEATURES.map(([k, desc]) => (
          <div className="feat" key={k}>
            <label htmlFor={`sw-${k}`} title={desc}>{k}</label>
            <Switch id={`sw-${k}`} checked={!!feat[k]} onChange={(v) => set(k, v)} label={`${k}: ${desc}`} />
          </div>
        ))}
        {NUM_FEATURES.map(([k, desc]) => (
          <div className="feat" key={k}>
            <label htmlFor={`in-${k}`} title={desc}>{k}</label>
            <input id={`in-${k}`} type="number" step="0.001" value={feat[k]}
              onChange={(e) => set(k, e.target.value === '' ? 0 : Number(e.target.value))} />
          </div>
        ))}
      </div>

      <button className="btn primary" onClick={() => run()} disabled={busy} style={{ alignSelf: 'flex-start' }}>
        {busy ? 'Scoring…' : 'Score event'}
      </button>

      {result && (
        <div className="score-out">
          <div>
            <div className={`big s-${sev}`}>{result.anomaly_score}</div>
            <div className={`sevlabel s-${sev}`}>{sev}</div>
          </div>
          <div style={{ marginLeft: 'auto', textAlign: 'right' }}>
            <LiveBadge live={result.live} />
            <div style={{ fontSize: 11, color: 'var(--text-faint)', marginTop: 8 }}>
              Isolation-Forest · LANL model
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
