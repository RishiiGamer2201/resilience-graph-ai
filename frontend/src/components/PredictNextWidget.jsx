import { useEffect, useState } from 'react'
import { Plus, X } from 'lucide-react'
import { predictNext } from '../api.js'
import LiveBadge from './LiveBadge.jsx'

const START = ['T1566.001', 'T1204.002']
const SUGGEST = ['T1550.002', 'T1110', 'T1078', 'T1021']

export default function PredictNextWidget() {
  const [chain, setChain] = useState(START)
  const [draft, setDraft] = useState('')
  const [result, setResult] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)

  async function run(ids = chain) {
    if (!ids.length) { setResult(null); return }
    setBusy(true)
    setError(null)
    try {
      setResult(await predictNext(ids))
    } catch (e) {
      // No hardcoded technique list standing in for the Markov model.
      setResult(null)
      setError(e?.message || 'prediction service unreachable')
    } finally {
      setBusy(false)
    }
  }

  useEffect(() => { run(START) /* initial prediction */ }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const add = (id) => {
    const v = id.trim().toUpperCase()
    if (v && !chain.includes(v)) setChain((c) => [...c, v])
    setDraft('')
  }
  const remove = (id) => setChain((c) => c.filter((x) => x !== id))

  return (
    <div className="livewidget">
      <div className="section-label">Observed ATT&amp;CK chain</div>
      <div className="chips">
        {chain.map((id) => (
          <span className="chip-x" key={id}>
            {id}
            <button onClick={() => remove(id)} aria-label={`Remove ${id}`}><X size={12} /></button>
          </span>
        ))}
        <form className="chip-add" onSubmit={(e) => { e.preventDefault(); add(draft) }}>
          <input value={draft} onChange={(e) => setDraft(e.target.value)}
            placeholder="T1059.001" aria-label="Add technique id" />
          <button className="btn" type="submit" aria-label="Add technique">
            <Plus size={14} />
          </button>
        </form>
      </div>

      <div className="chips" style={{ marginTop: -4 }}>
        <span style={{ fontSize: 11, color: 'var(--text-faint)' }}>quick add:</span>
        {SUGGEST.filter((s) => !chain.includes(s)).map((s) => (
          <button key={s} className="btn ghost" style={{ padding: '3px 8px', fontSize: 11 }}
            onClick={() => add(s)}>+ {s}</button>
        ))}
      </div>

      <button className="btn primary" onClick={() => run()} disabled={busy || !chain.length}
        style={{ alignSelf: 'flex-start' }}>
        {busy ? 'Predicting…' : 'Predict next technique'}
      </button>

      {error && (
        <div role="alert" style={{
          marginTop: 12, padding: '10px 12px',
          border: '1px solid var(--sev-critical, #a12c26)', borderRadius: 4,
          color: 'var(--sev-critical, #a12c26)', fontSize: 13,
        }}>
          <strong>No prediction.</strong> The Markov model is unreachable ({error}).
          This panel shows model output or nothing &mdash; it will not fall back to a
          fixed list of techniques.
        </div>
      )}

      {result && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span className="section-label">Predicted next moves (Markov Engine + Agent Prediction)</span>
            <LiveBadge live={result.live} />
          </div>

          {result.projection_narrative && (
            <div
              style={{
                padding: '10px 14px',
                background: 'var(--surface-sunken)',
                borderRadius: 6,
                border: '1px solid var(--border-soft)',
                fontSize: 12,
                lineHeight: 1.55,
                color: 'var(--text)',
              }}
            >
              <div style={{ fontWeight: 600, color: 'var(--accent)', marginBottom: 4, display: 'flex', alignItems: 'center', gap: 6 }}>
                <span>🎯 Plain-English Next Moves Projection:</span>
              </div>
              <p style={{ margin: 0, whiteSpace: 'pre-wrap' }}>{result.projection_narrative}</p>
            </div>
          )}

          <div className="ranked">
            {result.predictions.map((p) => (
              <div className="pred" key={p.technique_id}>
                <span className="rk">{p.rank}</span>
                <span className="pid">{p.technique_id}</span>
                <span className="pn">{p.name}</span>
                {p.score > 0 && <span className="pscore" title="Interpolated Markov transition probability">
                  {Math.round(p.score * 100)}%</span>}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
