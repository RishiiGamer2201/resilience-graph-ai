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

  async function run(ids = chain) {
    if (!ids.length) { setResult(null); return }
    setBusy(true)
    try {
      setResult(await predictNext(ids))
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
          <button key={s} className="btn ghost" style={{ padding: '3px 8px', fontSize: 11.5 }}
            onClick={() => add(s)}>+ {s}</button>
        ))}
      </div>

      <button className="btn primary" onClick={() => run()} disabled={busy || !chain.length}
        style={{ alignSelf: 'flex-start' }}>
        {busy ? 'Predicting…' : 'Predict next technique'}
      </button>

      {result && (
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
            <span className="section-label">Predicted next techniques</span>
            <LiveBadge live={result.live} />
          </div>
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
