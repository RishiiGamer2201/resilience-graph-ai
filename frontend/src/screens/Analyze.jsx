import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Play, Upload, X, FlaskConical } from 'lucide-react'
import { getScenarios, analyze, analyzeUpload } from '../api.js'
import { useAnalysis } from '../lib/analysis.jsx'
import { Card, CardHeader } from '../components/Card.jsx'

export default function Analyze() {
  const navigate = useNavigate()
  const { setBundle } = useAnalysis()
  const [scenarios, setScenarios] = useState([])
  const [crit, setCrit] = useState([])
  const [draft, setDraft] = useState('')
  const [file, setFile] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const [status, setStatus] = useState('')

  useEffect(() => {
    getScenarios().then((d) => setScenarios(d.scenarios || [])).catch(() => setScenarios([]))
  }, [])

  const addCrit = (v) => {
    const t = v.trim()
    if (t && !crit.includes(t)) setCrit((c) => [...c, t])
    setDraft('')
  }

  async function run(fn, label) {
    setBusy(true); setError(null); setStatus(label)
    try {
      const bundle = await fn()
      setBundle(bundle)
      navigate('/overview')
    } catch (e) {
      setError(e.message || String(e))
    } finally {
      setBusy(false); setStatus('')
    }
  }

  const runScenario = (name, criticalDefault) =>
    run(() => analyze({ scenario: name, critical_assets: crit.length ? crit : criticalDefault }),
        'Scoring events…')

  const runUpload = () => {
    if (!file) return
    run(() => analyzeUpload(file, crit), `Scoring ${file.name}…`)
  }

  return (
    <>
      <div className="page-head">
        <span className="tag-pill" style={{ background: 'var(--accent-soft)', color: 'var(--accent)' }}>
          LIVE PIPELINE
        </span>
        <h2>Analyze an event log</h2>
        <p className="mono">Every event is scored by the real IsolationForest, correlated into one incident,
          mapped to ATT&amp;CK, graphed, attributed and projected — computed on the spot.</p>
      </div>

      {error && (
        <div className="errbox" style={{ marginBottom: 16 }}>
          Analysis failed.<br /><span className="mono" style={{ fontSize: 12 }}>{error}</span>
        </div>
      )}

      <div className="grid2">
        <Card>
          <CardHeader title="Sample scenarios" meta="1-click, real data" />
          <div className="card-b pad" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {scenarios.length === 0 && <div style={{ color: 'var(--text-dim)' }}>No scenarios found.</div>}
            {scenarios.map((s) => (
              <div key={s.name} className="tech" style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <FlaskConical size={18} aria-hidden="true" style={{ color: 'var(--accent)', flex: '0 0 auto' }} />
                <div style={{ minWidth: 0, flex: 1 }}>
                  <div className="th"><span className="tname">{s.label}</span></div>
                  <div className="texp">{s.description}</div>
                  <div className="mono" style={{ fontSize: 11, color: 'var(--text-faint)', marginTop: 2 }}>
                    {s.n_events} events{s.critical_default?.length ? ` · crown jewel ${s.critical_default.join(', ')}` : ''}
                  </div>
                </div>
                <button className="btn primary" disabled={busy}
                  onClick={() => runScenario(s.name, s.critical_default)}
                  style={{ display: 'inline-flex', gap: 6, alignItems: 'center', flex: '0 0 auto' }}>
                  <Play size={13} aria-hidden="true" /> Analyze
                </button>
              </div>
            ))}
          </div>
        </Card>

        <div className="stack">
          <Card>
            <CardHeader title="Upload your own log" meta="CSV · common event schema" />
            <div className="card-b pad" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div style={{ fontSize: 12, color: 'var(--text-dim)', lineHeight: 1.55 }}>
                Columns: <span className="mono">timestamp, user, source_host, destination_host,
                status, protocol</span> (extras ignored). Max 50k rows.
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-dim)', lineHeight: 1.55 }}>
                No file handy? Grab the synthetic{' '}
                <a href="/sample_bank_incident.csv" download>sample bank incident CSV</a>{' '}
                — a fictional estate (nothing like LANL) that proves the pipeline analyzes
                whatever you feed it. Add crown jewels <span className="mono">DC-MUMBAI-01, DB-COREBANK-01</span>.
              </div>
              <label className="btn" style={{ display: 'inline-flex', gap: 6, alignItems: 'center', alignSelf: 'flex-start' }}>
                <Upload size={13} aria-hidden="true" /> {file ? file.name : 'Choose CSV'}
                <input type="file" accept=".csv" hidden
                  onChange={(e) => setFile(e.target.files?.[0] || null)} />
              </label>
              <button className="btn primary" disabled={busy || !file} onClick={runUpload}
                style={{ alignSelf: 'flex-start' }}>
                {busy ? status || 'Analyzing…' : 'Analyze upload'}
              </button>
            </div>
          </Card>

          <Card>
            <CardHeader title="Critical assets (optional)" meta="hosts to protect" />
            <div className="card-b pad">
              <div className="chips">
                {crit.map((id) => (
                  <span className="chip-x" key={id}>
                    {id}
                    <button onClick={() => setCrit((c) => c.filter((x) => x !== id))} aria-label={`Remove ${id}`}>
                      <X size={12} />
                    </button>
                  </span>
                ))}
                <form className="chip-add" onSubmit={(e) => { e.preventDefault(); addCrit(draft) }}>
                  <input value={draft} onChange={(e) => setDraft(e.target.value)}
                    placeholder="C2388" aria-label="Add critical host" />
                  <button className="btn" type="submit" aria-label="Add host">Add</button>
                </form>
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-faint)', marginTop: 8 }}>
                Designate crown-jewel hosts; the graph shows shortest paths to them and the SOAR
                gate escalates to human approval when they're at risk.
              </div>
            </div>
          </Card>
        </div>
      </div>
    </>
  )
}
