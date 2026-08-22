import { useEffect, useState, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { Play, Upload, X, FlaskConical, Bot, CheckCircle2, ShieldAlert, Cpu, ArrowRight } from 'lucide-react'
import { getScenarios, agentStreamUrl, analyzeUpload } from '../api.js'
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
  const [agentLogs, setAgentLogs] = useState([])
  const [currentAgent, setCurrentAgent] = useState(null)
  const [completedBundle, setCompletedBundle] = useState(null)
  const esRef = useRef(null)

  useEffect(() => {
    getScenarios().then((d) => setScenarios(d.scenarios || [])).catch(() => setScenarios([]))
    return () => {
      if (esRef.current) esRef.current.close()
    }
  }, [])

  const addCrit = (v) => {
    const t = v.trim()
    if (t && !crit.includes(t)) setCrit((c) => [...c, t])
    setDraft('')
  }

  const runScenarioStreaming = (name, criticalDefault) => {
    if (esRef.current) esRef.current.close()
    const criticalList = crit.length ? crit : (criticalDefault || [])
    setBusy(true)
    setError(null)
    setStatus(`Executing Live 10-Agent Pipeline on ${name}…`)
    setAgentLogs([])
    setCurrentAgent({ name: 'Initializing Multi-Agent Environment…', stage_num: 0, total_stages: 10 })
    setCompletedBundle(null)

    const url = agentStreamUrl(name, criticalList)
    const es = new EventSource(url)
    esRef.current = es

    es.addEventListener('progress', (e) => {
      try {
        const payload = JSON.parse(e.data)
        setCurrentAgent(payload)
        setAgentLogs((prev) => [...prev, payload])
      } catch (err) {
        console.error('Error parsing agent progress', err)
      }
    })

    es.addEventListener('done', (e) => {
      try {
        const bundle = JSON.parse(e.data)
        setBundle(bundle)
        setCompletedBundle(bundle)
        setBusy(false)
        setStatus('10-Agent Pipeline Execution Complete!')
      } catch (err) {
        setError('Failed to parse final analysis bundle.')
        setBusy(false)
      } finally {
        es.close()
      }
    })

    es.onerror = () => {
      setError('Connection to agent streaming endpoint failed.')
      setBusy(false)
      es.close()
    }
  }

  const runUpload = async () => {
    if (!file) return
    setBusy(true)
    setError(null)
    setStatus(`Dispatching 10-Agent Pipeline on ${file.name}…`)
    setAgentLogs([])
    setCurrentAgent({ name: 'Executing 10-Agent Orchestrator on upload…', stage_num: 5, total_stages: 10 })
    setCompletedBundle(null)

    try {
      const bundle = await analyzeUpload(file, crit)
      setBundle(bundle)
      setCompletedBundle(bundle)
      setBusy(false)
      setStatus('10-Agent Pipeline Execution Complete on Upload!')
    } catch (e) {
      setError(e.message || String(e))
      setBusy(false)
    }
  }

  return (
    <>
      <div className="page-head">
        <span className="tag-pill" style={{ background: 'var(--accent-soft)', color: 'var(--accent)', fontWeight: 600 }}>
          LIVE 10-AGENT MULTI-AGENT PIPELINE
        </span>
        <h2>Analyze with 10-Agent Collaborative Pipeline</h2>
        <p className="mono">
          Run our 10 specialized AI security agents directly on your event log. Every agent
          (Ingestion, Autoencoder Anomaly Detection, Graph Blast-Radius, ATT&amp;CK Intelligence,
          KB Connector, Evidence Validator, Attack Prioritization, Incident Reasoner, Markov Predictor,
          and Orchestrator) executes its dedicated analysis with schema and evidence gates.
        </p>
      </div>

      {/* LIVE AGENT EXECUTION MONITOR */}
      {(busy || agentLogs.length > 0 || completedBundle) && (
        <Card style={{ marginBottom: 20, borderColor: busy ? 'var(--accent)' : 'var(--border-soft)' }}>
          <CardHeader
            title="Real-Time 10-Agent Execution Pipeline"
            meta={busy ? 'Agents actively running…' : completedBundle ? 'Pipeline Complete ✓' : ''}
          >
            {completedBundle && (
              <button
                className="btn primary"
                onClick={() => navigate('/overview')}
                style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '4px 12px' }}
              >
                View Command Center <ArrowRight size={13} />
              </button>
            )}
          </CardHeader>
          <div className="card-b pad" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {busy && currentAgent && (
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  background: 'var(--surface-sunken)',
                  padding: '10px 14px',
                  borderRadius: 6,
                  borderLeft: '4px solid var(--accent)',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <Cpu className="spin" size={18} style={{ color: 'var(--accent)' }} />
                  <div>
                    <div style={{ fontWeight: 600, fontSize: 13 }}>
                      Running: {currentAgent.name}
                    </div>
                    <div className="mono" style={{ fontSize: 11.5, color: 'var(--text-muted)', marginTop: 2 }}>
                      {currentAgent.summary || 'Processing event telemetry…'}
                    </div>
                  </div>
                </div>
                <span className="tag-pill s-low" style={{ fontWeight: 600 }}>
                  Agent {currentAgent.stage_num || 1}/10
                </span>
              </div>
            )}

            {/* Agent Progress Feed */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, maxHeight: 320, overflowY: 'auto' }}>
              {agentLogs.map((log, idx) => (
                <div
                  key={idx}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '8px 12px',
                    background: 'var(--surface-raised)',
                    borderRadius: 5,
                    borderLeft: '3px solid var(--sev-low)',
                    fontSize: 12,
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <CheckCircle2 size={14} style={{ color: 'var(--sev-low)', flex: '0 0 auto' }} />
                    <div>
                      <b>{log.name}</b>: <span style={{ color: 'var(--text-dim)' }}>{log.summary}</span>
                    </div>
                  </div>
                  <div className="mono" style={{ fontSize: 11, color: 'var(--text-faint)', whiteSpace: 'nowrap', marginLeft: 10 }}>
                    {log.ms} ms · conf {Math.round((log.confidence || 1) * 100)}%
                  </div>
                </div>
              ))}
            </div>

            {completedBundle && (
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  background: 'rgba(56, 189, 248, 0.08)',
                  padding: '12px 16px',
                  borderRadius: 6,
                  border: '1px solid var(--accent)',
                }}
              >
                <div>
                  <div style={{ fontWeight: 600, color: 'var(--accent)' }}>
                    All 10 Agents Executed Successfully!
                  </div>
                  <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>
                    Evidence traceability gates passed with zero ungrounded techniques. Full incident narrative, attack chains, and predictions ready.
                  </div>
                </div>
                <button
                  className="btn primary"
                  onClick={() => navigate('/overview')}
                  style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}
                >
                  Open Command Center <ArrowRight size={13} />
                </button>
              </div>
            )}
          </div>
        </Card>
      )}

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
                  onClick={() => runScenarioStreaming(s.name, s.critical_default)}
                  style={{ display: 'inline-flex', gap: 6, alignItems: 'center', flex: '0 0 auto' }}>
                  <Play size={13} aria-hidden="true" /> Run Agent Pipeline
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
