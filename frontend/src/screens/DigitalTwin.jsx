import { useEffect, useRef, useState } from 'react'
import {
  ArrowRight,
  Bot,
  Cpu,
  HelpCircle,
  MessageSquare,
  RefreshCw,
  Scissors,
  Send,
  Shield,
  ShieldAlert,
  Sparkles,
  User,
  Zap,
} from 'lucide-react'
import { getCapabilities, getGraph, twinCandidates, twinChat, twinSimulate } from '../api.js'
import { Card, CardHeader, ErrorBox, Loading } from '../components/Card.jsx'
import { useAnalysis, useScreenData } from '../lib/analysis.jsx'

function DiffBadge({ label, before, after, betterWhenLower = true }) {
  const changed = before !== after
  const better = betterWhenLower ? after < before : after > before
  return (
    <div className="diff" style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '4px 8px', background: 'var(--surface-sunken)', borderRadius: 4 }}>
      <span className="k" style={{ fontSize: 12 }}>{label}:</span>
      <span className="mono b" style={{ fontSize: 12 }}>{before}</span>
      <ArrowRight size={11} aria-hidden="true" />
      <span className={`mono a ${changed ? (better ? 's-low' : 's-critical') : ''}`} style={{ fontSize: 12, fontWeight: 600 }}>
        {after}
      </span>
    </div>
  )
}

const QUICK_PROMPTS = [
  'Explain this incident in simple words for our executive team.',
  'What will happen if we isolate the recommended entry host?',
  'Which crown-jewel assets are in immediate danger and why?',
  'What CERT-In or CISA threat advisories apply to this attack?',
]

export default function DigitalTwin() {
  const { data: graphData, error: graphErr, loading: graphLoading } = useScreenData('graph', getGraph)
  const { bundle } = useAnalysis()
  const [candidates, setCandidates] = useState([])
  const [sim, setSim] = useState(null)
  const [simBusy, setSimBusy] = useState(null)
  const [simError, setSimError] = useState(null)

  // Chat State
  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      content:
        'I explain this incident in plain English, using only figures the analysis already computed.\n\nAsk what is at risk, what to isolate, which advisories apply, or what this analysis cannot tell you.\n\n_I restate and explain. I do not decide, and I do not approve actions._',
      sources: [],
      follow_ups: QUICK_PROMPTS.slice(0, 3),
    },
  ])
  const [input, setInput] = useState('')
  const [chatBusy, setChatBusy] = useState(false)
  // What the backend says about the language-model layer, so the header
  // reports what is actually on rather than a fixed claim.
  const [llm, setLlm] = useState(null)
  const chatBottomRef = useRef(null)

  const activeGraph = bundle?.graph || graphData

  useEffect(() => {
    if (activeGraph?.nodes?.length) {
      twinCandidates({ graph: activeGraph, limit: 6 })
        .then((res) => setCandidates(res.candidates || []))
        .catch(() => setCandidates([]))
    }
  }, [activeGraph])

  useEffect(() => {
    chatBottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, chatBusy])

  async function handleSimulate(host) {
    if (!host || !activeGraph) return
    setSimBusy(host)
    setSimError(null)
    try {
      const res = await twinSimulate({ graph: activeGraph, isolate_host: host })
      setSim(res)
    } catch (e) {
      setSimError(e.message)
    } finally {
      setSimBusy(null)
    }
  }

  async function handleSendMessage(textToSend) {
    const text = (textToSend || input).trim()
    if (!text || chatBusy) return

    const newHistory = [...messages, { role: 'user', content: text }]
    setMessages(newHistory)
    setInput('')
    setChatBusy(true)

    try {
      const res = await twinChat({
        message: text,
        history: newHistory.map((m) => ({ role: m.role, content: m.content })),
        graph: activeGraph,
        scenario: bundle?.meta?.scenario || 'aiims_ransomware',
        incident_id: bundle?.incident?.incident_id || 'INC-LIVE-001',
      })

      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          content: res.reply,
          sources: res.sources || [],
          follow_ups: res.follow_ups || [],
          method: res.method,
          model: res.model || '',
          llmError: res.llm_error || '',
        },
      ])
      setLlm(res.llm || null)
    } catch (e) {
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          content: `I encountered an issue retrieving the advisory response: ${e.message}. Please try again.`,
          sources: [],
          follow_ups: QUICK_PROMPTS.slice(0, 2),
        },
      ])
    } finally {
      setChatBusy(false)
    }
  }

  if (graphLoading) return <Loading />
  if (graphErr) return <ErrorBox error={graphErr} />

  const entryHost = activeGraph?.entry_host || 'WARD-PC-013'
  const critAssets = activeGraph?.critical_assets_at_risk || []
  const cost = sim?.operational_cost

  return (
    <>
      <div className="page-head">
        <span className="tag-pill" style={{ background: 'var(--accent-soft)', color: 'var(--accent)', fontWeight: 600 }}>
          DIGITAL TWIN &amp; PLAIN-LANGUAGE COPILOT
        </span>
        <h2>Digital Twin Simulation Lab &amp; AI Advisor</h2>
        <p className="mono">
          Simulate zero-risk counterfactual containment on a cloned attack graph and ask the
          executive advisor for plain-English explanations.
        </p>
      </div>

      <div className="grid2" style={{ alignItems: 'start', gap: 20 }}>
        {/* LEFT COLUMN: Digital Twin Containment Simulation */}
        <div className="stack" style={{ gap: 16 }}>
          <Card>
            <CardHeader
              title={
                <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Cpu size={16} /> Counterfactual Containment Twin
                </span>
              }
              meta="deterministic graph simulation · no live mutation"
            />
            <div className="card-b pad stack-sm">
              <div className="kv" style={{ background: 'var(--surface-sunken)', padding: '10px 14px', borderRadius: 6 }}>
                <div className="row">
                  <span className="k">Simulated Entry Pivot</span>
                  <span className="v mono" style={{ fontWeight: 600 }}>{entryHost}</span>
                </div>
                <div className="row">
                  <span className="k">Target Crown Jewels</span>
                  <span className="v s-critical mono" style={{ fontWeight: 600 }}>
                    {critAssets.length ? critAssets.join(', ') : 'None immediate'}
                  </span>
                </div>
                <div className="row">
                  <span className="k">Total Reachable Blast Radius</span>
                  <span className="v mono">{activeGraph?.blast_radius_size || activeGraph?.n_nodes || 0} host(s)</span>
                </div>
              </div>

              <div className="section-label" style={{ marginTop: 8 }}>
                Ranked Containment Candidates (Benefit vs Operational Cost)
              </div>

              {simError && <div className="errbox">{simError}</div>}

              <div style={{ overflowX: 'auto' }}>
                <table className="tbl" style={{ width: '100%' }}>
                  <thead>
                    <tr>
                      <th scope="col">Isolate Host</th>
                      <th scope="col">Crown Jewels Saved</th>
                      <th scope="col">Blast Cut</th>
                      <th scope="col">Disruption</th>
                      <th scope="col">Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(candidates || []).map((c) => {
                      const isSelected = sim?.candidate?.isolate_host === c.host
                      return (
                        <tr key={c.host} className={isSelected ? 'sel' : undefined}>
                          <th scope="row" className="mono" style={{ fontWeight: 600 }}>{c.host}</th>
                          <td>
                            {c.crown_jewels_protected?.length ? (
                              <span className="tag-pill s-low" style={{ padding: '2px 6px', fontSize: 11 }}>
                                {c.crown_jewels_protected.join(', ')}
                              </span>
                            ) : (
                              <span className="dim">none</span>
                            )}
                          </td>
                          <td className="mono" style={{ fontSize: 12 }}>
                            -{c.blast_radius_reduction} ({c.blast_radius_reduction_pct}%)
                          </td>
                          <td className="mono" style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                            {c.sessions_severed} sess · {c.accounts_disrupted} users
                          </td>
                          <td>
                            <button
                              className={`btn ${isSelected ? 'primary' : ''}`}
                              style={{ padding: '3px 9px', fontSize: 12 }}
                              disabled={simBusy === c.host}
                              onClick={() => handleSimulate(c.host)}
                            >
                              <Scissors size={12} aria-hidden="true" />{' '}
                              {simBusy === c.host ? 'Simulating…' : 'Simulate'}
                            </button>
                          </td>
                        </tr>
                      )
                    })}
                    {!candidates?.length && (
                      <tr>
                        <td colSpan={5} className="dim" style={{ textAlign: 'center', padding: 16 }}>
                          No containment candidates found in this topology.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>

              {/* Simulation Result Card */}
              {sim && (
                <div
                  className="twin-result"
                  style={{
                    marginTop: 12,
                    padding: 14,
                    background: 'var(--surface-sunken)',
                    borderRadius: 6,
                    border: '1px solid var(--border-soft)',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <ShieldAlert size={16} style={{ color: 'var(--accent)' }} />
                      <b className="mono" style={{ fontSize: 13 }}>
                        Simulated Isolation of {sim.candidate?.isolate_host}
                      </b>
                    </div>
                    <span className="tag-pill" style={{ background: 'var(--surface-raised)', fontSize: 11 }}>
                      Counterfactual Delta
                    </span>
                  </div>

                  <p className="verdict" style={{ fontSize: 13, lineHeight: 1.5, marginBottom: 12 }}>
                    {sim.verdict}
                  </p>

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 12 }}>
                    <DiffBadge label="Blast Radius" before={sim.before.blast_radius} after={sim.after.blast_radius} />
                    <DiffBadge
                      label="Exposed Jewels"
                      before={sim.before.crown_jewels_reachable.length}
                      after={sim.after.crown_jewels_reachable.length}
                    />
                  </div>

                  {cost && (
                    <div style={{ fontSize: 11.5, color: 'var(--text-muted)', lineHeight: 1.4, borderTop: '1px dashed var(--border-soft)', paddingTop: 8 }}>
                      <b>Operational Cost:</b> Disconnects {cost.hosts_taken_offline} host ({cost.sessions_severed} active sessions), disrupting {cost.accounts_disrupted?.length || 0} user account(s).
                    </div>
                  )}
                </div>
              )}
            </div>
          </Card>
        </div>

        {/* RIGHT COLUMN: Digital Twin AI Advisor Chatbot */}
        <div className="stack" style={{ gap: 16 }}>
          <Card>
            <CardHeader
              title={
                <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Bot size={16} style={{ color: 'var(--accent)' }} /> Digital Twin AI Advisor (Plain English)
                </span>
              }
              meta={
                llm?.enabled
                  ? `${llm.active_provider} · ${llm.providers?.[llm.active_provider]?.model || ''} · not authoritative`
                  : 'offline · deterministic templates · no language model'
              }
            />
            <div className="card-b pad" style={{ display: 'flex', flexDirection: 'column', height: 580 }}>
              {/* Chat Messages Container */}
              <div
                style={{
                  flex: 1,
                  overflowY: 'auto',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 14,
                  paddingRight: 4,
                  marginBottom: 12,
                }}
              >
                {messages.map((m, idx) => {
                  const isUser = m.role === 'user'
                  return (
                    <div
                      key={idx}
                      style={{
                        display: 'flex',
                        flexDirection: 'column',
                        alignItems: isUser ? 'flex-end' : 'flex-start',
                        gap: 4,
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: 'var(--text-faint)' }}>
                        {isUser ? <User size={12} /> : <Sparkles size={12} style={{ color: 'var(--accent)' }} />}
                        <span>{isUser ? 'You (Incident Commander)' : 'Digital Twin Advisor'}</span>
                      </div>
                      <div
                        style={{
                          maxWidth: '92%',
                          padding: '10px 14px',
                          borderRadius: 8,
                          fontSize: 13,
                          lineHeight: 1.55,
                          background: isUser ? 'var(--accent)' : 'var(--surface-sunken)',
                          color: isUser ? '#fff' : 'var(--text)',
                          border: isUser ? 'none' : '1px solid var(--border-soft)',
                          whiteSpace: 'pre-wrap',
                        }}
                      >
                        {m.content}
                      </div>

                      {/* Where this reply came from. The API returns it; not
                          showing it let a template read as a model answer. */}
                      {!isUser && m.method && (
                        <div
                          style={{
                            marginTop: 4,
                            fontSize: 10.5,
                            color: 'var(--text-faint)',
                            fontFamily: 'var(--mono)',
                          }}
                        >
                          {m.method === 'deterministic'
                            ? `template · no language model${m.llmError ? ` · ${m.llmError}` : ''}`
                            : `${m.method}${m.model ? ` · ${m.model}` : ''} · reworded, not authoritative`}
                        </div>
                      )}

                      {/* Evidence Citations */}
                      {!isUser && m.sources?.length > 0 && (
                        <div style={{ marginTop: 4, maxWidth: '92%' }}>
                          <div style={{ fontSize: 11, color: 'var(--text-faint)', marginBottom: 4, display: 'flex', alignItems: 'center', gap: 4 }}>
                            <Shield size={11} /> Cited Cyber Intelligence:
                          </div>
                          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                            {m.sources.map((s, sIdx) => (
                              <a
                                key={sIdx}
                                href={s.url}
                                target="_blank"
                                rel="noreferrer"
                                className="tag-pill"
                                style={{
                                  fontSize: 10.5,
                                  background: 'var(--surface-raised)',
                                  color: 'var(--accent)',
                                  border: '1px solid var(--border-soft)',
                                  textDecoration: 'none',
                                  display: 'inline-flex',
                                  alignItems: 'center',
                                  gap: 4,
                                }}
                                title={s.excerpt}
                              >
                                <b>{s.publisher}:</b> {s.title.slice(0, 24)}…
                              </a>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Follow-up question suggestions */}
                      {!isUser && m.follow_ups?.length > 0 && idx === messages.length - 1 && (
                        <div style={{ marginTop: 8, display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                          {m.follow_ups.map((q, qIdx) => (
                            <button
                              key={qIdx}
                              className="btn ghost"
                              style={{
                                fontSize: 11,
                                padding: '3px 8px',
                                borderRadius: 12,
                                textAlign: 'left',
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: 4,
                              }}
                              onClick={() => handleSendMessage(q)}
                            >
                              <HelpCircle size={11} /> {q}
                            </button>
                          ))}
                        </div>
                      )}
                    </div>
                  )
                })}

                {chatBusy && (
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 12px', background: 'var(--surface-sunken)', borderRadius: 8, width: 'fit-content' }}>
                    <RefreshCw size={14} className="spin" style={{ color: 'var(--accent)' }} />
                    <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Synthesizing plain-English advisor guidance…</span>
                  </div>
                )}
                <div ref={chatBottomRef} />
              </div>

              {/* Quick Prompt Pills */}
              <div style={{ display: 'flex', gap: 6, overflowX: 'auto', paddingBottom: 8, marginBottom: 4 }}>
                {QUICK_PROMPTS.map((qp, pIdx) => (
                  <button
                    key={pIdx}
                    className="btn ghost"
                    style={{ fontSize: 11, whiteSpace: 'nowrap', padding: '3px 9px', borderRadius: 4 }}
                    onClick={() => handleSendMessage(qp)}
                    disabled={chatBusy}
                  >
                    <Zap size={10} style={{ color: 'var(--accent)' }} /> {qp}
                  </button>
                ))}
              </div>

              {/* Chat Input Form */}
              <form
                onSubmit={(e) => {
                  e.preventDefault()
                  handleSendMessage()
                }}
                style={{ display: 'flex', gap: 8, alignItems: 'center' }}
              >
                <input
                  type="text"
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  placeholder="Ask the advisor to explain this incident, risks, or next steps in plain English…"
                  style={{
                    flex: 1,
                    padding: '8px 12px',
                    borderRadius: 6,
                    border: '1px solid var(--border-soft)',
                    background: 'var(--surface-sunken)',
                    color: 'var(--text)',
                    fontSize: 13,
                  }}
                  disabled={chatBusy}
                />
                <button
                  type="submit"
                  className="btn primary"
                  disabled={chatBusy || !input.trim()}
                  style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '8px 14px' }}
                >
                  <Send size={14} /> Send
                </button>
              </form>
            </div>
          </Card>
        </div>
      </div>
    </>
  )
}
