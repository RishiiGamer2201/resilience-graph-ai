import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { CircleAlert, Crosshair, Play, RotateCcw, Target } from 'lucide-react'
import { Card, CardHeader } from '../components/Card.jsx'
import StageRail from '../components/StageRail.jsx'
import Headline from '../components/Headline.jsx'
import Assessment, { ClaimsPanel } from '../components/Assessment.jsx'
import EvidenceList from '../components/EvidenceList.jsx'
import CaseFile from '../components/CaseFile.jsx'
import CrossCheck from '../components/CrossCheck.jsx'
import ReasoningAgents from '../components/ReasoningAgents.jsx'
import ActionPanel from '../components/ActionPanel.jsx'
import AuditPanel from '../components/AuditPanel.jsx'
import ExplainTrace from '../components/ExplainTrace.jsx'
import { TwinPanel, VulnPanel } from '../components/ImpactPanel.jsx'
import Progression from '../components/Progression.jsx'
import { getCapabilities, getScenarios, investigate, resetAudit, twinCandidates } from '../api.js'
import { useAnalysis } from '../lib/analysis.jsx'
import { useSession } from '../lib/session.jsx'
import { incidentCount, scaleSuffix } from '../lib/format.js'
import { CalibrationNote } from '../components/CalibrationBadge.jsx'

// The hero scenario: a concrete Indian critical-infrastructure story with a named
// crown jewel and a real asset inventory, so vulnerability prioritisation has
// something honest to work with. LANL stays available as the real-red-team
// evidence run.
const HERO = 'aiims_ransomware'

function Section({ id, title, subtitle, children, registerRef }) {
  return (
    <section className="inv-section" id={id} ref={(el) => registerRef?.(id, el)}>
      <div className="section-label">
        {title}
        {subtitle && <span className="sl-sub"> -- {subtitle}</span>}
      </div>
      {children}
    </section>
  )
}

export default function Investigate() {
  const navigate = useNavigate()
  const { setBundle } = useAnalysis()
  const { role } = useSession()
  const [scenarios, setScenarios] = useState([])
  const [scenario, setScenario] = useState(HERO)
  const [result, setResult] = useState(null)
  const [candidates, setCandidates] = useState([])
  const [caps, setCaps] = useState(null)
  const [running, setRunning] = useState(false)
  const [error, setError] = useState(null)
  const [auditKey, setAuditKey] = useState(0)
  const [active, setActive] = useState(null)
  const refs = useRef({})

  const registerRef = useCallback((id, el) => { refs.current[id] = el }, [])

  useEffect(() => {
    getScenarios().then((d) => setScenarios(d.scenarios || [])).catch(() => setScenarios([]))
    getCapabilities().then(setCaps).catch(() => setCaps(null))
  }, [])

  const meta = scenarios.find((s) => s.name === scenario)
  // stable identity: `run` depends on it, and a fresh array every render would
  // rebuild the callback (and re-fire anything keyed on it) for no reason
  const crit = useMemo(() => meta?.critical_default || [], [meta])

  const run = useCallback(async () => {
    setRunning(true); setError(null); setResult(null); setCandidates([])
    try {
      const r = await investigate({ scenario, critical_assets: crit })
      setResult(r)
      // every other screen renders this same analysis
      setBundle({ ...r.signals, meta: r.meta })
      setAuditKey((k) => k + 1)
      try {
        const c = await twinCandidates({ graph: r.signals.graph, limit: 6 })
        setCandidates(c.candidates)
      } catch { /* twin is optional; the investigation stands without it */ }
    } catch (e) {
      setError(e.message)
    } finally {
      setRunning(false)
    }
  }, [scenario, crit, setBundle])

  async function resetDemo() {
    setResult(null); setCandidates([]); setError(null); setActive(null)
    setBundle(null)
    try { await resetAudit() } catch { /* viewer may not reset; harmless */ }
    setAuditKey((k) => k + 1)
  }

  function jump(node) {
    setActive(node)
    refs.current[node]?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }

  const degraded = caps?.degraded || []
  const inc = result?.signals?.incident
  const graph = result?.signals?.graph
  const incidents = incidentCount(inc?.incident_count ?? result?.meta?.incident_count)

  return (
    <>
      {degraded.length > 0 && (
        <div className="degraded-banner">
          <CircleAlert size={15} aria-hidden="true" />
          Running degraded: {degraded.join(', ')}. The investigation still completes -- each
          stage reports what it could not do instead of hiding it.
        </div>
      )}

      <Card className="inv-control">
        <div className="card-b pad ctrl-row">
          <label htmlFor="scenario">Scenario</label>
          <select id="scenario" value={scenario} disabled={running}
            onChange={(e) => setScenario(e.target.value)}>
            {scenarios.map((s) => (
              <option key={s.name} value={s.name}>{s.label} · {s.n_events} events</option>
            ))}
          </select>
          <span className="dim crit">
            <Target size={12} aria-hidden="true" /> crown jewels:{' '}
            <span className="mono">{crit.join(', ') || 'none designated'}</span>
          </span>
          <span className="spacer" />
          <button className="btn primary" disabled={running || role === 'viewer'} onClick={run}
            title={role === 'viewer' ? 'A viewer may not run an analysis -- switch role in the top bar' : undefined}>
            <Play size={13} aria-hidden="true" /> {running ? 'Investigating…' : 'Run investigation'}
          </button>
          <button className="btn" disabled={running} onClick={resetDemo}>
            <RotateCcw size={13} aria-hidden="true" /> Reset demo
          </button>
        </div>
        <StageRail trace={result?.trace} running={running} onJump={jump} active={active} />
      </Card>

      {error && (
        <div className="errbox" style={{ marginTop: 16 }}>
          Investigation failed.<br /><span className="mono" style={{ fontSize: 12 }}>{error}</span>
        </div>
      )}

      {result && (
        <>
          <Headline headline={result.headline} />
          <Assessment assessment={result.headline.assessment}
            likelihood={result.headline.attack_progression_likelihood}
            confidence={result.headline.evidence_confidence} />

          <Section id="understand" title="1 · Understand" registerRef={registerRef}
            subtitle="what we were given, and what is missing">
            <Card>
              <div className="card-b pad kv">
                {[
                  ['Source', `${result.understand.source} · provenance ${result.understand.provenance}`],
                  ['Events', `${result.understand.n_events}`],
                  ['Accounts', `${result.understand.accounts_total}`],
                  ['Hosts', `${result.understand.hosts_total}`],
                  ['Crown jewels designated', result.understand.crown_jewels_designated.join(', ') || 'none'],
                  ['Columns defaulted by schema', result.understand.columns_missing.join(', ') || 'none'],
                  ['Crown jewels absent from this log',
                    result.understand.crown_jewels_not_in_log.join(', ') || 'none'],
                ].map(([k, v]) => (
                  <div className="row" key={k}>
                    <span className="k">{k}</span><span className="v">{v}</span>
                  </div>
                ))}
              </div>
            </Card>
          </Section>

          <Section id="plan" title="2 · Plan" registerRef={registerRef}
            subtitle="only the tools this case needs">
            <Card>
              <div className="card-b pad">
                <ul className="planlist">
                  {(result.trace.nodes.find((n) => n.node === 'plan')?.output?.steps || []).map((s) => (
                    <li key={s.node} className={s.selected ? 'on' : 'off'}>
                      <b>{s.node}</b> <span className="mono dim">{s.tool}</span>
                      <div className="dim">{s.why}</div>
                    </li>
                  ))}
                </ul>
                <p className="fineprint">
                  {result.trace.bounded_by}. There is no free-running agent loop here.
                </p>
              </div>
            </Card>
          </Section>

          <Section id="evidence" title="3 · Evidence" registerRef={registerRef}
            subtitle="official sources, hashed and dated">
            <div className="stack">
              <Card>
                <div className="card-b pad"><EvidenceList evidence={result.evidence} /></div>
              </Card>
              {/* Only appears for a scenario styled after a documented real
                  incident. Synthetic scenarios correctly show nothing here. */}
              <CaseFile casefile={result.casefile} />
            </div>
          </Section>

          <Section id="signals" title="4 · Signals" registerRef={registerRef}
            subtitle="detect, correlate, map, predict">
            <div className="grid2">
              <Card>
                {/* Correlation returns however many incidents it found. The
                    title used to say "One" and the row used to end in a literal
                    1, beside two live numbers from the same object. */}
                <CardHeader title={incidents} meta={inc.incident_id} />
                <div className="card-b pad kv">
                  {[
                    ['Severity', `${inc.severity} · peak score ${inc.max_anomaly_score}/100${scaleSuffix(result.meta?.calibration)}`],
                    ['Collapsed', `${inc.event_count} events → ${inc.alert_count} alerts → ${incidents}`],
                    ['Accounts', `${inc.accounts_involved?.length ?? 0}`],
                    ['ATT&CK chain', inc.technique_ids.join(' → ') || '--'],
                    ['Attacker pivot', graph.entry_host],
                    ['Crown jewels reachable', graph.critical_assets_at_risk.join(', ') || 'none'],
                  ].map(([k, v]) => (
                    <div className="row" key={k}>
                      <span className="k">{k}</span><span className="v">{v}</span>
                    </div>
                  ))}
                </div>
                {result.meta?.calibration?.note && (
                  <div style={{ padding: '0 16px 14px' }}>
                    <CalibrationNote cal={result.meta.calibration} />
                  </div>
                )}
              </Card>
              <Card>
                <CardHeader title="Predicted next moves" meta="interpolated Markov" />
                <div className="card-b pad">
                  <ul className="predlist">
                    {(result.signals.report?.predicted_next || []).map((p, i) => (
                      <li key={p.technique_id}>
                        <span className="mono rank">{i + 1}</span>
                        <b className="mono">{p.technique_id}</b> {p.name}
                      </li>
                    ))}
                    {!result.signals.report?.predicted_next?.length && (
                      <li className="dim">No prediction: no technique observed yet.</li>
                    )}
                  </ul>
                  <p className="fineprint">
                    Measured top-3 accuracy and the baseline it beats are on the{' '}
                    <button className="linkish" onClick={() => navigate('/scoreboard')}>
                      PS7 scoreboard
                    </button>.
                  </p>
                </div>
              </Card>
            </div>
            <Card style={{ marginTop: 18 }}>
              <CardHeader title="What we actually claim"
                meta="observed · inferred · predicted" />
              <div className="card-b pad">
                <ClaimsPanel claims={result.impact?.claims} />
              </div>
            </Card>
            {/* A second, differently-built analysis of the same log. Advisory:
                the workflow governs, but agreement or disagreement here moves
                evidence confidence. */}
            <div style={{ marginTop: 18 }}>
              <CrossCheck crosscheck={result.crosscheck} />
            </div>
            {/* Both lanes above are deterministic. This one is not: it is the
                only place a model decides what to look at next, which is why
                it is opt-in and why its citations are checked in code. */}
            <div style={{ marginTop: 18 }}>
              <ReasoningAgents scenario={result.scenario}
                criticalAssets={result.understand?.crown_jewels_designated}
                incidentId={result.incident_id} />
            </div>
          </Section>

          <Section id="replan" title="5 · Replan" registerRef={registerRef}
            subtitle="one bounded retry on an evidence gap">
            <Card>
              <div className="card-b pad">
                {result.trace.nodes.filter((n) => n.node === 'replan').map((n, i) => (
                  <div key={n.summary + i} className="replan-row">
                    <span className="mono chip">pass {i + 1}</span> {n.summary}
                    {n.notes.map((x) => <div key={x} className="dim">{x}</div>)}
                  </div>
                ))}
              </div>
            </Card>
          </Section>

          <Section id="impact" title="6 · Impact" registerRef={registerRef}
            subtitle="reachability, counterfactual containment, patch queue">
            <div className="stack">
              {/* Where the attack goes next, before the containment that stops it. */}
              <Progression forecast={result.impact?.progression_forecast} />
              <TwinPanel graph={graph} counterfactual={result.impact.counterfactual}
                candidates={candidates.length ? candidates : result.impact.containment_candidates} />
              <VulnPanel vulns={result.impact.vulnerabilities} />
            </div>
          </Section>

          <Section id="action" title="7 · Action" registerRef={registerRef}
            subtitle="simulated, gated, recorded">
            <div className="stack">
              <ActionPanel action={result.action} incidentId={inc.incident_id}
                techniqueIds={inc.technique_ids}
                evidence={result.evidence.citations}
                affected={graph.critical_assets_at_risk}
                onDecided={() => setAuditKey((k) => k + 1)} />
              <AuditPanel refreshKey={auditKey} onReset={() => setAuditKey((k) => k + 1)} />
            </div>
          </Section>

          <Section id="explain" title="Why did you flag this?" registerRef={registerRef}
            subtitle="one raw log line, all the way to the action">
            <ExplainTrace scenario={scenario} criticalAssets={crit} />
          </Section>

          <p className="fineprint bottom">
            <Crosshair size={12} aria-hidden="true" /> LLM: {result.llm.provider}. {result.llm.note}
          </p>
        </>
      )}

      {/* The first thing a new reader sees, and for a long time it was a
          paragraph about the CISA KEV catalogue. Someone who has just opened
          this does not need to know what a crown jewel is; they need to know
          what the button does and what will happen after they press it. */}
      {!result && !running && (
        <Card className="howto">
          <div className="card-b pad">
            <h3>What this does</h3>
            <p className="howto-lede">
              It reads a log of who signed in to which computer -- the kind every
              organisation already keeps -- and finds the attacker who is using a
              real employee&rsquo;s login rather than breaking in. That is the
              attacker normal defences miss, because nothing they do is
              technically forbidden.
            </p>

            <ol className="howto-steps">
              <li>
                <b>Press Run investigation.</b>
                <span>Takes about ten seconds. Nothing is uploaded and nothing on
                  your network is touched.</span>
              </li>
              <li>
                <b>Read the summary.</b>
                <span>One sentence on what happened, how many computers are at
                  risk, and what to do about it.</span>
              </li>
              <li>
                <b>Check the working.</b>
                <span>Every number links back to the evidence behind it, and the
                  ones we could not measure say so.</span>
              </li>
            </ol>

            <p className="howto-foot">
              The example is a hospital ransomware campaign: a phished ward PC
              reaches the patient database and the domain controller. To see the
              system judged against real red-team ground truth instead, pick the
              LANL campaign above -- 2,732 real sign-ins, 104 accounts the red team
              actually compromised.
            </p>
          </div>
        </Card>
      )}
    </>
  )
}
