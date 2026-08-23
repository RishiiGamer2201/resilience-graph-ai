import { useState } from 'react'
import { Bot, Gavel, Route, ShieldAlert, Sparkles } from 'lucide-react'
import { Card, CardHeader } from './Card.jsx'
import { reasonWithAgents } from '../api.js'

// Two agents over the attack graph, and the guard rails around them.
//
// The panel above this one compares two DETERMINISTIC lanes. This one is the
// only place in the product where a language model chooses what to do next:
// an Investigator picks which of seven graph questions to ask, then a Critic
// is handed the same tools and told to refute whatever the Investigator
// concluded.
//
// It is opt-in because it is several model round trips and takes tens of
// seconds, and because a product that quietly calls a third party on page load
// is not one you can hand to a hospital.
//
// The part worth reading on screen is the citation row. Every tool result is
// tagged with an evidence id, and a claim citing an id the agent never
// received is dropped in Python before it reaches this component. On the first
// live run two of five citations were invented. Showing the rejections is the
// point: an agent lane that cannot be caught lying is not evidence of anything.

const WHO = { investigator: Bot, critic: Gavel }

function ToolTrace({ calls }) {
  if (!calls?.length) return <div className="dim">No tool was called.</div>
  return (
    <ol className="rz-trace">
      {calls.map((c, i) => {
        const Icon = WHO[c.agent] || Route
        return (
          <li key={i} className={c.error ? 'rz-step err' : 'rz-step'}>
            <Icon size={13} aria-hidden="true" />
            <span className="rz-who">{c.agent}</span>
            <span className="mono rz-tool">{c.tool}</span>
            <span className="rz-rows">
              {c.error ? c.error : `${c.rows} row${c.rows === 1 ? '' : 's'}`}
            </span>
          </li>
        )
      })}
    </ol>
  )
}

export default function ReasoningAgents({ scenario, criticalAssets = [], incidentId }) {
  const [run, setRun] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)

  const go = async () => {
    setBusy(true); setError(null)
    try {
      setRun(await reasonWithAgents({
        scenario, critical_assets: criticalAssets, incident_id: incidentId,
      }))
    } catch (e) {
      setError(e)
    } finally {
      setBusy(false)
    }
  }

  const agreed = run && run.workflow_techniques?.length
    ? run.techniques.filter((t) => run.workflow_techniques.includes(t))
    : []

  return (
    <Card>
      <CardHeader
        title="Reasoning agents"
        meta={run
          ? `${run.method === 'agents' ? run.provider : 'deterministic summary'} · advisory, not authoritative`
          : 'advisory · opt-in'}>
        {!run && (
          <button className="btn primary" disabled={busy} onClick={go}>
            <Sparkles size={14} aria-hidden="true" />
            {busy ? 'Investigating…' : 'Run the agents'}
          </button>
        )}
        {run && (
          <button className="btn ghost" disabled={busy} onClick={go}>
            {busy ? 'Investigating…' : 'Run again'}
          </button>
        )}
      </CardHeader>

      <div className="card-b pad stack-sm">
        {!run && !error && (
          <div className="disclosure">
            An Investigator agent queries the attack graph through seven read-only
            tools and writes a hypothesis. A Critic agent is then given the same
            tools and told to refute it. Neither can score, rank or contain
            anything: the investigation above is unchanged by whatever they
            conclude. Takes 15 to 40 seconds.
          </div>
        )}

        {error && (
          <div className="banner xc-conflict">
            <ShieldAlert size={15} aria-hidden="true" />
            <span>The agent lane did not return: {String(error.message || error)}.
              The investigation above is unaffected.</span>
          </div>
        )}

        {run && (
          <>
            <div className="rz-cols">
              <div className="rz-col">
                <div className="xc-label">Investigator</div>
                <p className="rz-hyp">{run.hypothesis}</p>
                <div className="rz-tech mono">
                  {run.techniques.length
                    ? run.techniques.map((t) => (
                      <span key={t}
                        className={agreed.includes(t) ? 'chip rz-agree' : 'chip'}>
                        {t}
                      </span>
                    ))
                    : 'no techniques named'}
                </div>
                <div className="xc-vsub">
                  confidence {run.confidence.toFixed(2)}
                  {agreed.length > 0 &&
                    ` · ${agreed.length} of ${run.techniques.length} match the workflow`}
                </div>
              </div>

              <div className={`rz-col ${run.refuted === true ? 'refuted' : ''}`}>
                <div className="xc-label">Critic</div>
                {/* Three states, not two. `null` means the review never
                    returned, and showing that as "stands" would claim a
                    corroboration nobody performed. */}
                <div className="xc-sev">
                  {run.refuted === true ? 'refuted'
                    : run.refuted === false ? 'stands'
                      : 'not reviewed'}
                </div>
                {run.refuted === null && (
                  <div className="xc-vsub">no verdict came back, so nothing here
                    has been checked by a second agent</div>
                )}
                {run.critic_reasons?.length > 0 && (
                  <ul className="rz-reasons">
                    {run.critic_reasons.map((r) => <li key={r}>{r}</li>)}
                  </ul>
                )}
                {run.alternative && (
                  <p className="rz-alt">
                    <span className="xc-label">Alternative explanation</span>
                    {run.alternative}
                  </p>
                )}
              </div>
            </div>

            {/* The citation check, which is the reason this lane is allowed to
                exist. Rejections are shown, never quietly discarded. */}
            <div className="rz-cites">
              <span className="xc-label">Evidence cited</span>
              {run.evidence_ids.length
                ? run.evidence_ids.map((e) => (
                  <span key={e} className="chip mono">{e}</span>
                ))
                : (
                  <span className="dim">
                    {run.method === 'agents'
                      ? 'none survived the check'
                      : 'nothing to cite: the summary states graph facts rather than claims'}
                  </span>
                )}
              {run.rejected_citations?.length > 0 && (
                <span className="rz-rejected">
                  {run.rejected_citations.length} citation
                  {run.rejected_citations.length === 1 ? '' : 's'} rejected:
                  {' '}
                  <span className="mono">{run.rejected_citations.join(' · ')}</span>
                  {' '}were in no tool output this agent received
                </span>
              )}
            </div>

            <div>
              <span className="xc-label">What the agents actually did</span>
              <ToolTrace calls={run.tool_calls} />
            </div>

            {run.missing?.length > 0 && (
              <div className="disclosure">
                <strong>What would settle this:</strong>
                <ul className="rz-reasons">
                  {run.missing.map((m) => <li key={m}>{m}</li>)}
                </ul>
              </div>
            )}

            {run.notes?.length > 0 && (
              <div className="fineprint">
                {run.notes.map((n) => <div key={n}>{n}</div>)}
              </div>
            )}
          </>
        )}
      </div>
    </Card>
  )
}
