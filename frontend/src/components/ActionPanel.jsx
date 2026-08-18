import { useState } from 'react'
import { Ban, CheckCircle2, Lock, Mail, ShieldQuestion } from 'lucide-react'
import { Card, CardHeader } from './Card.jsx'
import { approveAction } from '../api.js'
import { useSession } from '../lib/session.jsx'

// Proposed containment. Every action is simulated; the gate is decided by policy
// from the action's own blast radius and crown-jewel involvement, and the
// decision is enforced server-side and written to the audit chain.
function Proposal({ proposal, incidentId, techniqueIds, evidence, affected, onDecided }) {
  const { role, actor } = useSession()
  const [reason, setReason] = useState('')
  const [state, setState] = useState(null)     // {decision, record} | {error}
  const [busy, setBusy] = useState(false)
  const gated = proposal.policy.requires_approval

  async function decide(decision) {
    setBusy(true); setState(null)
    try {
      const r = await approveAction({
        incident_id: incidentId, action: proposal, decision, reason,
        technique_ids: techniqueIds, evidence, affected_assets: affected,
      })
      setState({ decision: r.decision, record: r.record })
      onDecided?.(r)
    } catch (e) {
      setState({ error: e.message, status: e.status })
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className={`proposal ${gated ? 'gated' : 'auto'}`}>
      <div className="p-head">
        <span className="mono id">{proposal.id}</span>
        <b>{proposal.action}</b>
        <span className="spacer" />
        <span className={`mode ${gated ? 'm-approve' : 'm-auto'}`}>
          {gated ? <Lock size={11} aria-hidden="true" /> : null} {proposal.policy.gate}
        </span>
      </div>
      <div className="p-meta mono">
        {proposal.tactic} · kind {proposal.kind}
        {proposal.touches_crown_jewel ? ' · touches a crown jewel' : ''}
        {proposal.blast_radius_affected ? ` · affects ${proposal.blast_radius_affected} hosts` : ''}
        {' · simulated'}
      </div>
      <ul className="p-why">
        {proposal.policy.reasons.map((r) => <li key={r}>{r}</li>)}
      </ul>

      {state?.decision ? (
        <div className={`decided ${state.decision}`}>
          <CheckCircle2 size={13} aria-hidden="true" />
          {state.decision} by {actor} ({role}) · audit record #{state.record.seq}{' '}
          <span className="mono dim">{state.record.hash.slice(0, 16)}…</span>
          {' · executed: no'}
        </div>
      ) : (
        <div className="p-decide">
          <label className="sr-only" htmlFor={`reason-${proposal.id}`}>Reason for the decision</label>
          <input id={`reason-${proposal.id}`} value={reason} onChange={(e) => setReason(e.target.value)}
            placeholder={gated ? 'Written reason (required to approve)' : 'Reason (optional)'} />
          <button className="btn primary" disabled={busy} onClick={() => decide('approve')}>
            Approve (simulate)
          </button>
          <button className="btn" disabled={busy} onClick={() => decide('reject')}>
            <Ban size={12} aria-hidden="true" /> Reject
          </button>
        </div>
      )}
      {state?.error && (
        <div className="errbox small">
          <b>{state.status === 403 ? 'Refused by the server' : 'Rejected'}</b> — {state.error}
        </div>
      )}
    </div>
  )
}

function Rfi({ rfi }) {
  if (!rfi) return null
  return (
    <details className="rfi">
      <summary><Mail size={13} aria-hidden="true" /> Request for information — {rfi.subject}</summary>
      <p className="lede">{rfi.context}</p>
      <ul>
        {rfi.questions.map((q) => (
          <li key={q.field}>
            <b>{q.ask}</b>
            <span className="dim"> — {q.why}</span>
          </li>
        ))}
      </ul>
      <p className="fineprint">
        {rfi.generated_by}. {rfi.note}
      </p>
    </details>
  )
}

export default function ActionPanel({ action, incidentId, techniqueIds, evidence, affected, onDecided }) {
  if (!action) return null
  // The action node can degrade (see workflow.py). Never assume its lists exist.
  const proposals = action.proposals || []
  const gated = proposals.filter((p) => p.policy?.requires_approval).length
  return (
    <Card>
      <CardHeader title="Recommended response"
        meta={`${proposals.length} proposed · ${gated} gated · ${action.executed ?? 0} executed`} />
      <div className="card-b pad stack-sm">
        <div className="banner">
          <ShieldQuestion size={15} aria-hidden="true" />
          <span>
            Every action below is <b>simulated</b>. Nothing contacts a real system. Actions
            touching a crown jewel or a wide blast radius require a named human and a
            written reason, enforced by the API — not by hiding this button.
          </span>
        </div>
        {proposals.length === 0 && (
          <div className="disclosure">
            The action stage could not complete, so no response was proposed. The
            detection and impact above still stand.
          </div>
        )}
        {proposals.map((p) => (
          <Proposal key={p.id} proposal={p} incidentId={incidentId} techniqueIds={techniqueIds}
            evidence={evidence} affected={affected} onDecided={onDecided} />
        ))}
        {action.mitre_mitigations?.length > 0 && (
          <div className="mitigations">
            <b>MITRE-recommended mitigations for the observed techniques:</b>{' '}
            {action.mitre_mitigations.join(' · ')}
          </div>
        )}
        <Rfi rfi={action.rfi} />
        <p className="fineprint">{action.gating_policy}. {action.note}</p>
      </div>
    </Card>
  )
}
