import { useState } from 'react'
import { CircleAlert, GitCompareArrows, ScrollText } from 'lucide-react'
import { Card, CardHeader } from './Card.jsx'

// A second, differently-built analysis of the same log.
//
// The workflow governs. This lane exists to answer a question the workflow
// cannot ask itself: does an analysis built a different way reach the same
// conclusion? Agreement raises evidence confidence; disagreement lowers it and
// is shown rather than averaged away. Crucially, the two are only PARTIALLY
// independent — same log, same rule table — so what agreement is worth is capped.
const VERDICT_CLASS = {
  corroborates: 's-low',
  'partially corroborates': 's-medium',
  contradicts: 's-critical',
  inconclusive: 's-normal',
  'not available': 's-normal',
}

function Lane({ label, severity, basis, techniques }) {
  return (
    <div className="xc-lane">
      <div className="xc-label">{label}</div>
      <div className="xc-sev mono">{severity || '—'}</div>
      <div className="xc-basis">{basis}</div>
      <div className="xc-tech mono">
        {techniques.length ? techniques.join(' · ') : 'no techniques'}
      </div>
    </div>
  )
}

export default function CrossCheck({ crosscheck }) {
  const [open, setOpen] = useState(false)
  if (!crosscheck) return null

  if (!crosscheck.available) {
    return (
      <Card>
        <CardHeader title="Independent cross-check" meta="unavailable" />
        <div className="card-b pad">
          <div className="disclosure">
            The second analysis lane did not produce a result
            {crosscheck.reason ? `: ${crosscheck.reason}` : '.'} The investigation
            above is unaffected — the workflow is authoritative and the cross-check
            is advisory.
          </div>
        </div>
      </Card>
    )
  }

  const { severity, techniques, partial_independence: independence } = crosscheck
  const conflicting = crosscheck.verdict === 'contradicts'

  return (
    <Card>
      <CardHeader title="Independent cross-check"
        meta={`${crosscheck.verdict} · strength ${crosscheck.corroboration_strength}`} />
      <div className="card-b pad stack-sm">
        <div className={`banner ${conflicting ? 'xc-conflict' : ''}`}>
          {conflicting
            ? <CircleAlert size={15} aria-hidden="true" />
            : <GitCompareArrows size={15} aria-hidden="true" />}
          <span>{crosscheck.explanation}</span>
        </div>

        <div className="xc-grid">
          <Lane label="Workflow (authoritative)" severity={severity.workflow}
            basis={severity.basis_workflow} techniques={techniques.workflow} />
          <div className={`xc-verdict ${VERDICT_CLASS[crosscheck.verdict] || ''}`}>
            <div className="xc-vtext">{crosscheck.verdict}</div>
            <div className="xc-vsub">severity {severity.agreement}</div>
          </div>
          <Lane label="Agent lane (advisory)" severity={severity.agent_lane}
            basis={severity.basis_agent_lane} techniques={techniques.agent_lane} />
        </div>

        {(techniques.workflow_only.length > 0 || techniques.agent_lane_only.length > 0) && (
          <div className="xc-diff mono">
            {techniques.shared.length > 0 && (
              <span className="s-low">both: {techniques.shared.join(', ')}</span>
            )}
            {techniques.workflow_only.length > 0 && (
              <span className="dim"> · workflow only: {techniques.workflow_only.join(', ')}</span>
            )}
            {techniques.agent_lane_only.length > 0 && (
              <span className="dim"> · agent lane only: {techniques.agent_lane_only.join(', ')}</span>
            )}
          </div>
        )}

        {crosscheck.agent_lane_degraded?.length > 0 && (
          <div className="as-missing">
            <b>Agent lane degraded:</b> {crosscheck.agent_lane_degraded.join(', ')} —
            its agreement counts for less as a result.
          </div>
        )}

        <button className="linkish" onClick={() => setOpen(!open)} aria-expanded={open}>
          {open ? 'Hide' : 'Show'} the agent narrative and why this is only partial independence
        </button>
        {open && (
          <div className="xc-detail">
            <div className="xc-narr">
              <div className="cf-h">
                <ScrollText size={13} aria-hidden="true" /> Agent-lane narrative
                <span className="chip">
                  {crosscheck.narrative_method} · non-authoritative
                </span>
              </div>
              <p>{crosscheck.narrative || 'No narrative produced.'}</p>
            </div>
            <p className="fineprint">
              <b>Partial independence.</b> {independence.note} Shared:{' '}
              {independence.shared_components.join(', ')}.
            </p>
          </div>
        )}
      </div>
    </Card>
  )
}
