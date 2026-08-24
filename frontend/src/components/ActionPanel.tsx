/**
 * Proposed containment - read as proposals awaiting a human, because that is
 * what they are.
 *
 * Every action is simulated; nothing contacts a real system. The gate comes
 * from policy computed on the action's own blast radius and crown-jewel
 * involvement, and the decision is enforced SERVER-SIDE and written to the
 * tamper-evident audit chain.
 *
 * The Approve button is never hidden from a role that lacks the permission.
 * Hiding it would teach an operator that the client is the control. It is
 * pressed, the API refuses, and the server's own refusal is what appears on
 * screen. See DESIGN.md section 5.
 */
import * as React from 'react'
import { Ban, Lock, Mail, ShieldCheck, ShieldQuestion } from 'lucide-react'
import { Card, CardBody, CardHeader, CardMeta, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Disclosure, Disclosed, FinePrint } from '@/components/Disclosure'
import { approveAction } from '@/lib/api'
import type {
  ActionOutput,
  ActionProposal,
  ApiError,
  ApprovalResult,
  Rfi,
} from '@/types/api'

interface Decided {
  result: ApprovalResult
}
interface Refused {
  message: string
  status?: number
}

function Proposal({
  proposal,
  onDecided,
}: {
  proposal: ActionProposal
  onDecided?: () => void
}) {
  const [reason, setReason] = React.useState('')
  const [decided, setDecided] = React.useState<Decided | null>(null)
  const [refused, setRefused] = React.useState<Refused | null>(null)
  const [busy, setBusy] = React.useState(false)
  const gated = proposal.policy.requires_approval

  async function decide(decision: 'approve' | 'reject') {
    setBusy(true)
    setRefused(null)
    try {
      const r = await approveAction({
        proposal_id: proposal.proposal_id,
        decision,
        reason,
      })
      setDecided({ result: r })
      onDecided?.()
    } catch (e) {
      const err = e as ApiError
      setRefused({ message: err.message, status: err.status })
    } finally {
      setBusy(false)
    }
  }

  return (
    <div
      className={`rounded-md border p-3 ${
        gated ? 'border-sev-medium/40 bg-sev-medium/5' : 'border-border bg-surface-2'
      }`}
    >
      <div className="flex flex-wrap items-center gap-2">
        <span
          className="font-mono text-xs text-faint"
          title={`Server proposal ${proposal.proposal_id}; digest ${proposal.proposal_digest}`}
        >
          {proposal.id}
        </span>
        <span className="text-sm font-medium text-text">{proposal.action}</span>
        <span className="flex-1" />
        <Badge variant={gated ? 'warn' : 'default'}>
          {gated ? <Lock className="size-3" aria-hidden /> : null}
          {proposal.policy.gate}
        </Badge>
      </div>
      <div className="mt-1 font-mono text-xs text-faint">
        {proposal.tactic} · kind {proposal.kind}
        {proposal.touches_crown_jewel ? ' · touches a crown jewel' : ''}
        {proposal.blast_radius_affected
          ? ` · affects ${proposal.blast_radius_affected} hosts`
          : ''}
        {' · simulated'}
      </div>
      {proposal.policy.reasons.length ? (
        <ul className="mt-2 list-disc pl-4 text-xs text-dim">
          {proposal.policy.reasons.map((r) => (
            <li key={r}>{r}</li>
          ))}
        </ul>
      ) : null}

      {decided ? (
        <div className="mt-3 flex flex-wrap items-center gap-1.5 rounded-md border border-ok/40 bg-ok/5 px-2.5 py-1.5 text-xs text-dim">
          <ShieldCheck className="size-3.5 text-ok" aria-hidden />
          <span className="text-text">{decided.result.decision}</span> by{' '}
          {decided.result.record.actor ?? 'actor not recorded'} (
          {decided.result.record.role ?? 'role not recorded'}) ·
          audit record #{decided.result.record.seq}
          <span className="font-mono text-faint">
            {decided.result.record.hash.slice(0, 16)}…
          </span>
          <span aria-hidden>·</span>
          <span>executed: no</span>
        </div>
      ) : (
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <label className="sr-only" htmlFor={`reason-${proposal.proposal_id}`}>
            Reason for the decision
          </label>
          <input
            id={`reason-${proposal.proposal_id}`}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder={gated ? 'Written reason (required to approve)' : 'Reason (optional)'}
            className="h-8 min-w-0 flex-1 rounded-md border border-border bg-surface px-2.5 text-sm text-text placeholder:text-faint"
          />
          {/* Deliberately not disabled by role: the server decides, and its
              refusal is the thing worth showing. */}
          <Button size="sm" disabled={busy} onClick={() => void decide('approve')}>
            Approve (simulate)
          </Button>
          <Button
            size="sm"
            variant="outline"
            disabled={busy}
            onClick={() => void decide('reject')}
          >
            <Ban className="size-3" aria-hidden /> Reject
          </Button>
        </div>
      )}

      {refused ? (
        <div className="mt-2 rounded-md border border-sev-critical/40 bg-sev-critical/5 px-2.5 py-1.5 text-xs text-dim">
          <span className="font-medium text-sev-critical">
            {refused.status === 403 ? 'Refused by the server' : 'Rejected'}
          </span>{' '}
          - <span className="font-mono">{refused.message}</span>
        </div>
      ) : null}
    </div>
  )
}

function RfiBlock({ rfi }: { rfi: Rfi | null | undefined }) {
  if (!rfi) return null
  return (
    <Disclosure
      label={`Request for information - ${rfi.subject}`}
      labelOpen={`Hide the request for information`}
    >
      <div className="space-y-2">
        <p className="flex items-start gap-1.5 text-xs text-dim">
          <Mail className="mt-0.5 size-3 shrink-0" aria-hidden />
          {rfi.context}
        </p>
        <ul className="space-y-1 text-xs">
          {rfi.questions.map((q) => (
            <li key={q.field}>
              <span className="text-text">{q.ask}</span>
              <span className="text-faint"> - {q.why}</span>
            </li>
          ))}
        </ul>
        <FinePrint>
          {rfi.generated_by}. {rfi.note}
        </FinePrint>
      </div>
    </Disclosure>
  )
}

export default function ActionPanel({
  action,
  onDecided,
}: {
  action: ActionOutput | null | undefined
  onDecided?: () => void
}) {
  if (!action) return null
  // The action node can degrade. Never assume its lists exist.
  const proposals = action.proposals ?? []
  const gated = proposals.filter((p) => p.policy?.requires_approval).length

  return (
    <Card>
      <CardHeader>
        <CardTitle>Recommended response</CardTitle>
        <CardMeta>
          {proposals.length} proposed · {gated} gated · {action.executed ?? 0} executed
        </CardMeta>
      </CardHeader>
      <CardBody className="space-y-3">
        <div className="flex items-start gap-2 rounded-md border border-border bg-surface-2 px-3 py-2 text-xs text-dim">
          <ShieldQuestion className="mt-0.5 size-3.5 shrink-0" aria-hidden />
          <span>
            Every action below is <span className="font-medium text-text">simulated</span>.
            Nothing contacts a real system. Actions touching a crown jewel or a wide blast
            radius require a named human and a written reason, enforced by the API - not by
            hiding the button.
          </span>
        </div>

        {proposals.length === 0 ? (
          <Disclosed>
            The action stage could not complete, so no response was proposed. The detection and
            impact above still stand.
          </Disclosed>
        ) : null}

        {proposals.map((p) => (
          <Proposal
            key={p.proposal_id}
            proposal={p}
            onDecided={onDecided}
          />
        ))}

        {action.mitre_mitigations?.length ? (
          <div className="text-xs text-dim">
            <span className="font-medium text-text">
              MITRE-recommended mitigations for the observed techniques:
            </span>{' '}
            <span className="font-mono">{action.mitre_mitigations.join(' · ')}</span>
          </div>
        ) : null}

        <RfiBlock rfi={action.rfi} />
        <FinePrint>
          {action.gating_policy} {action.note}
        </FinePrint>
      </CardBody>
    </Card>
  )
}
