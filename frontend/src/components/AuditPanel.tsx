/**
 * The audit chain, live.
 *
 * Each record's hash covers the record AND the hash before it, so the "prove
 * it" button is real: we take the export, edit one record in the browser, send
 * it back, and the server locates the edit.
 *
 * Tamper-EVIDENT, not tamper-proof. We detect and locate an edit; we do not
 * claim to prevent it, and we do not call this a blockchain. That distinction
 * stays on screen.
 */
import * as React from 'react'
import { Download, FileCheck2, Link2, RotateCcw, ShieldX } from 'lucide-react'
import { Card, CardBody, CardHeader, CardMeta, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Table, TBody, TD, TDMono, TH, THead, TR } from '@/components/ui/table'
import { EmptyState, ErrorState } from '@/components/primitives'
import { FinePrint } from '@/components/Disclosure'
import { SkeletonRows } from '@/components/ui/skeleton'
import {
  exportAudit,
  exportAuditMarkdown,
  getAudit,
  resetAudit,
  verifyAudit,
  verifyAuditExport,
} from '@/lib/api'
import type { ApiError, AuditChain, AuditVerification } from '@/types/api'

function download(name: string, text: string, type: string) {
  const url = URL.createObjectURL(new Blob([text], { type }))
  const a = document.createElement('a')
  a.href = url
  a.download = name
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

interface TamperProof {
  clean: AuditVerification
  dirty: AuditVerification
  target: number
}

export default function AuditPanel({
  refreshKey,
  onReset,
}: {
  refreshKey: number
  onReset?: () => void
}) {
  const [data, setData] = React.useState<AuditChain | null>(null)
  const [error, setError] = React.useState<unknown>(null)
  const [loading, setLoading] = React.useState(true)
  const [live, setLive] = React.useState<AuditVerification | null>(null)
  const [proof, setProof] = React.useState<TamperProof | null>(null)
  const [proofError, setProofError] = React.useState<string | null>(null)
  const [busy, setBusy] = React.useState(false)

  const load = React.useCallback(() => {
    setLoading(true)
    getAudit(100)
      .then((d) => {
        setData(d)
        setError(null)
      })
      .catch((e: unknown) => setError(e))
      .finally(() => setLoading(false))
  }, [])

  React.useEffect(load, [load, refreshKey])

  async function proveTampering() {
    setBusy(true)
    setProof(null)
    setProofError(null)
    try {
      const exp = await exportAudit()
      const clean = await verifyAuditExport(exp)
      const target = Math.min(1, exp.records.length - 1)
      const edited = JSON.parse(JSON.stringify(exp)) as typeof exp
      edited.records[target].reason = 'approved without checking'
      const dirty = await verifyAuditExport(edited)
      setProof({ clean, dirty, target })
      load()
    } catch (e) {
      setProofError((e as ApiError).message)
    } finally {
      setBusy(false)
    }
  }

  async function doExport(kind: 'json' | 'md') {
    setBusy(true)
    try {
      if (kind === 'json') {
        download(
          'incident-audit.json',
          JSON.stringify(await exportAudit(), null, 2),
          'application/json',
        )
      } else {
        download('incident-audit.md', await exportAuditMarkdown(), 'text/markdown')
      }
      load()
    } catch (e) {
      setError(e)
    } finally {
      setBusy(false)
    }
  }

  async function doReset() {
    setBusy(true)
    try {
      await resetAudit()
      onReset?.()
      setProof(null)
      setLive(null)
      load()
    } catch (e) {
      setError(e)
    } finally {
      setBusy(false)
    }
  }

  const records = data?.records ?? []

  return (
    <Card>
      <CardHeader className="flex-wrap">
        <div className="flex min-w-0 items-baseline gap-3">
          <CardTitle>Evidence &amp; action audit</CardTitle>
          <CardMeta>
            {data ? `${data.count} records · head ${String(data.head).slice(0, 12)}…` : 'loading'}
          </CardMeta>
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          <Button
            size="sm"
            variant="outline"
            disabled={busy}
            onClick={() => {
              verifyAudit()
                .then(setLive)
                .catch((e: unknown) => setProofError((e as ApiError).message))
            }}
          >
            <FileCheck2 className="size-3" aria-hidden /> Verify
          </Button>
          <Button size="sm" variant="outline" disabled={busy} onClick={() => void proveTampering()}>
            <ShieldX className="size-3" aria-hidden /> Prove tamper-evidence
          </Button>
          <Button size="sm" variant="outline" disabled={busy} onClick={() => void doExport('json')}>
            <Download className="size-3" aria-hidden /> JSON
          </Button>
          <Button size="sm" variant="outline" disabled={busy} onClick={() => void doExport('md')}>
            <Download className="size-3" aria-hidden /> Report
          </Button>
          <Button size="sm" variant="outline" disabled={busy} onClick={() => void doReset()}>
            <RotateCcw className="size-3" aria-hidden /> Reset
          </Button>
        </div>
      </CardHeader>

      <CardBody className="space-y-3">
        {error ? <ErrorState error={error} retry={load} /> : null}

        {data ? (
          <div
            className={`flex items-start gap-2 rounded-md border px-3 py-2 text-xs ${
              data.verified
                ? 'border-ok/40 bg-ok/5 text-dim'
                : 'border-sev-critical/40 bg-sev-critical/5 text-dim'
            }`}
          >
            <Link2 className="mt-0.5 size-3.5 shrink-0" aria-hidden />
            <span>
              {data.verified
                ? 'Chain verifies: every record’s hash matches its contents and the record before it.'
                : `Chain BROKEN: ${data.problem ?? 'no detail given'}`}
            </span>
          </div>
        ) : null}

        {live ? (
          <div className="rounded-md border border-border bg-surface-2 px-3 py-2 font-mono text-xs text-dim">
            Live verification: {live.verified ? 'verified' : (live.problem ?? 'failed')} ·{' '}
            {live.records} records · {live.hash_algorithm} · {live.claim}
          </div>
        ) : null}

        {proof ? (
          <div className="space-y-1 rounded-md border border-border bg-surface-2 px-3 py-2 text-xs text-dim">
            <div>
              Exported chain as-is →{' '}
              <span className="font-medium text-ok">
                verified: {String(proof.clean.verified)}
              </span>
            </div>
            <div>
              Edited record #{proof.target}&apos;s reason in the browser and re-verified →{' '}
              <span className="font-medium text-sev-critical">
                verified: {String(proof.dirty.verified)}
              </span>
            </div>
            <div className="font-mono text-faint">{proof.dirty.problem}</div>
            <FinePrint>
              Tamper-<span className="font-medium text-text">evident</span>, not tamper-proof: we
              detect and locate the edit. We do not claim to prevent it, and we do not call this
              a blockchain.
            </FinePrint>
          </div>
        ) : null}

        {proofError ? (
          <div className="rounded-md border border-sev-critical/40 bg-sev-critical/5 px-3 py-2 font-mono text-xs text-dim">
            {proofError}
          </div>
        ) : null}

        {loading && !data ? <SkeletonRows rows={3} /> : null}
      </CardBody>

      {records.length ? (
        <Table>
          <THead>
            <TR>
              <TH className="text-right">#</TH>
              <TH>Time</TH>
              <TH>Event</TH>
              <TH>Actor (role)</TH>
              <TH>Decision</TH>
              <TH>Reason</TH>
              <TH>Hash</TH>
            </TR>
          </THead>
          <TBody>
            {records.map((r) => (
              <TR key={r.hash}>
                <TDMono className="text-right">{r.seq}</TDMono>
                <TDMono className="whitespace-nowrap">{String(r.at ?? r.timestamp ?? '')}</TDMono>
                <TD className="text-xs">{String(r.kind ?? '')}</TD>
                <TDMono>
                  {r.actor}
                  <span className="text-faint"> ({r.role})</span>
                </TDMono>
                <TD
                  className={`text-xs ${
                    r.decision === 'approved'
                      ? 'text-ok'
                      : r.decision
                        ? 'text-sev-high'
                        : 'text-faint'
                  }`}
                >
                  {r.decision ?? 'none recorded'}
                </TD>
                <TD className="max-w-xs text-xs text-dim">
                  {String(r.reason ?? '') || <span className="text-faint">none given</span>}
                </TD>
                <TDMono className="text-faint" title={r.hash}>
                  {r.hash.slice(0, 10)}…
                </TDMono>
              </TR>
            ))}
          </TBody>
        </Table>
      ) : !loading && !error ? (
        <EmptyState
          title="No audit records yet"
          detail="Records appear as analyses run and decisions are taken. Nothing is pre-seeded."
        />
      ) : null}

      <CardBody className="border-t border-border">
        <FinePrint>
          Session-scoped and held in memory: free hosts have an ephemeral filesystem, so we do
          not imply this survives a restart. Export it to keep it.
        </FinePrint>
      </CardBody>
    </Card>
  )
}
