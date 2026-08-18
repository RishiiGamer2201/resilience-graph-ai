import { useCallback, useEffect, useState } from 'react'
import { Download, FileCheck2, Link2, RotateCcw, ShieldX } from 'lucide-react'
import { Card, CardHeader } from './Card.jsx'
import {
  exportAudit, exportAuditMarkdown, getAudit, resetAudit, verifyAudit, verifyAuditExport,
} from '../api.js'

function download(name, text, type) {
  const url = URL.createObjectURL(new Blob([text], { type }))
  const a = document.createElement('a')
  a.href = url; a.download = name
  document.body.appendChild(a); a.click(); a.remove()
  URL.revokeObjectURL(url)
}

// The audit chain, live. Each record's hash covers the record AND the hash before
// it, so the "prove it" button is real: we take the export, edit one record in the
// browser, send it back, and the server locates the edit.
export default function AuditPanel({ refreshKey, onReset }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const [tamper, setTamper] = useState(null)
  const [busy, setBusy] = useState(false)

  const load = useCallback(() => {
    getAudit(100).then(setData).catch((e) => setError(e.message))
  }, [])
  useEffect(load, [load, refreshKey])

  async function proveTampering() {
    setBusy(true); setTamper(null)
    try {
      const exp = await exportAudit()
      const clean = await verifyAuditExport(exp)
      const target = Math.min(1, exp.records.length - 1)
      const edited = JSON.parse(JSON.stringify(exp))
      edited.records[target].reason = 'approved without checking'
      const dirty = await verifyAuditExport(edited)
      setTamper({ clean, dirty, target })
      load()
    } catch (e) {
      setTamper({ error: e.message })
    } finally {
      setBusy(false)
    }
  }

  async function doExport(kind) {
    setBusy(true)
    try {
      if (kind === 'json') {
        download('incident-audit.json', JSON.stringify(await exportAudit(), null, 2),
          'application/json')
      } else {
        download('incident-audit.md', await exportAuditMarkdown(), 'text/markdown')
      }
      load()
    } catch (e) {
      setError(e.message)
    } finally {
      setBusy(false)
    }
  }

  async function doReset() {
    setBusy(true)
    try {
      await resetAudit()
      onReset?.()
      load()
      setTamper(null)
    } catch (e) {
      setError(e.message)
    } finally {
      setBusy(false)
    }
  }

  const records = data?.records || []
  return (
    <Card>
      <CardHeader title="Evidence & action audit"
        meta={data ? `${data.count} records · head ${String(data.head).slice(0, 12)}…` : '—'}>
        <button className="btn" onClick={() => verifyAudit().then((v) => setTamper({ live: v }))}>
          <FileCheck2 size={12} aria-hidden="true" /> Verify
        </button>
        <button className="btn" disabled={busy} onClick={proveTampering}>
          <ShieldX size={12} aria-hidden="true" /> Prove tamper-evidence
        </button>
        <button className="btn" disabled={busy} onClick={() => doExport('json')}>
          <Download size={12} aria-hidden="true" /> JSON
        </button>
        <button className="btn" disabled={busy} onClick={() => doExport('md')}>
          <Download size={12} aria-hidden="true" /> Report
        </button>
        <button className="btn" disabled={busy} onClick={doReset}>
          <RotateCcw size={12} aria-hidden="true" /> Reset
        </button>
      </CardHeader>
      <div className="card-b pad stack-sm">
        {error && <div className="errbox small">{error}</div>}
        {data && (
          <div className={`chainstate ${data.verified ? 'ok' : 'bad'}`}>
            <Link2 size={13} aria-hidden="true" />
            {data.verified
              ? 'Chain verifies: every record’s hash matches its contents and the record before it.'
              : `Chain BROKEN: ${data.problem}`}
          </div>
        )}
        {tamper?.live && (
          <div className={`chainstate ${tamper.live.verified ? 'ok' : 'bad'}`}>
            Live verification: {tamper.live.verified ? 'verified' : tamper.live.problem}{' '}
            · {tamper.live.records} records · {tamper.live.hash_algorithm} · {tamper.live.claim}
          </div>
        )}
        {tamper?.dirty && (
          <div className="tamper-proof">
            <div>Exported chain as-is → <b className="s-low">verified: {String(tamper.clean.verified)}</b></div>
            <div>
              Edited record #{tamper.target}&apos;s reason in the browser and re-verified →{' '}
              <b className="s-critical">verified: {String(tamper.dirty.verified)}</b>
            </div>
            <div className="mono dim">{tamper.dirty.problem}</div>
            <p className="fineprint">
              Tamper-<b>evident</b>, not tamper-proof: we detect and locate the edit. We do
              not claim to prevent it, and we do not call this a blockchain.
            </p>
          </div>
        )}
        {tamper?.error && <div className="errbox small">{tamper.error}</div>}

        <table className="tbl audit">
          <caption className="sr-only">Audit records</caption>
          <thead>
            <tr>
              <th scope="col">#</th><th scope="col">Time</th><th scope="col">Event</th>
              <th scope="col">Actor (role)</th><th scope="col">Decision</th>
              <th scope="col">Reason</th><th scope="col">Hash</th>
            </tr>
          </thead>
          <tbody>
            {records.map((r) => (
              <tr key={r.hash}>
                <td className="mono">{r.seq}</td>
                <td className="mono">{r.at}</td>
                <td>{r.kind}</td>
                <td className="mono">{r.actor} <span className="dim">({r.role})</span></td>
                <td className={r.decision === 'approved' ? 's-low' : r.decision ? 's-high' : ''}>
                  {r.decision || '—'}
                </td>
                <td>{r.reason || '—'}</td>
                <td className="mono dim" title={r.hash}>{r.hash.slice(0, 10)}…</td>
              </tr>
            ))}
            {!records.length && <tr><td colSpan={7} className="dim">No records yet.</td></tr>}
          </tbody>
        </table>
        <p className="fineprint">
          Session-scoped and held in memory: free hosts have an ephemeral filesystem, so we
          do not imply this survives a restart. Export it to keep it.
        </p>
      </div>
    </Card>
  )
}
