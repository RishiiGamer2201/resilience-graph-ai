import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Search, Crosshair, Loader2 } from 'lucide-react'
import { getAttackers, getIncident, analyze } from '../api.js'
import { useFetch } from '../lib/useFetch.js'
import { useScreenData, useAnalysis } from '../lib/analysis.jsx'
import { Card, CardHeader, Loading, ErrorBox } from '../components/Card.jsx'
import { fmtTime } from '../lib/format.js'

// The campaign log every per-account incident is carved out of.
const CAMPAIGN_SCENARIO = 'lanl_campaign_all'

export default function Attackers() {
  // The roster is always the CAMPAIGN's accounts. Reading it from the live bundle
  // would collapse the list to one row the moment you open a single account.
  const { data: cached, error, loading } = useFetch(() => getAttackers().then((d) => d.attackers))
  const { bundle, setBundle } = useAnalysis()
  const data = (bundle?.attackers?.length > 1 ? bundle.attackers : null) || cached
  const { data: incident } = useScreenData('incident', getIncident)
  const navigate = useNavigate()

  const [q, setQ] = useState('')
  const [busy, setBusy] = useState(null)
  const [err, setErr] = useState(null)

  const rows = useMemo(() => {
    const list = data || []
    const needle = q.trim().toLowerCase()
    if (!needle) return list
    return list.filter((a) =>
      a.user.toLowerCase().includes(needle) ||
      a.pivots.some((p) => p.toLowerCase().includes(needle)) ||
      a.techniques.some((t) => t.toLowerCase().includes(needle)))
  }, [data, q])

  async function openAccount(user) {
    setBusy(user); setErr(null)
    try {
      const bundle = await analyze({
        scenario: CAMPAIGN_SCENARIO, account: user,   // crown jewels: backend default (derived)
      })
      setBundle(bundle)
      navigate('/incident')
    } catch (e) {
      setErr(e.message || String(e))
    } finally {
      setBusy(null)
    }
  }

  if (loading) return <Loading />
  if (error) return <ErrorBox error={error} />

  const list = data || []
  const totals = list.reduce((acc, a) => ({
    alerts: acc.alerts + a.alerts,
    hosts: acc.hosts + a.hosts_reached,
  }), { alerts: 0, hosts: 0 })
  const pivots = [...new Set(list.flatMap((a) => a.pivots))]
  const withCritical = list.filter((a) => a.critical_reached.length > 0)

  return (
    <>
      <div className="page-head">
        <span className="tag-pill" style={{ background: 'var(--accent-soft)', color: 'var(--accent)' }}>
          CAMPAIGN
        </span>
        <h2>{list.length} compromised accounts</h2>
        <p>Every account the red team used, scored from the same log. Open one to analyze
          it as its own incident.</p>
      </div>

      {err && <div className="errbox" style={{ marginBottom: 14 }}>{err}</div>}

      <div className="tiles">
        <div className="tile">
          <div className="k">Compromised accounts</div>
          <div className="v">{list.length}</div>
          <div className="sub">all in one campaign</div>
        </div>
        <div className="tile crit">
          <div className="k">Attacker pivots</div>
          <div className="v">{pivots.length}</div>
          <div className="sub mono">{pivots.join(' · ')}</div>
        </div>
        <div className="tile">
          <div className="k">Correlated alerts</div>
          <div className="v">{totals.alerts.toLocaleString()}</div>
          <div className="sub">across every account</div>
        </div>
        <div className="tile">
          <div className="k">Reached crown jewel</div>
          <div className="v">{withCritical.length}</div>
          <div className="sub">{withCritical.map((a) => a.user).join(', ') || 'none'}</div>
        </div>
      </div>

      <Card>
        <CardHeader title="Accounts used in this campaign"
          meta={`${rows.length}/${list.length} shown`}>
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
            <Search size={13} aria-hidden="true" style={{ color: 'var(--text-faint)' }} />
            <input value={q} onChange={(e) => setQ(e.target.value)}
              placeholder="filter account / pivot / technique"
              aria-label="Filter accounts"
              style={{ fontSize: 12, padding: '4px 8px', minWidth: 220 }} />
          </span>
        </CardHeader>
        <div className="card-b" style={{ maxHeight: 620, overflowY: 'auto' }}>
          <table className="mtable">
            <thead>
              <tr>
                <th>Account</th><th>Severity</th>
                <th style={{ textAlign: 'right' }}>Alerts</th>
                <th style={{ textAlign: 'right' }}>Hosts</th>
                <th style={{ textAlign: 'right' }}>Max score</th>
                <th>Pivot(s)</th><th>Techniques</th><th>First seen</th><th />
              </tr>
            </thead>
            <tbody>
              {rows.map((a) => (
                <tr key={a.user} className={incident?.account === a.user ? 'sel' : undefined}>
                  <td className="mono" style={{ fontWeight: 600 }}>{a.user}</td>
                  <td><span className={`s-${a.severity}`} style={{ fontWeight: 600 }}>{a.severity}</span></td>
                  <td className="num">{a.alerts}</td>
                  <td className="num">{a.hosts_reached}</td>
                  <td className={`num s-${a.severity}`}>{a.max_score}</td>
                  <td className="mono" style={{ fontSize: 11.5 }}>{a.pivots.join(' · ')}</td>
                  <td className="mono" style={{ fontSize: 11.5 }}>{a.techniques.join(' ')}</td>
                  <td className="mono" style={{ fontSize: 11.5 }}>{fmtTime(a.first_seen)}</td>
                  <td style={{ textAlign: 'right' }}>
                    {a.critical_reached.length > 0 && (
                      <span className="tag-pill" title={`reached ${a.critical_reached.join(', ')}`}
                        style={{ background: 'color-mix(in srgb, var(--sev-critical) 16%, transparent)',
                                 color: 'var(--sev-critical)', marginRight: 6 }}>
                        crown jewel
                      </span>
                    )}
                    <button className="btn" disabled={busy === a.user}
                      onClick={() => openAccount(a.user)}
                      style={{ padding: '2px 8px', fontSize: 11.5, display: 'inline-flex', gap: 4, alignItems: 'center' }}>
                      {busy === a.user
                        ? <><Loader2 size={11} className="spin" /> Analyzing…</>
                        : <><Crosshair size={11} /> Open incident</>}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="note">
          Each account is analyzed by the same live pipeline, scoped to its own events —
          behavioural features are computed against the whole log first, so an account's
          baseline reflects everything that happened, not just its own slice.
        </div>
      </Card>
    </>
  )
}
