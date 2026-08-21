import { Fragment, useState } from 'react'
import { ArrowRight, Scissors, ShieldAlert } from 'lucide-react'
import { Card, CardHeader } from './Card.jsx'
import { twinSimulate } from '../api.js'

function Diff({ label, before, after, betterWhenLower = true }) {
  const changed = before !== after
  const better = betterWhenLower ? after < before : after > before
  return (
    <div className="diff">
      <span className="k">{label}</span>
      <span className="mono b">{before}</span>
      <ArrowRight size={12} aria-hidden="true" />
      <span className={`mono a ${changed ? (better ? 's-low' : 's-critical') : ''}`}>{after}</span>
    </div>
  )
}

// Digital twin: pick a host, and the backend clones the incident graph, removes
// it, and recomputes reachability. Security benefit AND operational cost, because
// taking a hospital server off the network is a decision, not a free win.
export function TwinPanel({ graph, counterfactual, candidates }) {
  const [sim, setSim] = useState(counterfactual || null)
  const [busy, setBusy] = useState(null)
  const [error, setError] = useState(null)

  async function run(host) {
    setBusy(host); setError(null)
    try {
      setSim(await twinSimulate({ graph, isolate_host: host }))
    } catch (e) {
      setError(e.message)
    } finally {
      setBusy(null)
    }
  }

  const cost = sim?.operational_cost
  return (
    <Card>
      <CardHeader title="Counterfactual containment twin" meta="deterministic · simulated" />
      <div className="card-b pad stack-sm">
        <p className="lede">
          Isolate a candidate host on a <b>clone</b> of this incident&apos;s attack graph and
          recompute what the attacker can still reach. The live graph is never touched.
        </p>
        <p className="fineprint">
          Named precisely: this is a <b>counterfactual containment twin</b> over the
          attack graph, not a full cyber-resilience digital twin. A complete twin
          would also carry synchronised asset, identity, dependency and control
          state, expected behaviour by operating mode, and — for OT — validated
          process models with uncertainty. Those are on the roadmap, not on screen.
        </p>
        {error && <div className="errbox">{error}</div>}

        <table className="tbl">
          <caption className="sr-only">Containment candidates ranked by benefit then cost</caption>
          <thead>
            <tr>
              <th scope="col">Isolate</th>
              <th scope="col">Crown jewels protected</th>
              <th scope="col">Hosts removed from reach</th>
              <th scope="col">Sessions severed</th>
              <th scope="col">Accounts disrupted</th>
              <th scope="col"><span className="sr-only">Simulate</span></th>
            </tr>
          </thead>
          <tbody>
            {(candidates || []).map((c) => (
              <tr key={c.host} className={sim?.candidate?.isolate_host === c.host ? 'sel' : undefined}>
                <th scope="row" className="mono">{c.host}</th>
                <td>{c.crown_jewels_protected.length
                  ? <span className="s-low">{c.crown_jewels_protected.join(', ')}</span>
                  : <span className="dim">none</span>}</td>
                <td className="mono">{c.blast_radius_reduction} ({c.blast_radius_reduction_pct}%)</td>
                <td className="mono">{c.sessions_severed}</td>
                <td className="mono">{c.accounts_disrupted}</td>
                <td>
                  <button className="btn" disabled={busy === c.host} onClick={() => run(c.host)}>
                    <Scissors size={12} aria-hidden="true" /> {busy === c.host ? '…' : 'Simulate'}
                  </button>
                </td>
              </tr>
            ))}
            {!candidates?.length && (
              <tr><td colSpan={6} className="dim">No containment candidate in this graph.</td></tr>
            )}
          </tbody>
        </table>

        {sim && (
          <div className="twin-result">
            <div className="twin-head">
              <ShieldAlert size={15} aria-hidden="true" />
              <b className="mono">{sim.candidate.isolate_host || (sim.candidate.cut_edge || []).join(' → ')}</b>
              <span className="chip">simulated</span>
            </div>
            <p className="verdict">{sim.verdict}</p>
            <div className="diffs">
              <Diff label="Blast radius" before={sim.before.blast_radius} after={sim.after.blast_radius} />
              <Diff label="Crown jewels reachable"
                before={sim.before.crown_jewels_reachable.length}
                after={sim.after.crown_jewels_reachable.length} />
              <Diff label="Graph nodes" before={sim.before.n_nodes} after={sim.after.n_nodes} />
              <Diff label="Movements" before={sim.before.n_edges} after={sim.after.n_edges} />
            </div>
            <div className="cost">
              <b>Operational cost:</b> {cost.hosts_taken_offline} host offline ·{' '}
              {cost.sessions_severed} sessions severed ·{' '}
              {cost.accounts_disrupted.length} account(s) disrupted
              {cost.accounts_disrupted.length
                ? <span className="mono dim"> ({cost.accounts_disrupted.slice(0, 4).join(', ')})</span>
                : null}
            </div>
            <p className="fineprint">{sim.method}. {sim.note}</p>
          </div>
        )}
      </div>
    </Card>
  )
}

const BAND_CLASS = { 'act now': 's-critical', urgent: 's-high', scheduled: 's-medium', monitor: 's-normal' }

// Vulnerability queue. The interesting column is not the score, it is WHY:
// every factor is shown with the fact behind it, and unknown factors are listed
// rather than silently scored zero.
export function VulnPanel({ vulns }) {
  const [open, setOpen] = useState(null)
  const findings = vulns?.findings || []

  return (
    <Card>
      <CardHeader title="Vulnerability priority for this incident"
        meta={vulns?.config ? `config v${vulns.config.version}` : 'no inventory'} />
      <div className="card-b pad stack-sm">
        {!findings.length ? (
          <div className="disclosure">
            {vulns?.inventory_note || vulns?.disclosure
              || 'No asset inventory for this log, so no findings. We never guess what software a host runs.'}
          </div>
        ) : (
          <>
            <p className="lede">
              {vulns.total_findings} finding(s) across {vulns.assets_considered} inventoried
              assets, matched against {vulns.kev_catalog_size} CISA Known-Exploited entries.
              Ranked by asset criticality, known exploitation, reachability in <i>this</i>{' '}
              attack graph, technique overlap, severity and evidence freshness.
            </p>
            <table className="tbl">
              <caption className="sr-only">Prioritised vulnerabilities</caption>
              <thead>
                <tr>
                  <th scope="col">Priority</th><th scope="col">CVE</th><th scope="col">Asset</th>
                  <th scope="col">Owner</th><th scope="col">Confidence</th><th scope="col">Why</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((f) => (
                  <Fragment key={f.cve + f.host}>
                    <tr>
                      <td>
                        <span className={`mono ${BAND_CLASS[f.band] || ''}`}>{f.priority_score}</span>
                        <span className="band">{f.band}</span>
                      </td>
                      <th scope="row" className="mono">
                        <a href={f.citation.url} target="_blank" rel="noopener noreferrer">{f.cve}</a>
                      </th>
                      <td className="mono">{f.host}</td>
                      <td>{f.owner}</td>
                      <td className="mono" title={`unknown: ${f.unknown_factors.join(', ') || 'none'}`}>
                        {Math.round(f.confidence * 100)}%
                      </td>
                      <td>
                        <button className="linkish" onClick={() => setOpen(open === f.cve + f.host ? null : f.cve + f.host)}
                          aria-expanded={open === f.cve + f.host}>
                          {open === f.cve + f.host ? 'hide factors' : 'show factors'}
                        </button>
                      </td>
                    </tr>
                    {open === f.cve + f.host && (
                      <tr className="expand">
                        <td colSpan={6}>
                          <ul className="factors">
                            {Object.entries(f.factors).map(([name, fac]) => (
                              <li key={name}>
                                <span className="mono fk">{name.replace(/_/g, ' ')}</span>
                                <span className={`mono fv ${fac.value === null ? 'dim' : ''}`}>
                                  {fac.value === null ? 'unknown' : fac.value}
                                </span>
                                <span className="ff">{fac.fact}</span>
                              </li>
                            ))}
                          </ul>
                          <p className="fineprint">
                            Unknown factors are excluded from the weighted average and lower
                            confidence — they are never scored as zero. Weights:{' '}
                            <span className="mono">
                              {Object.entries(vulns.config.weights).map(([k, v]) => `${k} ${v}`).join(' · ')}
                            </span>{' '}
                            (config sha256 {vulns.config.sha256.slice(0, 12)}…)
                          </p>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                ))}
              </tbody>
            </table>
            <p className="fineprint">
              Inventory provenance: <b>{vulns.inventory_provenance}</b>. {vulns.note}
            </p>
          </>
        )}
      </div>
    </Card>
  )
}
