import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { RefreshCw, ExternalLink, ShieldAlert, Siren, Check, X, Waypoints, Crosshair } from 'lucide-react'
import { getThreatRadar, getIncident, getThreatIntel, getGraph } from '../api.js'
import { useScreenData } from '../lib/analysis.jsx'
import { Card, CardHeader, Loading, ErrorBox } from '../components/Card.jsx'
import LiveBadge from '../components/LiveBadge.jsx'
import { nowIST } from '../lib/format.js'

// The distinct techniques behind an item's "where you're exposed" movements —
// used to deep-link the Attack Graph to exactly those movements.
function exposureTechs(item) {
  const bridge = (item?.your_exposure && Object.keys(item.your_exposure).length)
    ? item.your_exposure : (item?.your_exposure_tactic || {})
  return [...new Set(Object.values(bridge).flat().map((m) => m.technique).filter(Boolean))]
}

// The advisory text a SOC lead would review before anything left the building.
// Generated from real fields only — no invented impact claims.
function draftAdvisory(entry, incidentId) {
  const r = entry.relevance
  const why = [
    r.matched_techniques.length ? `shares technique(s) ${r.matched_techniques.join(', ')}` : null,
    !r.matched_techniques.length && r.matched_tactics.length
      ? `shares ATT&CK tactic(s) ${r.matched_tactics.join(', ')}` : null,
    r.matched_actors.length ? `names attributed actor ${r.matched_actors.join(', ')}` : null,
  ].filter(Boolean).join('; ')
  return [
    `SECTOR ADVISORY (DRAFT — NOT DISPATCHED)`,
    `Source: ${entry.item.source} · ${entry.item.published}`,
    `Report: ${entry.item.title}`,
    `Link: ${entry.item.url}`,
    ``,
    `Relevance to ${incidentId || 'the open incident'}: ${why || 'context only'}.`,
    entry.item.techniques.length ? `Techniques in report: ${entry.item.techniques.join(', ')}` : '',
    ``,
    `Recommended action: review your own detections for the technique(s) above.`,
    `This advisory is simulated. No recipient is contacted by this system.`,
  ].filter((l) => l !== null).join('\n')
}

function SourceStatus({ sources }) {
  return (
    <div className="chips" style={{ marginTop: 4 }}>
      {sources.map((s) => (
        <span className="chip" key={s.source}
          title={s.ok ? `${s.items} items` : s.note || 'unavailable'}
          style={{ opacity: s.ok ? 1 : 0.5 }}>
          {s.ok ? '●' : '○'} {s.source}{s.ok ? ` ${s.items}` : ''}
        </span>
      ))}
    </div>
  )
}

function RadarItem({ item, names, onAlert, alerted }) {
  const rel = item.relevance || { score: 0, matched_techniques: [], matched_tactics: [], matched_actors: [] }
  const strong = rel.matched_techniques.length > 0 || rel.matched_actors.length > 0
  const related = rel.score > 0
  return (
    <div className="tech" style={{
      borderLeft: related ? `3px solid var(--sev-${strong ? 'critical' : 'high'})` : '3px solid transparent',
      paddingLeft: 10,
    }}>
      <div className="th" style={{ flexWrap: 'wrap', gap: 6 }}>
        <span className="chip">{item.source}</span>
        <span className="mono" style={{ fontSize: 11, color: 'var(--text-faint)' }}>{item.published}</span>
        {item.tags?.slice(0, 2).map((t) => (
          <span className="tag-pill" key={t}
            style={{ background: 'var(--surface-2)', color: 'var(--text-dim)' }}>{t}</span>
        ))}
      </div>

      <div style={{ margin: '4px 0 2px' }}>
        <a href={item.url} target="_blank" rel="noopener noreferrer"
          style={{ fontWeight: 600, display: 'inline-flex', gap: 5, alignItems: 'baseline' }}>
          {item.title} <ExternalLink size={11} aria-hidden="true" />
        </a>
      </div>
      {item.text && <div className="texp">{item.text.slice(0, 180)}</div>}

      {item.techniques?.length > 0 && (
        <div className="chips" style={{ marginTop: 6 }}>
          {item.techniques.map((t) => {
            const hit = rel.matched_techniques.includes(t)
            return (
              <span className="tag-pill" key={t} title={names[t] || t}
                style={hit
                  ? { background: 'color-mix(in srgb, var(--sev-critical) 16%, transparent)', color: 'var(--sev-critical)' }
                  : { background: 'var(--accent-soft)', color: 'var(--accent)' }}>
                {t} {names[t] ? `· ${names[t]}` : ''}
              </span>
            )
          })}
        </div>
      )}

      {related && (
        <div style={{ marginTop: 6, fontSize: 12, color: 'var(--text)' }}>
          <ShieldAlert size={12} aria-hidden="true"
            style={{ color: `var(--sev-${strong ? 'critical' : 'high'})`, verticalAlign: -2 }} />
          {' '}
          {rel.matched_techniques.length > 0 && <>Same technique as your incident: <b className="mono">{rel.matched_techniques.join(', ')}</b>. </>}
          {rel.matched_techniques.length === 0 && rel.matched_tactics.length > 0 &&
            <>Same ATT&CK tactic as your incident: <b>{rel.matched_tactics.join(', ')}</b>. </>}
          {rel.matched_actors.length > 0 && <>Mentions attributed actor <b>{rel.matched_actors.join(', ')}</b>. </>}
          <button className="btn" onClick={() => onAlert(item)} disabled={alerted}
            style={{ marginLeft: 6, padding: '2px 8px', fontSize: 11, display: 'inline-flex', gap: 4, alignItems: 'center' }}>
            <Siren size={11} aria-hidden="true" />
            {alerted ? 'queued — see Alert queue below' : 'Queue sector alert (simulated)'}
          </button>
        </div>
      )}

      {(() => {
        const exact = item.your_exposure && Object.keys(item.your_exposure).length > 0
        const bridge = exact ? item.your_exposure : (item.your_exposure_tactic || {})
        if (Object.keys(bridge).length === 0) return null
        const techs = exposureTechs(item)   // techniques the graph should highlight
        return (
          <div style={{ marginTop: 8, borderTop: '1px solid var(--border)', paddingTop: 8 }}>
            <div style={{ fontSize: 11.5, fontWeight: 600, marginBottom: 4 }}>
              <Crosshair size={12} aria-hidden="true" style={{ verticalAlign: -2, color: 'var(--sev-high)' }} />
              {' '}Where you're exposed — {exact ? 'same technique' : 'same tactic'} in your own incident
            </div>
            {Object.entries(bridge).map(([key, moves]) => (
              <div key={key} style={{ marginBottom: 4 }}>
                <span className="mono" style={{ fontSize: 11, color: 'var(--sev-high)' }}>{key}</span>
                <span style={{ fontSize: 11.5, color: 'var(--text-dim)' }}> — {moves.length} of your movements:</span>
                <div className="chips" style={{ marginTop: 3 }}>
                  {moves.slice(0, 8).map((m, k) => (
                    <span key={k} className="chip mono" title={`${m.technique} · anomaly score ${m.score}`}>
                      {m.from}→{m.to}{m.event_count > 1 ? ` ×${m.event_count}` : ''}
                    </span>
                  ))}
                  {moves.length > 8 && <span className="chip">+{moves.length - 8}</span>}
                </div>
              </div>
            ))}
            <Link to={`/graph?techniques=${encodeURIComponent(techs.join(','))}`} className="btn"
              style={{ marginTop: 4, padding: '2px 8px', fontSize: 11, display: 'inline-flex', gap: 4, alignItems: 'center' }}>
              <Waypoints size={11} aria-hidden="true" /> Highlight these in the Attack Graph
            </Link>
          </div>
        )
      })()}
    </div>
  )
}

export default function ThreatRadar() {
  // the incident we're investigating — live analysis bundle if one is loaded,
  // otherwise the sample. Drives the cross-reference.
  const { data: incident } = useScreenData('incident', getIncident)
  const { data: intel } = useScreenData('threat_intel', getThreatIntel)
  const { data: graph } = useScreenData('graph', getGraph)

  const [radar, setRadar] = useState(null)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const [queue, setQueue] = useState([])          // simulated, human-gated alert queue

  const enqueue = (item) => setQueue((q) => (
    q.some((e) => e.item.url === item.url) ? q : [
      { item, relevance: item.relevance, queued_at: nowIST(), status: 'pending' }, ...q,
    ]
  ))
  const setStatus = (url, status) => setQueue((q) =>
    q.map((e) => (e.item.url === url ? { ...e, status, decided_at: nowIST() } : e)))

  const techniques = incident?.technique_ids || []
  const actors = (intel?.attribution || []).slice(0, 3).map((a) => a.actor)
  // compact edges so the backend can map an external technique -> your movements
  const edges = (graph?.edges || []).map((e) => ({
    technique: e.technique, from: e.from, to: e.to, score: e.score, event_count: e.event_count,
  }))

  const load = useCallback(async (refresh = false) => {
    setBusy(true); setError(null)
    try {
      setRadar(await getThreatRadar({ technique_ids: techniques, actors, edges, refresh }))
    } catch (e) {
      setError(e)
    } finally {
      setBusy(false)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [JSON.stringify(techniques), JSON.stringify(actors), edges.length])

  useEffect(() => { load(false) }, [load])

  if (!radar && busy) return <Loading label="Loading threat radar…" />
  if (error) return <ErrorBox error={error} />
  if (!radar) return <Loading />

  const names = radar.technique_names || {}
  const relevant = radar.items.filter((i) => i.relevance?.score > 0)
  const rest = radar.items.filter((i) => !(i.relevance?.score > 0))
  const live = radar.meta?.source === 'live'

  return (
    <>
      <div className="page-head">
        <span className="tag-pill" style={{ background: 'var(--accent-soft)', color: 'var(--accent)' }}>
          EXTERNAL INTEL
        </span>
        <h2>Threat Radar</h2>
        <p>Free, purpose-built CTI feeds mapped to MITRE ATT&amp;CK and cross-referenced
          with the incident you're investigating.</p>
      </div>

      <Card>
        <CardHeader title="Feed status" meta={`fetched ${radar.fetched_at}`}>
          <LiveBadge live={live} />
          <button className="btn" onClick={() => load(true)} disabled={busy}
            style={{ display: 'inline-flex', gap: 6, alignItems: 'center', marginLeft: 8 }}>
            <RefreshCw size={13} aria-hidden="true" /> {busy ? 'Fetching…' : 'Refresh (live)'}
          </button>
        </CardHeader>
        <div className="card-b pad">
          <SourceStatus sources={radar.sources || []} />
          <div className="note" style={{ marginTop: 10 }}>{radar.note}</div>
        </div>
      </Card>

      <div className="section-label">
        Relevant to your incident{incident?.incident_id ? ` · ${incident.incident_id}` : ''}
      </div>
      <Card>
        <CardHeader title="Cross-referenced hits"
          meta={techniques.length ? `matching ${techniques.join(', ')}${actors.length ? ` · ${actors[0]}` : ''}` : 'no incident loaded'} />
        <div className="card-b pad" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          {relevant.length === 0 ? (
            <div style={{ color: 'var(--text-dim)', fontSize: 13, lineHeight: 1.6 }}>
              <b>No current external item matches this incident.</b> That is a real result,
              not a gap: your incident is authentication-based
              ({techniques.join(', ') || '—'}), while today's public feeds are dominated by
              vulnerability and malware reporting. We show it plainly rather than
              manufacture a match — a hit here would mean the outside world is talking
              about the same techniques you are seeing.
            </div>
          ) : relevant.map((i) => (
            <RadarItem key={i.url} item={i} names={names}
              alerted={queue.some((e) => e.item.url === i.url)} onAlert={enqueue} />
          ))}
        </div>
        <div className="note">
          Alerts are <b>simulated and human-gated</b> — the same policy as our SOAR actions.
          Nothing is dispatched to any real organisation.
        </div>
      </Card>

      {queue.length > 0 && (
        <>
          <div className="section-label">Alert queue · {queue.filter((e) => e.status === 'pending').length} awaiting approval</div>
          <Card>
            <CardHeader title="Queued sector alerts"
              meta="simulated · a SOC lead approves before anything would leave" />
            <div className="card-b pad" style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              {queue.map((e) => (
                <div key={e.item.url} className="tech" style={{
                  borderLeft: `3px solid var(--sev-${e.status === 'approved' ? 'medium' : e.status === 'dismissed' ? 'normal' : 'high'})`,
                  paddingLeft: 10, opacity: e.status === 'dismissed' ? 0.55 : 1,
                }}>
                  <div className="th" style={{ flexWrap: 'wrap', gap: 6 }}>
                    <span className="chip">{e.item.source}</span>
                    <span className="tag-pill" style={{
                      background: e.status === 'pending'
                        ? 'color-mix(in srgb, var(--sev-high) 16%, transparent)'
                        : 'var(--surface-2)',
                      color: e.status === 'pending' ? 'var(--sev-high)' : 'var(--text-dim)',
                    }}>
                      {e.status === 'pending' ? 'awaiting human approval'
                        : e.status === 'approved' ? 'approved · simulated, not dispatched'
                        : 'dismissed'}
                    </span>
                    <span className="mono" style={{ fontSize: 11, color: 'var(--text-faint)' }}>
                      queued {e.queued_at}{e.decided_at ? ` · decided ${e.decided_at}` : ''}
                    </span>
                  </div>

                  <div style={{ fontWeight: 600, margin: '4px 0' }}>{e.item.title}</div>

                  <div style={{ fontSize: 12, color: 'var(--text-dim)', marginBottom: 6 }}>
                    Would notify: <b>sector CERT / peer operators</b> (simulated recipient) ·
                    Basis: {e.relevance.matched_techniques.length
                      ? <>technique <b className="mono">{e.relevance.matched_techniques.join(', ')}</b></>
                      : e.relevance.matched_tactics.length
                        ? <>tactic <b>{e.relevance.matched_tactics.join(', ')}</b></>
                        : 'context'}
                    {e.relevance.matched_actors.length > 0 && <> · actor <b>{e.relevance.matched_actors.join(', ')}</b></>}
                  </div>

                  <details>
                    <summary style={{ cursor: 'pointer', fontSize: 12, color: 'var(--accent)' }}>
                      View draft advisory
                    </summary>
                    <pre className="mono" style={{
                      whiteSpace: 'pre-wrap', fontSize: 11.5, background: 'var(--surface-2)',
                      border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)',
                      padding: 10, marginTop: 6, color: 'var(--text-dim)',
                    }}>{draftAdvisory(e, incident?.incident_id)}</pre>
                  </details>

                  <div style={{ display: 'flex', gap: 8, marginTop: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                    {e.status === 'pending' && (
                      <>
                        <button className="btn primary" onClick={() => setStatus(e.item.url, 'approved')}
                          style={{ padding: '3px 9px', fontSize: 11.5, display: 'inline-flex', gap: 4, alignItems: 'center' }}>
                          <Check size={12} aria-hidden="true" /> Approve (simulated)
                        </button>
                        <button className="btn" onClick={() => setStatus(e.item.url, 'dismissed')}
                          style={{ padding: '3px 9px', fontSize: 11.5, display: 'inline-flex', gap: 4, alignItems: 'center' }}>
                          <X size={12} aria-hidden="true" /> Dismiss
                        </button>
                      </>
                    )}
                    <Link to={exposureTechs(e.item).length
                      ? `/graph?techniques=${encodeURIComponent(exposureTechs(e.item).join(','))}`
                      : '/graph'} className="btn"
                      style={{ padding: '3px 9px', fontSize: 11.5, display: 'inline-flex', gap: 4, alignItems: 'center' }}>
                      <Waypoints size={12} aria-hidden="true" /> Review your attack path
                    </Link>
                    <a className="btn" href={e.item.url} target="_blank" rel="noopener noreferrer"
                      style={{ padding: '3px 9px', fontSize: 11.5, display: 'inline-flex', gap: 4, alignItems: 'center' }}>
                      <ExternalLink size={12} aria-hidden="true" /> Source report
                    </a>
                  </div>
                </div>
              ))}
            </div>
            <div className="note">
              <b>External intel has no attack path of its own</b> — we hold no telemetry for someone
              else's breach, and inventing one would be fabrication. The path lives with <i>your</i>
              {' '}incident: <Link to="/graph">Attack Graph</Link> · <Link to="/incident">Live Incident</Link>.
              Approval here is a simulated gate; nothing is transmitted.
            </div>
          </Card>
        </>
      )}

      <div className="section-label">Everything the radar is watching · {rest.length}</div>
      <Card>
        <CardHeader title="Live threat feed" meta="newest first" />
        <div className="card-b pad" style={{ display: 'flex', flexDirection: 'column', gap: 14,
                                             maxHeight: 620, overflowY: 'auto' }}>
          {rest.map((i) => (
            <RadarItem key={i.url} item={i} names={names}
              alerted={queue.some((e) => e.item.url === i.url)} onAlert={enqueue} />
          ))}
        </div>
      </Card>
    </>
  )
}
