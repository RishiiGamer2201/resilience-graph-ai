import { useCallback, useEffect, useState } from 'react'
import { RefreshCw, ExternalLink, ShieldAlert, Siren } from 'lucide-react'
import { getThreatRadar, getIncident, getThreatIntel } from '../api.js'
import { useScreenData } from '../lib/analysis.jsx'
import { Card, CardHeader, Loading, ErrorBox } from '../components/Card.jsx'
import LiveBadge from '../components/LiveBadge.jsx'

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
          <button className="btn" onClick={() => onAlert(item.url)} disabled={alerted}
            style={{ marginLeft: 6, padding: '2px 8px', fontSize: 11, display: 'inline-flex', gap: 4, alignItems: 'center' }}>
            <Siren size={11} aria-hidden="true" />
            {alerted ? 'queued · awaiting human approval' : 'Queue sector alert (simulated)'}
          </button>
        </div>
      )}
    </div>
  )
}

export default function ThreatRadar() {
  // the incident we're investigating — live analysis bundle if one is loaded,
  // otherwise the sample. Drives the cross-reference.
  const { data: incident } = useScreenData('incident', getIncident)
  const { data: intel } = useScreenData('threat_intel', getThreatIntel)

  const [radar, setRadar] = useState(null)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const [alerted, setAlerted] = useState({})

  const techniques = incident?.technique_ids || []
  const actors = (intel?.attribution || []).slice(0, 3).map((a) => a.actor)

  const load = useCallback(async (refresh = false) => {
    setBusy(true); setError(null)
    try {
      setRadar(await getThreatRadar({ technique_ids: techniques, actors, refresh }))
    } catch (e) {
      setError(e)
    } finally {
      setBusy(false)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [JSON.stringify(techniques), JSON.stringify(actors)])

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
            <RadarItem key={i.url} item={i} names={names} alerted={!!alerted[i.url]}
              onAlert={(u) => setAlerted((a) => ({ ...a, [u]: true }))} />
          ))}
        </div>
        <div className="note">
          Alerts are <b>simulated and human-gated</b> — the same policy as our SOAR actions.
          Nothing is dispatched to any real organisation.
        </div>
      </Card>

      <div className="section-label">Everything the radar is watching · {rest.length}</div>
      <Card>
        <CardHeader title="Live threat feed" meta="newest first" />
        <div className="card-b pad" style={{ display: 'flex', flexDirection: 'column', gap: 14,
                                             maxHeight: 620, overflowY: 'auto' }}>
          {rest.map((i) => (
            <RadarItem key={i.url} item={i} names={names} alerted={!!alerted[i.url]}
              onAlert={(u) => setAlerted((a) => ({ ...a, [u]: true }))} />
          ))}
        </div>
      </Card>
    </>
  )
}
