import { useState } from 'react'
import { BookMarked, CircleCheck, CircleHelp, ExternalLink, TriangleAlert } from 'lucide-react'
import { Card, CardHeader } from './Card.jsx'

// The real incident, beside the synthetic scenario styled after it.
//
// The point of this card is the gap. Government sources established exactly one
// ATT&CK technique for AIIMS 2022. Everything else that circulates about that
// incident — the initial vector, the ransomware family, the actor, the data
// theft — is not in the public record. A product that draws a complete kill
// chain here is fabricating most of it, so this shows what is known, what is a
// hypothesis, and what nobody has established.
const STATUS_ICON = { confirmed: CircleCheck, inferred: CircleHelp, predicted: CircleHelp }
const STATUS_CLASS = { confirmed: 's-low', inferred: 's-medium', predicted: 's-high' }

export default function CaseFile({ casefile }) {
  const [open, setOpen] = useState(false)
  if (!casefile) return null

  return (
    <Card>
      <CardHeader title={`Real incident on record — ${casefile.title}`}
        meta={`${casefile.provenance} · ${casefile.sources_verified} primary sources`} />
      <div className="card-b pad stack-sm">
        <div className="banner">
          <BookMarked size={15} aria-hidden="true" />
          <span>
            The scenario above is <b>synthetic</b>. This is the public record for the
            real incident it is styled after. {casefile.summary}.
          </span>
        </div>

        <div className="cf-split">
          <div className="cf-col">
            <div className="cf-h"><CircleCheck size={13} aria-hidden="true" className="s-low" /> Established</div>
            <ul className="cf-list">
              {casefile.claims.filter((c) => c.status === 'confirmed').map((c) => (
                <li key={c.external_id}>
                  <b className="mono">{c.external_id}</b> {c.object}
                  <span className="dim"> · {c.tactic}</span>
                </li>
              ))}
              {casefile.control_weaknesses.map((w) => (
                <li key={w.weakness}>
                  {w.weakness}
                  <div className="dim">{w.note}</div>
                </li>
              ))}
            </ul>
          </div>
          <div className="cf-col">
            <div className="cf-h"><TriangleAlert size={13} aria-hidden="true" className="s-high" /> Not publicly established</div>
            <ul className="cf-list dim">
              {casefile.not_established.map((n) => <li key={n}>{n}</li>)}
            </ul>
          </div>
        </div>

        <table className="tbl">
          <caption className="sr-only">ATT&amp;CK claims for the real incident</caption>
          <thead>
            <tr>
              <th scope="col">Technique</th><th scope="col">Status</th>
              <th scope="col">Confidence</th><th scope="col">Basis</th>
            </tr>
          </thead>
          <tbody>
            {casefile.claims.map((c) => {
              const Icon = STATUS_ICON[c.status] || CircleHelp
              return (
                <tr key={c.external_id}>
                  <th scope="row" className="mono">{c.external_id} <span className="dim">{c.object}</span></th>
                  <td className={STATUS_CLASS[c.status]}>
                    <Icon size={12} aria-hidden="true" /> {c.status}
                  </td>
                  <td className="mono">{c.confidence} <span className="band">{c.confidence_band}</span></td>
                  <td className="cf-why">{c.note}</td>
                </tr>
              )
            })}
          </tbody>
        </table>

        <button className="linkish" onClick={() => setOpen(!open)} aria-expanded={open}>
          {open ? 'Hide' : 'Show'} the primary sources and the exact quotes
        </button>
        {open && (
          <div className="cf-sources">
            {casefile.established_facts.map((f) => {
              const src = casefile.sources.find((s) => s.id === f.source_id)
              return (
                <blockquote key={f.quote} className="cf-quote">
                  <p>&ldquo;{f.quote}&rdquo;</p>
                  <footer className="mono">
                    {src ? (
                      <a href={src.url} target="_blank" rel="noopener noreferrer">
                        {src.chamber} {src.question_no}, {src.answered_on}
                        {' '}<ExternalLink size={10} aria-hidden="true" />
                      </a>
                    ) : f.source_id}
                    {src?.ministry ? ` · ${src.ministry}` : ''}
                  </footer>
                </blockquote>
              )
            })}
            <ul className="cf-list fineprint">
              {casefile.sources.map((s) => (
                <li key={s.id}>
                  <b>{s.id}</b> — {s.verified
                    ? 'verified: text extracted from the fetched PDF'
                    : `NOT re-verified — ${s.note}`}
                </li>
              ))}
            </ul>
          </div>
        )}

        <p className="fineprint">{casefile.why_this_matters}</p>
        <p className="fineprint">{casefile.relationship_to_scenario.note}</p>
      </div>
    </Card>
  )
}
