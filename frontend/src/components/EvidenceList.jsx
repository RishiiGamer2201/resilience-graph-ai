import { ExternalLink, ShieldCheck } from 'lucide-react'

const AUTHORITY_LABEL = {
  'government-authoritative': 'Government authority',
  'primary-framework': 'Primary framework',
  unrated: 'Unrated source',
}

// One official document, with everything needed to check it: who published it,
// what kind of authority that is, the document's own date, when WE retrieved it,
// which section, the excerpt, the content hash, and why the retriever returned it.
export function EvidenceCard({ hit }) {
  return (
    <article className="evidence">
      <header>
        <ShieldCheck size={14} aria-hidden="true" className="s-low" />
        <a href={hit.url} target="_blank" rel="noopener noreferrer">
          {hit.title} <ExternalLink size={11} aria-hidden="true" />
        </a>
        <span className="spacer" />
        <span className="chip">{hit.publisher}</span>
      </header>
      <div className="ev-meta mono">
        {AUTHORITY_LABEL[hit.authority] || hit.authority}
        {' · '}{hit.section}
        {' · '}published {hit.published || 'no date stated by source'}
        {' · '}retrieved {hit.retrieved_at}
      </div>
      <p className="ev-excerpt">{hit.excerpt}</p>
      <footer className="mono">
        <span title="Why the retriever returned this chunk">why: {hit.match_reason || hit.why_relevant || '—'}</span>
        <span className="spacer" />
        <span title="SHA-256 of the indexed text — the citation is checkable">
          sha256:{String(hit.sha256 || '').slice(0, 16)}…
        </span>
      </footer>
    </article>
  )
}

export default function EvidenceList({ evidence }) {
  const hits = evidence?.citations || evidence?.hits || []
  if (!hits.length) {
    return (
      <div className="disclosure">
        No official source matched. That is reported, not filled in — a citation we
        cannot produce is a citation we do not invent.
      </div>
    )
  }
  return (
    <>
      <div className="ev-corpus mono">
        {hits.length} citation{hits.length === 1 ? '' : 's'} ·{' '}
        {Object.entries(evidence.corpus || {}).map(([k, v]) => `${k} ${v}`).join(' · ')}
        {evidence.index_built_at ? ` · index built ${evidence.index_built_at}` : ''}
        {' · '}{evidence.retrieval || 'bundled read-only index, no network'}
      </div>
      <div className="ev-list">
        {hits.map((h) => <EvidenceCard key={h.chunk_id} hit={h} />)}
      </div>
      <p className="fineprint">
        Retrieved document text is treated as evidence, never as instruction. Excerpts
        are sanitised before display.
      </p>
    </>
  )
}
