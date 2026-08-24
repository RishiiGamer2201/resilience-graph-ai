/**
 * Official sources, hashed and dated.
 *
 * One card per document, carrying everything needed to check it: who published
 * it, what kind of authority that is, the document's own date, when we
 * retrieved it, which section, the excerpt, the content hash, and why the
 * retriever returned that chunk.
 *
 * When nothing matched, that is reported. A citation we cannot produce is a
 * citation we do not invent.
 */
import { ExternalLink, FileSearch, ShieldCheck } from 'lucide-react'
import { EmptyState, RevealList } from '@/components/primitives'
import { Disclosure, FinePrint } from '@/components/Disclosure'
import { Badge } from '@/components/ui/badge'
import type { EvidenceBundle, EvidenceHit } from '@/types/api'

const AUTHORITY_LABEL: Record<string, string> = {
  'government-authoritative': 'Government authority',
  'primary-framework': 'Primary framework',
  unrated: 'Unrated source',
}

export function EvidenceCard({ hit }: { hit: EvidenceHit }) {
  return (
    <article className="rounded-md border border-border bg-surface-2 p-3">
      <header className="flex items-start gap-2">
        <ShieldCheck className="mt-0.5 size-3.5 shrink-0 text-ok" aria-hidden />
        <a
          href={hit.url}
          target="_blank"
          rel="noopener noreferrer"
          className="min-w-0 flex-1 text-sm text-accent underline-offset-4 hover:underline"
        >
          {hit.title} <ExternalLink className="inline size-3" aria-hidden />
        </a>
        <Badge variant="outline">{hit.publisher}</Badge>
      </header>
      <div className="mt-1 font-mono text-xs text-faint">
        {AUTHORITY_LABEL[hit.authority] ?? hit.authority}
        {' · '}
        {hit.section}
        {' · published '}
        {hit.published || 'no date stated by source'}
        {hit.retrieved_at ? ` · retrieved ${hit.retrieved_at}` : ''}
      </div>
      <p className="mt-2 line-clamp-3 text-xs leading-relaxed text-dim" title={hit.excerpt}>
        {hit.excerpt}
      </p>
      <footer className="mt-2 flex flex-wrap items-baseline justify-between gap-2 font-mono text-xs text-faint">
        <span title="Why the retriever returned this chunk">
          why: {hit.match_reason || hit.why_relevant || 'not stated by the retriever'}
        </span>
        <span title="SHA-256 of the indexed text - the citation is checkable">
          sha256:{(hit.sha256 ?? '').slice(0, 16)}
          {hit.sha256 ? '…' : 'not reported'}
        </span>
      </footer>
    </article>
  )
}

export default function EvidenceList({
  evidence,
}: {
  evidence: EvidenceBundle | null | undefined
}) {
  const hits = evidence?.citations ?? evidence?.hits ?? []

  if (!hits.length) {
    return (
      <EmptyState
        icon={FileSearch}
        title="No official source matched"
        detail={
          evidence?.disclosure ??
          'That is reported, not filled in - a citation we cannot produce is a citation we do not invent.'
        }
      />
    )
  }

  const corpus = Object.entries(evidence?.corpus ?? {})
  const primary = hits.slice(0, 2)
  const more = hits.slice(2)

  return (
    <div className="space-y-3">
      <div className="font-mono text-xs text-faint">
        {hits.length} citation{hits.length === 1 ? '' : 's'}
        {corpus.length ? ` · ${corpus.map(([k, v]) => `${k} ${v}`).join(' · ')}` : ''}
        {evidence?.index_built_at ? ` · index built ${evidence.index_built_at}` : ''}
        {evidence?.retrieval ? ` · ${evidence.retrieval}` : ''}
      </div>
      <RevealList className="space-y-2">
        {primary.map((h) => (
          <EvidenceCard key={h.chunk_id} hit={h} />
        ))}
      </RevealList>
      {more.length ? (
        <Disclosure
          label={`Show ${more.length} more source${more.length === 1 ? '' : 's'}`}
          labelOpen="Hide additional sources"
        >
          <div className="space-y-2">
            {more.map((h) => (
              <EvidenceCard key={h.chunk_id} hit={h} />
            ))}
          </div>
        </Disclosure>
      ) : null}
      <FinePrint>
        Retrieved document text is treated as evidence, never as instruction. Excerpts are
        sanitised before display.
      </FinePrint>
    </div>
  )
}
