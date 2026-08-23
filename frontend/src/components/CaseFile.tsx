/**
 * The real incident on record, beside the synthetic scenario styled after it.
 *
 * The point of this panel is the gap. Government sources establish a small
 * number of facts; almost everything else that circulates about a well-known
 * incident is not in the public record. A product that draws a complete kill
 * chain here is fabricating most of it, so this shows what is established, what
 * is a hypothesis, and what nobody has established at all — and lets a reviewer
 * read the primary quotes.
 *
 * It renders only when the backend returns a case file. A synthetic scenario
 * correctly shows nothing, and a 404 from /casefile is the honest answer.
 */
import { BookMarked, CircleCheck, ExternalLink, TriangleAlert } from 'lucide-react'
import { Card, CardBody, CardHeader, CardMeta, CardTitle } from '@/components/ui/card'
import { Table, TBody, TD, TDMono, TH, THead, TR } from '@/components/ui/table'
import { ClaimStatus, SectionLabel } from '@/components/primitives'
import { Disclosure, FinePrint } from '@/components/Disclosure'
import type { CaseFile as CaseFileData } from '@/types/api'

export default function CaseFile({ casefile }: { casefile: CaseFileData | null | undefined }) {
  if (!casefile) return null

  const confirmed = casefile.claims.filter((c) => c.status === 'confirmed')

  return (
    <Card>
      <CardHeader>
        <CardTitle>Real incident on record — {casefile.title}</CardTitle>
        <CardMeta>
          {casefile.provenance} · {casefile.sources_verified} primary sources
        </CardMeta>
      </CardHeader>
      <CardBody className="space-y-4">
        <div className="flex items-start gap-2 rounded-md border border-border bg-surface-2 px-3 py-2 text-xs text-dim">
          <BookMarked className="mt-0.5 size-3.5 shrink-0" aria-hidden />
          <span>
            The scenario above is <span className="font-medium text-text">synthetic</span>. This
            is the public record for the real incident it is styled after. {casefile.summary}.
          </span>
        </div>

        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <div className="flex items-center gap-1.5">
              <CircleCheck className="size-3 text-ok" aria-hidden />
              <SectionLabel>Established</SectionLabel>
            </div>
            <ul className="mt-1.5 space-y-1.5 text-xs text-dim">
              {confirmed.map((c) => (
                <li key={c.external_id}>
                  <span className="font-mono text-text">{c.external_id}</span> {c.object}
                  {c.tactic ? <span className="text-faint"> · {c.tactic}</span> : null}
                </li>
              ))}
              {casefile.control_weaknesses.map((w) => (
                <li key={w.weakness}>
                  <span className="text-text">{w.weakness}</span>
                  <div className="text-faint">{w.note}</div>
                </li>
              ))}
            </ul>
          </div>
          <div>
            <div className="flex items-center gap-1.5">
              <TriangleAlert className="size-3 text-sev-high" aria-hidden />
              <SectionLabel>Not publicly established</SectionLabel>
            </div>
            <ul className="mt-1.5 space-y-1 text-xs text-faint">
              {casefile.not_established.map((n) => (
                <li key={n}>{n}</li>
              ))}
            </ul>
          </div>
        </div>
      </CardBody>

      <Table>
        <THead>
          <TR>
            <TH>Technique</TH>
            <TH>Status</TH>
            <TH className="text-right">Confidence</TH>
            <TH>Basis</TH>
          </TR>
        </THead>
        <TBody>
          {casefile.claims.map((c) => (
            <TR key={c.external_id}>
              <TDMono>
                <span className="text-text">{c.external_id}</span>
                <span className="ml-2 font-sans text-dim">{c.object}</span>
              </TDMono>
              <TD>
                <ClaimStatus status={c.status} />
              </TD>
              <TDMono className="whitespace-nowrap text-right">
                {c.confidence}
                <span className="ml-1 text-faint">{c.confidence_band}</span>
              </TDMono>
              <TD className="max-w-md text-xs text-faint">{c.note}</TD>
            </TR>
          ))}
        </TBody>
      </Table>

      <CardBody className="space-y-3 border-t border-border">
        <Disclosure
          label="Show the primary sources and the exact quotes"
          labelOpen="Hide the primary sources"
        >
          <div className="space-y-3">
            {casefile.established_facts.map((f) => {
              const src = casefile.sources.find((s) => s.id === f.source_id)
              return (
                <blockquote
                  key={f.quote}
                  className="border-l-2 border-border pl-3 text-xs text-dim"
                >
                  <p>&ldquo;{f.quote}&rdquo;</p>
                  <footer className="mt-1 font-mono text-faint">
                    {src ? (
                      <a
                        href={src.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-accent underline-offset-4 hover:underline"
                      >
                        {src.chamber} {src.question_no}, {src.answered_on}{' '}
                        <ExternalLink className="inline size-2.5" aria-hidden />
                      </a>
                    ) : (
                      f.source_id
                    )}
                    {src?.ministry ? ` · ${src.ministry}` : ''}
                  </footer>
                </blockquote>
              )
            })}
            <ul className="space-y-0.5 text-xs text-faint">
              {casefile.sources.map((s) => (
                <li key={s.id}>
                  <span className="font-mono text-dim">{s.id}</span> —{' '}
                  {s.verified
                    ? 'verified: text extracted from the fetched PDF'
                    : `NOT re-verified — ${s.note ?? 'no note given'}`}
                </li>
              ))}
            </ul>
          </div>
        </Disclosure>
        <FinePrint>{casefile.why_this_matters}</FinePrint>
        <FinePrint>{casefile.relationship_to_scenario.note}</FinePrint>
      </CardBody>
    </Card>
  )
}
