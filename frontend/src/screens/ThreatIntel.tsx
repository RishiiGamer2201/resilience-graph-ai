/**
 * Threat Intel & Attribution.
 *
 * GET /api/threat-intel returns three things: the observed techniques with
 * their own ATT&CK descriptions, a ranked list of public group profiles, and
 * the note that says what that ranking is.
 *
 * ATTRIBUTION IS NOT IDENTIFICATION. The backend does weighted retrieval over
 * public ATT&CK group profiles and prints its arithmetic; it is not a trained
 * classifier and it has not identified anybody. So no row here is styled as
 * "the attacker": every candidate renders identically apart from its rank, and
 * the score, the technique overlap that produced it and the printed
 * justification are all on screen next to the name.
 *
 * The old screen ended its narrative fallback chain with a hand-written
 * paragraph about "anomalous authentication activity" that rendered whenever
 * the pipeline produced nothing. That is fabrication and it is gone: if no
 * narrative was generated, the card says so.
 */
import { Shield, Sparkles } from 'lucide-react'
import { getOverview, getThreatIntel } from '@/lib/api'
import { useAnalysis, useScreenData } from '@/providers/analysis'
import { PageHeader } from '@/components/Layout'
import { Badge } from '@/components/ui/badge'
import PredictNextWidget from '@/components/PredictNextWidget'
import { Card, CardBody, CardFooter, CardHeader, CardMeta, CardTitle } from '@/components/ui/card'
import { SkeletonRows } from '@/components/ui/skeleton'
import { InfoTip } from '@/components/ui/tooltip'
import {
  EmptyState,
  ErrorState,
  Reveal,
  SectionLabel,
} from '@/components/primitives'
import type { ActorMatch, AnalysisBundle, OverviewView, ThreatIntelView } from '@/types/api'

/** The synthesized incident narrative and, always, where it came from. */
function NarrativeCard({ bundle }: { bundle: AnalysisBundle | null }) {
  // The cached overview carries the agent lane at the top level, a live bundle
  // under meta. Never fabricate one: the old screen ended this chain with a
  // hand-written paragraph, which is why that paragraph is gone.
  const cached = useScreenData<OverviewView>(bundle?.overview, getOverview)
  const lane =
    bundle?.meta?.agent_pipeline ?? bundle?.agent_pipeline ?? cached.data?.agent_pipeline
  const narrative = lane?.incident_narrative

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Sparkles className="size-3.5 text-accent" aria-hidden />
          Attack assessment, in plain English
        </CardTitle>
        <CardMeta>agent lane · second opinion, not authoritative</CardMeta>
      </CardHeader>
      <CardBody>
        {cached.loading && !lane ? (
          <SkeletonRows rows={2} />
        ) : cached.error && !lane ? (
          <ErrorState error={cached.error} />
        ) : narrative ? (
          <>
            <p className="text-sm leading-relaxed text-text">{narrative}</p>
            <ProvenanceForLane method={lane?.point_b_method} error={lane?.error} />
          </>
        ) : (
          <EmptyState
            title="No narrative was generated for this incident"
            detail={
              lane?.status
                ? `The agent lane reported status "${lane.status}".`
                : 'The agent lane did not run on this bundle.'
            }
          />
        )}
      </CardBody>
    </Card>
  )
}

/** point_b_method is `template` when no model was involved. Kept on screen so a
 *  template cannot read as a model answer. */
function ProvenanceForLane({ method, error }: { method?: string; error?: string }) {
  if (!method) return null
  return (
    <div className="mt-2 font-mono text-xs text-faint">
      {method === 'template' || method === 'deterministic'
        ? `template · no language model${error ? ` · ${error}` : ''}`
        : `${method} · reworded, not authoritative${error ? ` · ${error}` : ''}`}
    </div>
  )
}

/** One ranked profile match. Deliberately identical to every other row: the
 *  top-scoring group is a candidate, not a finding. */
function ActorRow({ match, rank }: { match: ActorMatch; rank: number }) {
  return (
    <div className="border-b border-border py-2.5 last:border-0">
      <div className="flex items-baseline justify-between gap-3">
        <div className="flex min-w-0 items-baseline gap-2">
          <span className="font-mono text-xs text-faint">#{rank}</span>
          <span className="truncate text-sm font-medium text-text">{match.actor}</span>
        </div>
        <div className="flex shrink-0 items-baseline gap-3">
          <InfoTip label="Retrieval score combining observed-technique coverage, profile overlap and semantic similarity. It is a match strength, not a probability that this group is responsible.">
            <span className="font-mono text-sm tabular-nums text-text">
              {match.score.toFixed(3)}
            </span>
          </InfoTip>
          <span className="font-mono text-xs tabular-nums text-dim">
            {(match.coverage * 100).toFixed(0)}% overlap
          </span>
        </div>
      </div>

      {match.matched.length ? (
        <div className="mt-1.5 flex flex-wrap gap-1">
          {match.matched.map((t) => (
            <span
              key={t}
              className="rounded-md border border-accent/30 bg-accent-soft px-1.5 py-0.5 font-mono text-xs text-accent"
            >
              {t}
            </span>
          ))}
        </div>
      ) : (
        <div className="mt-1.5 text-xs text-faint">
          No observed technique is in this group&apos;s public profile; the score is
          semantic similarity only.
        </div>
      )}

      <p className="mt-1.5 text-xs text-faint">{match.justification}</p>
    </div>
  )
}

export default function ThreatIntel() {
  const { bundle, source: bundleSource } = useAnalysis()
  const cached = useScreenData<ThreatIntelView>(
    bundle?.threat_intel,
    getThreatIntel,
    bundleSource,
  )
  // A live analysis publishes its own threat_intel slice; the cached endpoint
  // is the sample. Which one is on screen is stated in the header.
  const data = cached.data
  const { error, loading, reload, source } = cached

  if (loading && !data) {
    return (
      <>
        <PageHeader eyebrow="Intelligence" title="Threat Intel & Attribution" />
        <div className="grid gap-4 xl:grid-cols-2">
          {[0, 1].map((i) => (
            <Card key={i}>
              <CardBody>
                <SkeletonRows rows={5} />
              </CardBody>
            </Card>
          ))}
        </div>
      </>
    )
  }

  if (!data) {
    return (
      <>
        <PageHeader eyebrow="Intelligence" title="Threat Intel & Attribution" />
        <Card>
          <ErrorState error={error ?? new Error('no data')} retry={reload} />
        </Card>
      </>
    )
  }

  const mapping = data.mapping ?? []
  const attribution = data.attribution ?? []
  const observed = mapping.map((m) => m.technique_id)

  return (
    <>
      <PageHeader
        eyebrow="Intelligence"
        title="Threat Intel & Attribution"
        description="Observed techniques with their own ATT&CK descriptions, and the public group profiles that overlap them."
        actions={
          <Badge variant={source === 'live' ? 'accent' : 'outline'}>
            {source === 'live'
              ? 'live analysis'
              : source === 'restored'
                ? 'restored session'
                : 'sample cache'}
          </Badge>
        }
      />

      <Reveal>
        <NarrativeCard bundle={bundle} />
      </Reveal>

      <div className="mt-4 grid gap-4 xl:grid-cols-2">
        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Observed techniques</CardTitle>
              <CardMeta>{mapping.length} mapped</CardMeta>
            </CardHeader>
            {mapping.length ? (
              <CardBody className="space-y-3">
                {mapping.map((m) => (
                  <div key={m.technique_id} className="border-b border-border pb-3 last:border-0 last:pb-0">
                    <div className="flex items-baseline gap-2">
                      <span className="font-mono text-xs text-accent">{m.technique_id}</span>
                      <span className="text-sm font-medium text-text">{m.name}</span>
                    </div>
                    <p className="mt-1 text-xs leading-relaxed text-dim">{m.explanation}</p>
                  </div>
                ))}
              </CardBody>
            ) : (
              <EmptyState
                title="No technique mapped on this incident"
                detail="Nothing in the log matched an ATT&CK technique, so there is nothing to attribute."
              />
            )}
            <CardFooter>
              Descriptions are ATT&amp;CK&apos;s own text for the technique, not
              generated commentary about this incident.
            </CardFooter>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Predict next technique</CardTitle>
              <CardMeta>POST /predict-next</CardMeta>
            </CardHeader>
            <PredictNextWidget given={observed} />
          </Card>
        </div>

        <Card>
          <CardHeader>
            <CardTitle>Actor profile matches</CardTitle>
            <CardMeta>{attribution.length} ranked candidates</CardMeta>
          </CardHeader>
          <CardBody>
            <SectionLabel className="mb-2">
              Ranked candidates — not an identification
            </SectionLabel>
            {attribution.length ? (
              attribution.map((a, i) => <ActorRow key={a.actor} match={a} rank={i + 1} />)
            ) : (
              <EmptyState
                title="No group profile was ranked"
                detail="Ranking needs at least one observed technique present in the ATT&CK embedding artifact."
                icon={Shield}
              />
            )}
          </CardBody>
          {data.note ? <CardFooter>{data.note}</CardFooter> : null}
        </Card>
      </div>
    </>
  )
}
