/**
 * Overview — the reference implementation.
 *
 * THIS FILE IS THE EXEMPLAR every other screen follows. It shows the required
 * shape: real API through `@/lib/api`, `useFetch` for loading and error,
 * `Skeleton` while pending, `ErrorState` carrying the backend's own message,
 * `NotMeasured` where a figure is absent, primitives for everything, and motion
 * only where data arrives.
 *
 * Nothing on this screen is hardcoded. If the API does not return a field, the
 * screen says so rather than inventing a plausible value.
 */
import { Activity, GitBranch, ShieldAlert, Users } from 'lucide-react'
import { getOverviewBundle } from '@/lib/api'
import { useAnalysis, useScreenData } from '@/providers/analysis'
import { PageHeader } from '@/components/Layout'
import { Badge } from '@/components/ui/badge'
import { Card, CardBody, CardHeader, CardMeta, CardTitle } from '@/components/ui/card'
import { SkeletonRows } from '@/components/ui/skeleton'
import { Table, TBody, TD, TDMono, TH, THead, TR } from '@/components/ui/table'
import {
  ClaimStatus,
  EmptyState,
  ErrorState,
  MeasuredValue,
  NotMeasured,
  Reveal,
  RevealList,
  SectionLabel,
  SeverityBadge,
  StatRow,
} from '@/components/primitives'
import type { AnalysisBundle, InvestigationClaim } from '@/types/api'

export default function Overview() {
  const { bundle, source: bundleSource } = useAnalysis()
  const { data, error, loading, reload, source } = useScreenData<AnalysisBundle>(
    bundle,
    getOverviewBundle,
    bundleSource,
  )

  if (loading) {
    return (
      <>
        <PageHeader eyebrow="Operations" title="Overview" />
        <div className="grid gap-4 md:grid-cols-4">
          {Array.from({ length: 4 }, (_, i) => (
            <Card key={i}>
              <CardBody>
                <SkeletonRows rows={2} />
              </CardBody>
            </Card>
          ))}
        </div>
      </>
    )
  }

  if (error || !data) {
    return (
      <>
        <PageHeader eyebrow="Operations" title="Overview" />
        <Card>
          <ErrorState error={error ?? new Error('no data')} retry={reload} />
        </Card>
      </>
    )
  }

  const incident = data.incident
  const graph = data.graph
  const overview = data.overview
  const analysis = data.analysis ?? overview?.analysis
  const alerts = overview?.alerts_correlated.alerts
  const accounts = incident.accounts_involved ?? []
  const mttd = overview?.mttd

  return (
    <>
      <PageHeader
        eyebrow="Operations"
        title="Incident brief"
        description="One operational picture: observed scope, evidence strength and the decisions the pipeline can justify."
        actions={
          <>
            <Badge variant={source === 'live' ? 'accent' : 'outline'}>
              {source === 'live' ? 'live analysis' : source === 'restored' ? 'restored session' : 'sample cache'}
            </Badge>
            <SeverityBadge severity={incident.severity} />
          </>
        }
      />

      {/* One connected status ledger, not four disconnected KPI cards. */}
      <Reveal>
        <div className="grid overflow-hidden border border-border bg-surface sm:grid-cols-2 xl:grid-cols-4">
          <div className="min-h-32 border-b border-border p-4 sm:border-r xl:border-b-0">
            <div className="section-label">Incident state</div>
            <div className="mt-5 flex flex-wrap items-center gap-2">
              {incident?.severity ? <SeverityBadge severity={incident.severity} /> : <NotMeasured />}
              <span className="font-mono text-xs text-faint">{incident?.incident_id}</span>
            </div>
          </div>
          <div className="min-h-32 border-b border-border p-4 xl:border-b-0 xl:border-r">
            <div className="section-label">Signals collapsed</div>
            <div className="mt-3 font-mono text-2xl tabular-nums text-text">
              {incident ? incident.event_count.toLocaleString() : <NotMeasured />}
            </div>
            <div className="mt-1 text-xs text-dim">
              {alerts != null ? `${alerts.toLocaleString()} alerts above threshold` : <NotMeasured />}
            </div>
          </div>
          <div className="min-h-32 border-b border-border p-4 sm:border-r sm:border-b-0">
            <div className="section-label">Reachable blast radius</div>
            <div className="mt-3 font-mono text-2xl tabular-nums text-text">
              {graph?.blast_radius_size != null ? graph.blast_radius_size.toLocaleString() : <NotMeasured why="No attack graph was built for this incident." />}
            </div>
            <div className="mt-1 text-xs text-dim">hosts reachable on the observed graph</div>
          </div>
          <div className="min-h-32 p-4">
            <div className="section-label">Mean time to detect</div>
            <div className="mt-3 font-mono text-2xl tabular-nums text-text">
              {mttd?.value ?? <NotMeasured why="Detection time was not computed." />}
            </div>
            <div className="mt-1 text-xs text-dim">{mttd?.note ?? 'From first malicious event to first alert.'}</div>
          </div>
        </div>
      </Reveal>

      <div className="mt-4 grid gap-4 xl:grid-cols-3">
        {/* Assessment: four separate numbers, never blended into one bar. */}
        <Card className="xl:col-span-2">
          <CardHeader>
            <CardTitle>Assessment</CardTitle>
            <CardMeta>four axes, reported separately</CardMeta>
          </CardHeader>
          <CardBody>
            {analysis?.assessment ? (
              <div className="grid gap-x-8 gap-y-1 sm:grid-cols-2">
                {(
                  [
                    ['Anomaly', analysis.assessment.anomaly],
                    ['Attack progression likelihood', analysis.assessment.likelihood],
                    ['Impact', analysis.assessment.impact],
                    ['Evidence confidence', analysis.assessment.confidence],
                  ] as const
                ).map(([label, m]) => (
                  <StatRow key={label} label={label}>
                    {m?.band ? (
                      <span className="mr-2 font-sans text-dim">{m.band}</span>
                    ) : null}
                    <MeasuredValue m={m ?? null} />
                  </StatRow>
                ))}
              </div>
            ) : (
              <EmptyState
                title="No assessment on this bundle"
                detail="The analysis layer runs on live analysis and on the cached sample. If this is empty the bundle predates it."
              />
            )}
          </CardBody>
        </Card>

        {/* Scope */}
        <Card>
          <CardHeader>
            <CardTitle>Scope</CardTitle>
            <CardMeta>
              <Users className="inline size-3" /> {accounts.length}
            </CardMeta>
          </CardHeader>
          <CardBody className="space-y-1">
            <StatRow label="Entry host">
              {graph?.entry_host ?? <NotMeasured why="No entry point could be identified." />}
            </StatRow>
            <StatRow label="Recommended isolation">
              {graph?.recommended_isolation ?? (
                <NotMeasured why="No single host removal improved containment." />
              )}
            </StatRow>
            <StatRow label="Systems removed from reach">
              {graph?.isolation_cuts != null ? graph.isolation_cuts : <NotMeasured />}
            </StatRow>
            <StatRow label="Crown jewels reachable">
              {graph?.critical_assets_at_risk?.length ? (
                graph.critical_assets_at_risk.length
              ) : (
                <span className="text-faint">none marked reachable</span>
              )}
            </StatRow>
            <StatRow label="Graph">
              {graph ? `${graph.n_nodes} nodes · ${graph.n_edges} edges` : <NotMeasured />}
            </StatRow>
          </CardBody>
        </Card>
      </div>

      {/* Claims: status is always visible; an inferred finding never renders
          identically to an observed one. */}
      <Card className="mt-4">
        <CardHeader>
          <CardTitle>Findings</CardTitle>
          <CardMeta>
            {analysis?.claims?.length ?? 0} claim
            {analysis?.claims?.length === 1 ? '' : 's'}
          </CardMeta>
        </CardHeader>
        {analysis?.claims?.length ? (
          <Table>
            <THead>
              <TR>
                <TH>Technique</TH>
                <TH>Status</TH>
                <TH className="text-right">Confidence</TH>
                <TH>Still missing</TH>
              </TR>
            </THead>
            <TBody>
              {analysis.claims.map((c: InvestigationClaim) => (
                <TR key={c.external_id}>
                  <TDMono>
                    <span className="text-text">{c.external_id}</span>
                    {c.object ? (
                      <span className="ml-2 font-sans text-dim">{c.object}</span>
                    ) : null}
                  </TDMono>
                  <TD>
                    <ClaimStatus status={c.status} />
                  </TD>
                  <TDMono className="text-right">
                    {typeof c.confidence === 'number' ? (
                      c.confidence.toFixed(3)
                    ) : (
                      <NotMeasured />
                    )}
                  </TDMono>
                  <TD className="max-w-md text-xs text-faint">
                    {c.missing_evidence?.length
                      ? c.missing_evidence.join('; ')
                      : 'nothing outstanding'}
                  </TD>
                </TR>
              ))}
            </TBody>
          </Table>
        ) : (
          <EmptyState
            title="No claims on this incident"
            detail="A claim is only raised where a rule matched an alerting event."
            icon={ShieldAlert}
          />
        )}
      </Card>

      {/* The two lanes may disagree. Both are shown; neither is suppressed. */}
      {analysis?.crosscheck ? (
        <Card className="mt-4">
          <CardHeader>
            <CardTitle>Cross-check</CardTitle>
            <CardMeta>{analysis.crosscheck.verdict}</CardMeta>
          </CardHeader>
          <CardBody>
            {analysis.crosscheck.available ? (
              <>
                <div className="grid gap-4 sm:grid-cols-2">
                  <div>
                    <SectionLabel>Workflow (authoritative)</SectionLabel>
                    <div className="mt-1 flex items-center gap-2">
                      <SeverityBadge severity={analysis.crosscheck.severity?.workflow} />
                    </div>
                    <p className="mt-1 text-xs text-faint">
                      {analysis.crosscheck.severity?.basis_workflow}
                    </p>
                  </div>
                  <div>
                    <SectionLabel>Agent lane (second opinion)</SectionLabel>
                    <div className="mt-1 flex items-center gap-2">
                      <SeverityBadge severity={analysis.crosscheck.severity?.agent_lane} />
                    </div>
                    <p className="mt-1 text-xs text-faint">
                      {analysis.crosscheck.severity?.basis_agent_lane}
                    </p>
                  </div>
                </div>
                {analysis.crosscheck.partial_independence ? (
                  <p className="mt-3 border-t border-border pt-3 text-xs text-faint">
                    {analysis.crosscheck.partial_independence.note}
                  </p>
                ) : null}
              </>
            ) : (
              <EmptyState
                title="Cross-check not available"
                detail={analysis.crosscheck.reason}
                icon={GitBranch}
              />
            )}
          </CardBody>
        </Card>
      ) : null}

      {/* ATT&CK chain */}
      {incident?.technique_ids?.length ? (
        <Card className="mt-4">
          <CardHeader>
            <CardTitle>ATT&amp;CK chain</CardTitle>
            <CardMeta>
              <Activity className="inline size-3" /> observed order
            </CardMeta>
          </CardHeader>
          <CardBody>
            <RevealList className="flex flex-wrap items-center gap-1.5">
              {incident.technique_ids.map((t) => (
                <span
                  key={t}
                  className="rounded-md border border-border bg-surface-2 px-2 py-1 font-mono text-xs text-text"
                >
                  {t}
                </span>
              ))}
            </RevealList>
          </CardBody>
        </Card>
      ) : null}
    </>
  )
}
