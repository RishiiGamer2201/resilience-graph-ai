/**
 * Attackers — the "who" table for the campaign.
 *
 * GET /api/attackers is the roster: every account the red team used, each
 * scored from its own alerts out of the same log. Opening one runs the live
 * pipeline again scoped to that account (POST /api/analyze).
 *
 * The old screen published the result to the analysis store and navigated
 * straight to /incident. It still publishes — every other screen reads that
 * store — but the jump is now an explicit link, and the run is summarised here
 * next to the row that produced it. An automatic redirect meant that if the
 * destination fell back to the cached campaign you would be looking at a
 * different incident under this account's name, and never know.
 */
import { useMemo, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { ArrowRight, Crosshair, Loader2, Search, Users } from 'lucide-react'
import { analyze, getAttackers, getIncident } from '@/lib/api'
import { useFetch } from '@/hooks/useFetch'
import { useAnalysis } from '@/providers/analysis'
import { PageHeader } from '@/components/Layout'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardBody, CardFooter, CardHeader, CardMeta, CardTitle } from '@/components/ui/card'
import { SkeletonRows } from '@/components/ui/skeleton'
import { Table, TBody, TD, TDMono, TH, THead, TR } from '@/components/ui/table'
import {
  EmptyState,
  ErrorState,
  MetricCard,
  NotMeasured,
  Reveal,
  SectionLabel,
  SeverityBadge,
  StatRow,
} from '@/components/primitives'
import { fmtTime } from '@/lib/format'
import { cn } from '@/lib/utils'
import type { AnalysisBundle, Incident } from '@/types/api'

/** What the pipeline returned for one account, just now. */
function AnalysedAccount({ user, bundle, scenario }: { user: string; bundle: AnalysisBundle; scenario: string }) {
  const inc = bundle.incident
  const graph = bundle.graph
  return (
    <Reveal className="mb-4">
      <Card>
        <CardHeader>
          <CardTitle>
            Live analysis · <span className="font-mono">{user}</span>
          </CardTitle>
          <div className="flex items-center gap-3">
            <CardMeta>POST /analyze · scenario {scenario}</CardMeta>
            <Button asChild size="sm" variant="secondary">
              <Link to="/incident">
                Open in Live Incident
                <ArrowRight className="size-3" aria-hidden />
              </Link>
            </Button>
          </div>
        </CardHeader>
        <CardBody className="grid gap-4 md:grid-cols-3">
          <div className="space-y-1 md:col-span-2">
            <StatRow label="Incident">{inc?.incident_id ?? <NotMeasured />}</StatRow>
            <StatRow label="Severity">
              <SeverityBadge severity={inc?.severity} />
            </StatRow>
            <StatRow label="Alerts correlated">
              {inc ? `${inc.alert_count} of ${inc.event_count} events` : <NotMeasured />}
            </StatRow>
            <StatRow label="Entry host">
              {graph?.entry_host ?? (
                <NotMeasured why="No entry point could be identified for this account." />
              )}
            </StatRow>
            <StatRow label="Recommended isolation">
              {graph?.recommended_isolation ?? (
                <NotMeasured why="No single host removal improved containment." />
              )}
            </StatRow>
            <StatRow label="Blast radius">
              {graph?.blast_radius_size != null ? (
                `${graph.blast_radius_size.toLocaleString()} hosts reachable`
              ) : (
                <NotMeasured />
              )}
            </StatRow>
            <StatRow label="Crown jewels reachable">
              {graph?.critical_assets_at_risk?.length ? (
                graph.critical_assets_at_risk.join(', ')
              ) : (
                <span className="text-faint">none marked reachable</span>
              )}
            </StatRow>
          </div>
          <div>
            <SectionLabel>ATT&amp;CK chain</SectionLabel>
            {inc?.technique_ids?.length ? (
              <div className="mt-1.5 flex flex-wrap gap-1">
                {inc.technique_ids.map((t) => (
                  <span
                    key={t}
                    className="rounded-md border border-border bg-surface-2 px-1.5 py-0.5 font-mono text-xs text-text"
                  >
                    {t}
                  </span>
                ))}
              </div>
            ) : (
              <div className="mt-1.5 text-xs text-faint">
                No technique mapped for this account.
              </div>
            )}
          </div>
        </CardBody>
        <CardFooter>
          This run is now the console&apos;s live bundle, so the other screens show it
          instead of the cached sample. Crown jewels are the backend&apos;s derived
          default for this scenario, and
          behavioural features were computed against the whole log — so this
          account&apos;s baseline reflects everything that happened, not just its
          own slice.
        </CardFooter>
      </Card>
    </Reveal>
  )
}

export default function Attackers() {
  const navigate = useNavigate()
  // The roster is always the campaign's accounts, from the cached view.
  const { data: roster, error, loading, reload } = useFetch(getAttackers)
  // Only to mark which row the currently loaded incident belongs to. A failure
  // here costs a highlight, not the screen.
  const { data: incident } = useFetch<Incident>(getIncident)
  // Publishing the run is what lets the rest of the console render it.
  const { bundle: liveBundle, setBundle } = useAnalysis()
  // This route is the fixed campaign roster. A live bundle from another
  // scenario must not replace it while row actions still analyse LANL.
  const data = roster?.attackers ?? null

  const [q, setQ] = useState('')
  const [busy, setBusy] = useState<string | null>(null)
  const [runError, setRunError] = useState<unknown>(null)
  const [analysed, setAnalysed] = useState<{ user: string; bundle: AnalysisBundle } | null>(
    null,
  )

  const list = useMemo(() => data ?? [], [data])
  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase()
    if (!needle) return list
    return list.filter(
      (a) =>
        a.user.toLowerCase().includes(needle) ||
        a.pivots.some((p) => p.toLowerCase().includes(needle)) ||
        a.techniques.some((t) => t.toLowerCase().includes(needle)),
    )
  }, [list, q])

  async function openAccount(user: string) {
    setBusy(user)
    setRunError(null)
    try {
      // Crown jewels are left to the backend default, which derives them.
      if (!roster?.scenario) throw new Error('The attacker roster did not identify its source scenario.')
      const bundle = await analyze({ scenario: roster.scenario, account: user })
      setBundle(bundle)
      setAnalysed({ user, bundle })
      navigate('/incident')
    } catch (e: unknown) {
      setRunError(e)
    } finally {
      setBusy(null)
    }
  }

  if (loading) {
    return (
      <>
        <PageHeader eyebrow="Campaign" title="Attackers" />
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {Array.from({ length: 4 }, (_, i) => (
            <Card key={i}>
              <CardBody>
                <SkeletonRows rows={2} />
              </CardBody>
            </Card>
          ))}
        </div>
        <Card className="mt-4">
          <CardBody>
            <SkeletonRows rows={8} />
          </CardBody>
        </Card>
      </>
    )
  }

  if (error || !data) {
    return (
      <>
        <PageHeader eyebrow="Campaign" title="Attackers" />
        <Card>
          <ErrorState error={error ?? new Error('no data')} retry={reload} />
        </Card>
      </>
    )
  }

  const totals = list.reduce(
    (acc, a) => ({ alerts: acc.alerts + a.alerts, hosts: acc.hosts + a.hosts_reached }),
    { alerts: 0, hosts: 0 },
  )
  const pivots = [...new Set(list.flatMap((a) => a.pivots))]
  const withCritical = list.filter((a) => a.critical_reached.length > 0)

  return (
    <>
      <PageHeader
        eyebrow="Campaign"
        title="Compromised accounts"
        description="Every account the red team used, scored from the same log. Open one to analyse it as its own incident."
        actions={
          <>
            <Badge variant="outline">campaign roster Â· sample cache</Badge>
            <Badge variant="outline">
              <Users className="size-3" aria-hidden /> {list.length} accounts
            </Badge>
          </>
        }
      />

      <Reveal>
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <MetricCard
            label="Compromised accounts"
            value={list.length.toLocaleString()}
            context="all carved from one campaign log"
          />
          <MetricCard
            label="Attacker pivots"
            value={pivots.length.toLocaleString()}
            context={pivots.length ? pivots.join(' · ') : undefined}
            severity={pivots.length ? 'critical' : undefined}
          />
          <MetricCard
            label="Correlated alerts"
            value={totals.alerts.toLocaleString()}
            context={`${totals.hosts.toLocaleString()} host arrivals across every account`}
          />
          <MetricCard
            label="Reached a crown jewel"
            value={withCritical.length.toLocaleString()}
            context={
              withCritical.length
                ? withCritical.map((a) => a.user).join(', ')
                : 'no account reached a designated crown jewel'
            }
          />
        </div>
      </Reveal>

      {runError ? (
        <Card className="mt-4">
          <ErrorState error={runError} />
        </Card>
      ) : null}

      <div className="mt-4">
        {analysed && roster?.scenario ? (
          <AnalysedAccount user={analysed.user} bundle={analysed.bundle} scenario={roster.scenario} />
        ) : null}

        <Card>
          <CardHeader>
            <CardTitle>Accounts used in this campaign</CardTitle>
            <div className="flex items-center gap-3">
              <CardMeta>
                {rows.length}/{list.length} shown
              </CardMeta>
              <span className="flex items-center gap-1.5">
                <Search className="size-3 text-faint" aria-hidden />
                <input
                  value={q}
                  onChange={(e) => setQ(e.target.value)}
                  placeholder="filter account / pivot / technique"
                  aria-label="Filter accounts by account, pivot or technique"
                  className="h-7 w-56 rounded-md border border-border bg-surface-2 px-2 text-xs text-text placeholder:text-faint"
                />
              </span>
            </div>
          </CardHeader>

          {rows.length ? (
            <div className="max-h-[620px] overflow-y-auto">
              <Table>
                <THead className="sticky top-0 z-10">
                  <TR>
                    <TH>Account</TH>
                    <TH>Severity</TH>
                    <TH className="text-right">Alerts</TH>
                    <TH className="text-right">Hosts</TH>
                    <TH className="text-right">Max score</TH>
                    <TH>Pivot</TH>
                    <TH>Techniques</TH>
                    <TH>First seen</TH>
                    <TH className="text-right">Analyse</TH>
                  </TR>
                </THead>
                <TBody>
                  {rows.map((a) => (
                    <TR
                      key={a.user}
                      className={cn(
                        (liveBundle?.incident?.account ?? incident?.account) === a.user && 'bg-surface-2',
                        analysed?.user === a.user && 'bg-accent-soft',
                      )}
                    >
                      <TDMono className="font-medium text-text">{a.user}</TDMono>
                      <TD>
                        <SeverityBadge severity={a.severity} />
                      </TD>
                      <TDMono className="text-right">{a.alerts.toLocaleString()}</TDMono>
                      <TDMono className="text-right">
                        {a.hosts_reached.toLocaleString()}
                      </TDMono>
                      <TDMono className="text-right">{a.max_score}</TDMono>
                      <TDMono className="text-dim">{a.pivots.join(' · ')}</TDMono>
                      <TDMono className="text-dim">{a.techniques.join(' ')}</TDMono>
                      <TDMono className="text-dim">{fmtTime(a.first_seen)}</TDMono>
                      <TD className="text-right">
                        <div className="flex items-center justify-end gap-2">
                          {a.critical_reached.length ? (
                            <Badge
                              variant="critical"
                              title={`reached ${a.critical_reached.join(', ')}`}
                            >
                              crown jewel
                            </Badge>
                          ) : null}
                          <Button
                            size="sm"
                            variant="secondary"
                            disabled={busy === a.user}
                            onClick={() => openAccount(a.user)}
                          >
                            {busy === a.user ? (
                              <>
                                <Loader2 className="size-3 animate-spin" aria-hidden />
                                Analysing
                              </>
                            ) : (
                              <>
                                <Crosshair className="size-3" aria-hidden />
                                Analyse
                              </>
                            )}
                          </Button>
                        </div>
                      </TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
            </div>
          ) : (
            <EmptyState
              title="No account matches this filter"
              detail={`${list.length} accounts are in the roster. Clear the filter to see them.`}
              icon={Search}
            />
          )}

          <CardFooter>
            Each account is analysed by the same live pipeline, scoped to its own
            events — behavioural features are computed against the whole log first,
            so an account&apos;s baseline reflects everything that happened, not just
            its own slice.
          </CardFooter>
        </Card>
      </div>
    </>
  )
}
