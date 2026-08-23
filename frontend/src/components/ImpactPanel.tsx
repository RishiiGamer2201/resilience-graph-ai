/**
 * Impact: what the attacker can still reach, what containment would cost, and
 * which vulnerabilities matter in THIS incident.
 *
 * TwinPanel is a counterfactual containment twin over the attack graph, and it
 * is named that precisely: the backend clones the incident graph, removes a
 * host and recomputes reachability. It reports security benefit AND operational
 * cost, because taking a hospital server off the network is a decision, not a
 * free win. The live graph is never touched.
 *
 * VulnPanel's interesting column is not the score, it is WHY: every factor is
 * shown with the fact behind it, and unknown factors are listed rather than
 * silently scored zero.
 */
import * as React from 'react'
import { ArrowRight, ExternalLink, Scissors, ShieldAlert } from 'lucide-react'
import { Card, CardBody, CardHeader, CardMeta, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Table, TBody, TD, TDMono, TH, THead, TR } from '@/components/ui/table'
import { EmptyState, ErrorState, NotMeasured } from '@/components/primitives'
import { Disclosure, Disclosed, FinePrint } from '@/components/Disclosure'
import { twinSimulate } from '@/lib/api'
import type {
  AttackGraph,
  ContainmentCandidate,
  TwinSimulation,
  VulnFinding,
  VulnReport,
} from '@/types/api'

function Diff({
  label,
  before,
  after,
}: {
  label: string
  before: number
  after: number
}) {
  const changed = before !== after
  const better = after < before
  return (
    <div className="flex items-baseline gap-2 rounded-md border border-border bg-surface-2 px-2.5 py-1.5">
      <span className="flex-1 text-xs text-dim">{label}</span>
      <span className="font-mono text-xs tabular-nums text-faint">{before}</span>
      <ArrowRight className="size-3 text-faint" aria-hidden />
      <span
        className={`font-mono text-sm tabular-nums ${
          changed ? (better ? 'text-ok' : 'text-sev-critical') : 'text-text'
        }`}
      >
        {after}
      </span>
    </div>
  )
}

export function TwinPanel({
  graph,
  counterfactual,
  candidates,
}: {
  graph: AttackGraph
  counterfactual: TwinSimulation | null
  candidates: ContainmentCandidate[]
}) {
  const [sim, setSim] = React.useState<TwinSimulation | null>(counterfactual)
  const [busy, setBusy] = React.useState<string | null>(null)
  const [error, setError] = React.useState<unknown>(null)

  async function run(host: string) {
    setBusy(host)
    setError(null)
    try {
      setSim(await twinSimulate({ graph, isolate_host: host }))
    } catch (e) {
      setError(e)
    } finally {
      setBusy(null)
    }
  }

  const cost = sim?.operational_cost

  return (
    <Card>
      <CardHeader>
        <CardTitle>Counterfactual containment twin</CardTitle>
        <CardMeta>deterministic · simulated</CardMeta>
      </CardHeader>
      <CardBody className="space-y-3">
        <p className="text-xs text-dim">
          Isolate a candidate host on a <span className="font-medium text-text">clone</span> of
          this incident&apos;s attack graph and recompute what the attacker can still reach. The
          live graph is never touched.
        </p>
        <FinePrint>
          Named precisely: this is a counterfactual containment twin over the attack graph, not
          a full cyber-resilience digital twin. A complete twin would also carry synchronised
          asset, identity, dependency and control state, expected behaviour by operating mode,
          and — for OT — validated process models with uncertainty. Those are on the roadmap,
          not on screen.
        </FinePrint>
        {error ? <ErrorState error={error} /> : null}
      </CardBody>

      {candidates.length ? (
        <Table>
          <THead>
            <TR>
              <TH>Isolate</TH>
              <TH>Crown jewels protected</TH>
              <TH className="text-right">Hosts removed from reach</TH>
              <TH className="text-right">Sessions severed</TH>
              <TH className="text-right">Accounts disrupted</TH>
              <TH>
                <span className="sr-only">Simulate</span>
              </TH>
            </TR>
          </THead>
          <TBody>
            {candidates.map((c) => (
              <TR
                key={c.host}
                className={sim?.candidate?.isolate_host === c.host ? 'bg-accent-soft' : undefined}
              >
                <TDMono className="text-text">{c.host}</TDMono>
                <TD className="text-xs">
                  {c.crown_jewels_protected.length ? (
                    <span className="text-ok">{c.crown_jewels_protected.join(', ')}</span>
                  ) : (
                    <span className="text-faint">none</span>
                  )}
                </TD>
                <TDMono className="whitespace-nowrap text-right">
                  {c.blast_radius_reduction} ({c.blast_radius_reduction_pct}%)
                </TDMono>
                <TDMono className="text-right">{c.sessions_severed}</TDMono>
                <TDMono className="text-right">{c.accounts_disrupted}</TDMono>
                <TD>
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={busy === c.host}
                    onClick={() => void run(c.host)}
                  >
                    <Scissors className="size-3" aria-hidden />
                    {busy === c.host ? 'simulating' : 'Simulate'}
                  </Button>
                </TD>
              </TR>
            ))}
          </TBody>
        </Table>
      ) : (
        <EmptyState
          title="No containment candidate in this graph"
          detail="Every host either has no outbound movement or removing it changes nothing reachable."
        />
      )}

      {sim && cost ? (
        <CardBody className="space-y-3 border-t border-border">
          <div className="flex flex-wrap items-center gap-2">
            <ShieldAlert className="size-3.5 text-sev-high" aria-hidden />
            <span className="font-mono text-sm text-text">
              {sim.candidate.isolate_host ?? (sim.candidate.cut_edge ?? []).join(' → ')}
            </span>
            <span className="rounded-full border border-border bg-surface-2 px-2 py-0.5 text-xs text-dim">
              simulated
            </span>
          </div>
          <p className="text-sm text-dim">{sim.verdict}</p>
          <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
            <Diff
              label="Blast radius"
              before={sim.before.blast_radius}
              after={sim.after.blast_radius}
            />
            <Diff
              label="Crown jewels reachable"
              before={sim.before.crown_jewels_reachable.length}
              after={sim.after.crown_jewels_reachable.length}
            />
            <Diff label="Graph nodes" before={sim.before.n_nodes} after={sim.after.n_nodes} />
            <Diff label="Movements" before={sim.before.n_edges} after={sim.after.n_edges} />
          </div>
          <Disclosed>
            <span className="font-medium text-text">Operational cost:</span>{' '}
            {cost.hosts_taken_offline} host offline · {cost.sessions_severed} sessions severed ·{' '}
            {cost.accounts_disrupted.length} account(s) disrupted
            {cost.accounts_disrupted.length ? (
              <span className="font-mono text-faint">
                {' '}
                ({cost.accounts_disrupted.slice(0, 4).join(', ')})
              </span>
            ) : null}
          </Disclosed>
          <FinePrint>
            {sim.method}. {sim.note}
          </FinePrint>
        </CardBody>
      ) : null}
    </Card>
  )
}

// ───────────────────────────────────────────────────────────────────────────
const BAND_CLASS: Record<string, string> = {
  'act now': 'text-sev-critical',
  urgent: 'text-sev-high',
  scheduled: 'text-sev-medium',
  monitor: 'text-sev-normal',
}

function Factors({ finding, weights }: { finding: VulnFinding; weights?: Record<string, number> }) {
  return (
    <div className="space-y-2">
      <ul className="space-y-1">
        {Object.entries(finding.factors).map(([name, fac]) => (
          <li key={name} className="flex flex-wrap items-baseline gap-2 text-xs">
            <span className="w-44 shrink-0 font-mono text-dim">{name.replace(/_/g, ' ')}</span>
            <span className="w-16 shrink-0 font-mono tabular-nums text-text">
              {fac.value === null ? <NotMeasured why="This factor is unknown for this asset. It is excluded from the weighted average and lowers confidence — it is never scored as zero." /> : fac.value}
            </span>
            <span className="min-w-0 flex-1 text-faint">{fac.fact}</span>
          </li>
        ))}
      </ul>
      <FinePrint>
        Unknown factors are excluded from the weighted average and lower confidence — they are
        never scored as zero.
        {weights ? (
          <>
            {' '}
            Weights:{' '}
            <span className="font-mono">
              {Object.entries(weights)
                .map(([k, v]) => `${k} ${v}`)
                .join(' · ')}
            </span>
          </>
        ) : null}
      </FinePrint>
    </div>
  )
}

export function VulnPanel({ vulns }: { vulns: VulnReport | null | undefined }) {
  const findings = vulns?.findings ?? []

  return (
    <Card>
      <CardHeader>
        <CardTitle>Vulnerability priority for this incident</CardTitle>
        <CardMeta>
          {vulns?.config ? `config v${vulns.config.version}` : 'no inventory'}
        </CardMeta>
      </CardHeader>

      {!findings.length ? (
        <EmptyState
          title="No vulnerability findings"
          detail={
            vulns?.inventory_note ??
            vulns?.disclosure ??
            'No asset inventory for this log, so no findings. We never guess what software a host runs.'
          }
        />
      ) : (
        <>
          <CardBody>
            <p className="text-xs text-dim">
              {vulns?.total_findings} finding(s) across {vulns?.assets_considered} inventoried
              assets
              {vulns?.kev_catalog_size
                ? `, matched against ${vulns.kev_catalog_size} CISA Known-Exploited entries`
                : ''}
              . Ranked by asset criticality, known exploitation, reachability in{' '}
              <em>this</em> attack graph, technique overlap, severity and evidence freshness.
            </p>
          </CardBody>
          <Table>
            <THead>
              <TR>
                <TH className="text-right">Priority</TH>
                <TH>CVE</TH>
                <TH>Asset</TH>
                <TH>Owner</TH>
                <TH className="text-right">Confidence</TH>
                <TH>Factors</TH>
              </TR>
            </THead>
            <TBody>
              {findings.map((f) => (
                <TR key={`${f.cve}-${f.host}`}>
                  <TDMono className="whitespace-nowrap text-right">
                    <span className={BAND_CLASS[f.band] ?? 'text-text'}>{f.priority_score}</span>
                    <span className="ml-1 font-sans text-xs text-faint">{f.band}</span>
                  </TDMono>
                  <TDMono>
                    <a
                      href={f.citation.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-accent underline-offset-4 hover:underline"
                    >
                      {f.cve} <ExternalLink className="inline size-2.5" aria-hidden />
                    </a>
                  </TDMono>
                  <TDMono>{f.host}</TDMono>
                  <TD className="text-xs text-dim">{f.owner}</TD>
                  <TDMono
                    className="text-right"
                    title={`unknown: ${f.unknown_factors.join(', ') || 'none'}`}
                  >
                    {Math.round(f.confidence * 100)}%
                  </TDMono>
                  <TD className="max-w-lg">
                    <Disclosure label="show factors" labelOpen="hide factors">
                      <Factors finding={f} weights={vulns?.config?.weights} />
                    </Disclosure>
                  </TD>
                </TR>
              ))}
            </TBody>
          </Table>
          <CardBody className="border-t border-border">
            <FinePrint>
              Inventory provenance:{' '}
              <span className="font-medium text-text">{vulns?.inventory_provenance}</span>.{' '}
              {vulns?.note}
              {vulns?.config ? (
                <>
                  {' '}
                  Config sha256{' '}
                  <span className="font-mono">{vulns.config.sha256.slice(0, 12)}…</span>
                </>
              ) : null}
            </FinePrint>
          </CardBody>
        </>
      )}
    </Card>
  )
}
