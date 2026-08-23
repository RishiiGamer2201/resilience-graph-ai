/**
 * The audit-ready incident report, from `GET /api/report`.
 *
 * Every line is the backend's: the summary is assembled by
 * `src/shared/views.py::report_view`, the attribution justification comes from
 * profile retrieval, the ROC-AUC is read out of `reports/metrics.json`. The
 * component adds no prose of its own.
 *
 * Two honesty affordances survive the port. `predicted_next` carries the
 * `predicted` claim status, because a Markov ranking is not an observation. And
 * every response action keeps its `mode` — nothing here is executed by pressing
 * anything on this screen.
 */
import { Download, FileText, Printer } from 'lucide-react'
import { getReport } from '@/lib/api'
import { useAnalysis, useScreenData } from '@/providers/analysis'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Card, CardBody, CardHeader, CardMeta, CardTitle } from '@/components/ui/card'
import { SkeletonRows } from '@/components/ui/skeleton'
import {
  ClaimStatus,
  EmptyState,
  ErrorState,
  NotMeasured,
  SectionLabel,
} from '@/components/primitives'
import type { IncidentReportData } from '@/types/api'

function toMarkdown(r: IncidentReportData): string {
  return [
    `# Incident report: ${r.incident_id}`,
    '',
    `- Generated: ${r.generated_at}`,
    `- Severity: ${r.severity.toUpperCase()} (max anomaly ${r.max_anomaly_score}/100)`,
    `- Account: ${r.account ?? 'not measured'} · Pivot: ${r.pivot ?? 'not measured'}`,
    '',
    '## Summary',
    r.summary,
    '',
    '## ATT&CK chain (observed order)',
    ...r.attack_chain.map((t) => `- ${t.tactic} (x${t.count})`),
    '',
    '## Techniques',
    ...r.techniques.map((t) => `- ${t.technique_id}: ${t.name}`),
    '',
    '## Attack path',
    r.attack_path.join(' -> '),
    '',
    '## Attribution',
    `- ${r.attributed_actor.actor}: ${r.attributed_actor.justification}`,
    '',
    '## Predicted next moves (predicted, not observed)',
    ...r.predicted_next.map((t) => `- ${t.technique_id}: ${t.name}`),
    '',
    '## Recommended response (simulated, human-gated)',
    ...r.response_actions.map((a) => `- [${a.mode}] ${a.action}`),
    '',
    '## Mitigations',
    ...r.mitigations.map((m) => `- ${m}`),
    '',
    '## Evidence',
    `- Detector: ${r.evidence.detector}, ROC-AUC ${r.evidence.lanl_roc_auc ?? 'not measured'} (${r.evidence.basis}, ${r.evidence.source})`,
    `- MTTD: ${r.mttd.value} — ${r.mttd.note}`,
    `- Comparison: ${r.mttd.citation}`,
  ].join('\n')
}

export default function IncidentReport() {
  const { bundle, source: bundleSource } = useAnalysis()
  const { data: r, error, loading, reload, source } = useScreenData<IncidentReportData>(
    bundle?.report,
    getReport,
    bundleSource,
  )

  if (loading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Audit-ready incident report</CardTitle>
        </CardHeader>
        <CardBody>
          <SkeletonRows rows={5} />
        </CardBody>
      </Card>
    )
  }

  if (error || !r) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Audit-ready incident report</CardTitle>
        </CardHeader>
        <ErrorState error={error ?? new Error('no report')} retry={reload} />
      </Card>
    )
  }

  const download = () => {
    const blob = new Blob([toMarkdown(r)], { type: 'text/markdown' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${r.incident_id}.md`
    a.click()
    URL.revokeObjectURL(url)
  }

  const print = () => {
    const cleanup = () => document.body.classList.remove('printing-incident-report')
    document.body.classList.add('printing-incident-report')
    window.addEventListener('afterprint', cleanup, { once: true })
    window.print()
    window.setTimeout(cleanup, 1000)
  }

  return (
    <Card className="incident-report-print mt-4">
      <CardHeader>
        <CardTitle>Audit-ready incident report</CardTitle>
        <div className="report-print-actions flex items-center gap-2">
          <Badge variant={source === 'live' ? 'accent' : 'outline'}>
            {source === 'live'
              ? 'live analysis'
              : source === 'restored'
                ? 'restored session'
                : 'sample cache'}
          </Badge>
          <CardMeta>{r.generated_at}</CardMeta>
          <Button variant="secondary" size="sm" onClick={download}>
            <Download className="size-3.5" />
            Download .md
          </Button>
          <Button variant="secondary" size="sm" onClick={print}>
            <Printer className="size-3.5" />
            Print
          </Button>
        </div>
      </CardHeader>

      <CardBody className="space-y-4">
        <div>
          <SectionLabel>Summary</SectionLabel>
          <p className="mt-1 text-sm text-text">{r.summary}</p>
        </div>

        <div className="grid gap-x-8 gap-y-4 sm:grid-cols-2">
          <div>
            <SectionLabel>ATT&amp;CK chain · observed order</SectionLabel>
            <div className="mt-1 space-y-0.5">
              {r.attack_chain.length ? (
                r.attack_chain.map((t) => (
                  <div key={t.tactic} className="font-mono text-xs text-dim">
                    {t.tactic} <span className="text-sev-high">×{t.count}</span>
                  </div>
                ))
              ) : (
                <NotMeasured why="No tactic was mapped for this incident." />
              )}
            </div>
          </div>

          <div>
            <SectionLabel>Attack path</SectionLabel>
            <div className="mt-1 font-mono text-xs text-sev-critical">
              {r.attack_path.length ? (
                r.attack_path.join('  →  ')
              ) : (
                <NotMeasured why="No path to a crown jewel was found." />
              )}
            </div>
          </div>

          <div>
            <SectionLabel>Attributed actor</SectionLabel>
            <div className="mt-1 text-sm text-text">{r.attributed_actor.actor}</div>
            <p className="text-xs text-faint">{r.attributed_actor.justification}</p>
          </div>

          <div>
            <SectionLabel>Predicted next moves</SectionLabel>
            <div className="mt-1 space-y-1">
              {r.predicted_next.length ? (
                r.predicted_next.map((t) => (
                  <div key={t.technique_id} className="flex items-center gap-2">
                    <span className="font-mono text-xs text-sev-high">
                      {t.technique_id}
                    </span>
                    <span className="text-xs text-dim">{t.name}</span>
                    <ClaimStatus status="predicted" />
                  </div>
                ))
              ) : (
                <NotMeasured why="The transition model had no observed chain to extend." />
              )}
            </div>
          </div>
        </div>

        <div>
          <SectionLabel>Recommended response · simulated, human-gated</SectionLabel>
          <div className="mt-1 space-y-1">
            {r.response_actions.length ? (
              r.response_actions.map((a, i) => (
                <div key={`${a.action}-${i}`} className="flex items-baseline gap-2">
                  <Badge variant="warn">{a.mode}</Badge>
                  <span className="text-sm text-text">{a.action}</span>
                  {a.tactic ? (
                    <span className="text-xs text-faint">{a.tactic}</span>
                  ) : null}
                </div>
              ))
            ) : (
              <EmptyState
                title="No response proposed"
                detail="The playbook maps actions to observed tactics; none matched."
                icon={FileText}
              />
            )}
          </div>
        </div>

        {r.mitigations.length ? (
          <div>
            <SectionLabel>ATT&amp;CK mitigations</SectionLabel>
            <div className="mt-1 flex flex-wrap gap-1.5">
              {r.mitigations.map((m) => (
                <span
                  key={m}
                  className="rounded-md border border-border bg-surface-2 px-2 py-0.5 text-xs text-dim"
                >
                  {m}
                </span>
              ))}
            </div>
          </div>
        ) : null}

        <div className="border-t border-border pt-3">
          <SectionLabel>Evidence</SectionLabel>
          <p className="mt-1 text-xs text-faint">
            {r.evidence.detector} ·{' '}
            {r.evidence.lanl_roc_auc != null ? (
              <span className="font-mono text-dim">
                ROC-AUC {r.evidence.lanl_roc_auc}
              </span>
            ) : (
              <NotMeasured why="reports/metrics.json has no LANL card." />
            )}{' '}
            · {r.evidence.basis} · {r.evidence.source}
          </p>
          <p className="mt-1 text-xs text-faint">
            Mean time to detect: <span className="font-mono text-dim">{r.mttd.value}</span>{' '}
            — {r.mttd.note} Comparison: {r.mttd.citation}.
          </p>
        </div>
      </CardBody>
    </Card>
  )
}
