import { Download, Printer } from 'lucide-react'
import { getReport } from '../api.js'
import { useFetch } from '../lib/useFetch.js'
import { Card, CardHeader } from './Card.jsx'

function toMarkdown(r) {
  const L = [
    `# Incident Report: ${r.incident_id}`, '',
    `- Generated: ${r.generated_at}`,
    `- Severity: ${r.severity.toUpperCase()} (max anomaly ${r.max_anomaly_score}/100)`,
    `- Account: ${r.account} · Pivot: ${r.pivot}`, '',
    '## Summary', r.summary, '',
    '## ATT&CK chain',
    ...r.attack_chain.map((t) => `- ${t.tactic} (×${t.count})`),
    '', '## Techniques',
    ...r.techniques.map((t) => `- ${t.technique_id}: ${t.name}`),
    '', `## Attack path`, r.attack_path.join(' -> '),
    '', '## Attribution', `- ${r.attributed_actor.actor}: ${r.attributed_actor.justification}`,
    '', '## Predicted next moves',
    ...r.predicted_next.map((t) => `- ${t.technique_id}: ${t.name}`),
    '', '## Recommended response (simulated, gated)',
    ...r.response_actions.map((a) => `- [${a.mode}] ${a.action}`),
    '', '## Evidence',
    `- Detector: LANL lateral-movement, ROC-AUC ${r.evidence.lanl_roc_auc} (${r.evidence.basis})`,
    `- MTTD: ~${r.mttd.traditional_days} days → ~${r.mttd.ours_minutes} min`,
  ]
  return L.join('\n')
}

export default function IncidentReport() {
  const { data: r, loading } = useFetch(getReport)
  if (loading || !r) return null

  const printReport = () => {
    document.body.classList.add('printing-incident-report')
    const cleanup = () => document.body.classList.remove('printing-incident-report')
    window.addEventListener('afterprint', cleanup, { once: true })
    window.print()
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

  const Section = ({ title, children }) => (
    <div style={{ marginBottom: 14 }}>
      <div style={{ fontSize: 11, letterSpacing: '.5px', textTransform: 'uppercase',
                    color: 'var(--text-faint)', marginBottom: 5 }}>{title}</div>
      {children}
    </div>
  )

  return (
    <Card className="incident-report-card">
      <CardHeader title="Audit-ready incident report" meta={r.generated_at}>
        <button className="btn" onClick={download}
          style={{ display: 'inline-flex', gap: 6, alignItems: 'center' }}>
          <Download size={13} aria-hidden="true" /> Download .md
        </button>
        <button className="btn" onClick={printReport}
          style={{ display: 'inline-flex', gap: 6, alignItems: 'center', marginLeft: 8 }}>
          <Printer size={13} aria-hidden="true" /> Print
        </button>
      </CardHeader>
      <div className="card-b pad incident-report-body" style={{ fontSize: 13, lineHeight: 1.55 }}>
        <Section title="Summary">
          <div style={{ color: 'var(--text)' }}>{r.summary}</div>
        </Section>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 18 }}>
          <Section title="ATT&CK chain">
            {r.attack_chain.map((t) => (
              <div key={t.tactic} className="mono" style={{ color: 'var(--text-dim)' }}>
                {t.tactic} <span className="s-high">×{t.count}</span>
              </div>
            ))}
          </Section>
          <Section title="Attack path">
            <div className="mono s-critical">{r.attack_path.join('  →  ')}</div>
          </Section>
          <Section title="Attributed actor">
            <div><b>{r.attributed_actor.actor}</b></div>
            <div style={{ color: 'var(--text-dim)', fontSize: 12 }}>{r.attributed_actor.justification}</div>
          </Section>
          <Section title="Predicted next moves">
            {r.predicted_next.map((t) => (
              <div key={t.technique_id} className="mono">
                <span className="s-high">{t.technique_id}</span> {t.name}
              </div>
            ))}
          </Section>
        </div>
        <Section title="Recommended response (simulated · gated)">
          {r.response_actions.map((a, i) => (
            <div key={i} style={{ display: 'flex', gap: 10, alignItems: 'baseline', marginBottom: 3 }}>
              <span className="chip" style={{ flex: '0 0 auto' }}>{a.mode}</span>
              <span>{a.action}</span>
            </div>
          ))}
        </Section>
      </div>
    </Card>
  )
}
