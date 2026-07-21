import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, CartesianGrid } from 'recharts'
import { getMetrics } from '../api.js'
import { useFetch } from '../lib/useFetch.js'
import { Card, CardHeader, Loading, ErrorBox } from '../components/Card.jsx'

function MetricTable({ rows }) {
  return (
    <table className="mtable">
      <thead><tr><th>Metric</th><th style={{ textAlign: 'right' }}>Value</th></tr></thead>
      <tbody>
        {rows.map((r) => (
          <tr key={r.label}>
            <td>{r.label}</td>
            <td className={`num${r.hl ? ' hl' : ''}`}>{r.value}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

export default function Metrics() {
  const { data, error, loading } = useFetch(getMetrics)
  if (loading) return <Loading />
  if (error) return <ErrorBox error={error} />

  const { engine1, engine2 } = data
  const { cicids, lanl, unsw } = engine1
  const { predictor, embeddings } = engine2

  // Driven off metrics.json so a model promotion can't leave this screen stale:
  // `shipped` names the winning method, and rows appear only if the eval wrote them.
  const shipped = predictor.shipped || 'markov'
  const METHODS = [
    { key: 'most_frequent', name: 'most_frequent', label: 'Most-frequent', v: predictor.most_frequent_top3 },
    { key: 'killchain', name: 'kill-chain', label: 'Kill-chain baseline', v: predictor.killchain_top3 },
    { key: 'lstm', name: 'LSTM', label: 'LSTM', v: predictor.lstm_top3 },
    { key: 'markov', name: 'Markov 1st', label: 'Markov 1st-order', v: predictor.markov_top3 },
    { key: 'markov_interp', name: 'Markov interp', label: 'Markov interpolated', v: predictor.markov_interp_top3 },
  ].filter((m) => typeof m.v === 'number')
  const predData = METHODS.map((m) => ({ ...m, shipped: m.key === shipped }))
  const maxPred = Math.max(...predData.map((d) => d.v))
  const shippedLabel = (METHODS.find((m) => m.key === shipped) || {}).label || 'Markov'

  return (
    <>
      <div className="section-label">Engine 1 · Anomaly detection</div>
      <div className="grid2" style={{ gridTemplateColumns: '1fr 1fr 1fr' }}>
        <Card>
          <CardHeader title="LANL · lateral movement" meta="the moat" />
          <div className="card-b pad">
            <MetricTable rows={[
              { label: 'ROC-AUC', value: lanl.roc_auc, hl: true },
              { label: 'TPR @ 1% FPR', value: lanl.tpr_at_1pct_fpr },
              { label: 'TPR @ 5% FPR', value: lanl.tpr_at_5pct_fpr },
              { label: 'Behavioral-only ROC', value: lanl.behavioral_only_roc },
            ]} />
          </div>
          <div className="note"><b>Real red-team labels.</b> {lanl.note}</div>
        </Card>

        <Card>
          <CardHeader title="CIC-IDS2017" meta="benign-only" />
          <div className="card-b pad">
            <MetricTable rows={[
              { label: 'Autoencoder PR-AUC', value: cicids.autoencoder_prauc, hl: true },
              { label: 'Isolation-Forest PR-AUC', value: cicids.iforest_prauc },
              { label: 'Isolation-Forest ROC', value: cicids.iforest_roc },
              { label: 'Rule baseline PR-AUC', value: cicids.rule_prauc },
              { label: 'Random PR-AUC', value: cicids.random_prauc },
            ]} />
          </div>
          <div className="note"><b>Honest baseline.</b> {cicids.note}</div>
        </Card>

        <Card>
          <CardHeader title="UNSW-NB15" meta="2nd benchmark" />
          <div className="card-b pad">
            <MetricTable rows={[
              { label: 'ROC-AUC', value: unsw.roc_auc, hl: true },
              { label: 'PR-AUC', value: unsw.prauc },
            ]} />
          </div>
          <div className="note"><b>Cross-check.</b> {unsw.note}</div>
        </Card>
      </div>

      <div className="section-label">Engine 2 · Prediction &amp; attribution</div>
      <div className="grid2">
        <Card>
          <CardHeader title="Next-technique predictor · top-3 accuracy" meta={`${shippedLabel} shipped`} />
          <div className="card-b pad" style={{ height: 260 }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={predData} margin={{ top: 8, right: 8, left: -12, bottom: 4 }}>
                <CartesianGrid stroke="var(--grid)" vertical={false} />
                <XAxis dataKey="name" tick={{ fill: 'var(--text-dim)', fontSize: 12 }} axisLine={{ stroke: 'var(--border)' }} tickLine={false} />
                <YAxis tick={{ fill: 'var(--text-faint)', fontSize: 11 }} axisLine={false} tickLine={false} domain={[0, Math.ceil(maxPred * 10) / 10]} />
                <Tooltip
                  cursor={{ fill: 'var(--surface-2)' }}
                  contentStyle={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, color: 'var(--text)', fontSize: 12 }}
                  formatter={(v) => [v, 'top-3']} />
                <Bar dataKey="v" radius={[5, 5, 0, 0]}>
                  {predData.map((d) => (
                    <Cell key={d.name} fill={d.shipped ? 'var(--accent)' : 'var(--sev-normal)'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
          <div className="note"><b>Anti-circularity.</b> {predictor.note}</div>
        </Card>

        <div className="stack">
          <Card>
            <CardHeader title="Predictor methods" />
            <div className="card-b pad">
              <MetricTable rows={[
                ...[...METHODS].reverse().map((m) => ({
                  label: m.key === shipped ? `${m.label} (shipped)` : m.label,
                  value: m.v,
                  hl: m.key === shipped,
                })),
                { label: 'CERT-In manual (top-3)', value: engine2.manual_cert_in_top3 },
              ]} />
            </div>
          </Card>

          <Card>
            <CardHeader title="Technique embeddings · cosine" />
            <div className="card-b pad">
              <MetricTable rows={[
                { label: 'Same-tactic similarity', value: embeddings.same_tactic_cos, hl: true },
                { label: 'Random pair similarity', value: embeddings.random_cos },
              ]} />
            </div>
            <div className="note">Same-tactic techniques cluster above random, so the embedding space is meaningful.</div>
          </Card>
        </div>
      </div>
    </>
  )
}
