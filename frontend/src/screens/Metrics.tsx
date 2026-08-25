/**
 * Models & metrics - the evaluation numbers, exactly as reports/metrics.json
 * has them.
 *
 * Two rules govern this screen:
 *
 *   - Nothing is computed here that the evaluation did not write. The previous
 *     version multiplied a rate by a hardcoded red-team event count to produce
 *     "616/702 events caught"; that constant is not in the payload, so the
 *     sentence is gone and the backend's own note stands in its place.
 *   - No chart without axis labels, units and a caption naming the dataset it
 *     came from. A bar with no y-axis unit is decoration.
 *
 * A metric the evaluation never wrote renders `Not measured`, and a chart with
 * no data renders an empty state rather than an empty axis.
 */
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { Link } from 'react-router-dom'
import { getMetrics } from '@/lib/api'
import { useFetch } from '@/hooks/useFetch'
import { PageHeader } from '@/components/Layout'
import {
  Card,
  CardBody,
  CardFooter,
  CardHeader,
  CardMeta,
  CardTitle,
} from '@/components/ui/card'
import { SkeletonRows } from '@/components/ui/skeleton'
import {
  EmptyState,
  ErrorState,
  MeasuredValue,
  SectionLabel,
  StatRow,
} from '@/components/primitives'
import { EstimatorRanking } from '@/components/EstimatorRanking'
import type { MetricsPayload, PredictorMetrics } from '@/types/api'

interface Bar1 {
  name: string
  value: number
  shipped: boolean
}

const AXIS_TICK = { fill: 'var(--text-dim)', fontSize: 11 }
const AXIS_LABEL = { fill: 'var(--text-faint)', fontSize: 11 }

/** One bar chart, always with both axes labelled and a unit on y. */
function Bars({
  data,
  xLabel,
  yLabel,
  seriesName,
}: {
  data: Bar1[]
  xLabel: string
  yLabel: string
  seriesName: string
}) {
  const max = Math.max(...data.map((d) => d.value))
  return (
    <div className="h-64">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 8, right: 8, left: 4, bottom: 24 }}>
          <CartesianGrid stroke="var(--grid)" vertical={false} />
          <XAxis
            dataKey="name"
            tick={AXIS_TICK}
            axisLine={{ stroke: 'var(--border)' }}
            tickLine={false}
            interval={0}
            label={{ value: xLabel, position: 'insideBottom', offset: -16, ...AXIS_LABEL }}
          />
          <YAxis
            tick={AXIS_TICK}
            axisLine={false}
            tickLine={false}
            domain={[0, Math.ceil(max * 10) / 10]}
            label={{ value: yLabel, angle: -90, position: 'insideLeft', ...AXIS_LABEL }}
          />
          <Tooltip
            cursor={{ fill: 'var(--surface-2)' }}
            contentStyle={{
              background: 'var(--surface)',
              border: '1px solid var(--border)',
              borderRadius: 6,
              color: 'var(--text)',
              fontSize: 12,
            }}
          />
          <Bar dataKey="value" name={seriesName} radius={[4, 4, 0, 0]}>
            {data.map((d) => (
              <Cell key={d.name} fill={d.shipped ? 'var(--accent)' : 'var(--sev-normal)'} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}

/** The predictor methods the evaluation actually wrote, in the order they are
 *  worth reading. A method with no number is absent, not zero. */
function predictorMethods(p: PredictorMetrics): { key: string; label: string; value: number }[] {
  const all: { key: string; label: string; value: number | undefined }[] = [
    { key: 'most_frequent', label: 'Most-frequent', value: p.most_frequent_top3 },
    { key: 'killchain', label: 'Kill-chain baseline', value: p.killchain_top3 },
    { key: 'lstm', label: 'LSTM', value: p.lstm_top3 },
    { key: 'markov', label: 'Markov 1st-order', value: p.markov_top3 },
    { key: 'markov_interp', label: 'Markov interpolated', value: p.markov_interp_top3 },
  ]
  return all.flatMap((m) =>
    typeof m.value === 'number' ? [{ key: m.key, label: m.label, value: m.value }] : [],
  )
}

export default function Metrics() {
  const { data, error, loading, reload } = useFetch<MetricsPayload>(getMetrics)

  const header = (
    <PageHeader
      eyebrow="Model checks"
      title="How well did the models perform?"
      description="Compare model results, baselines, and known limitations."
    />
  )

  if (loading) {
    return (
      <>
        {header}
        <div className="grid gap-4 xl:grid-cols-3">
          {Array.from({ length: 3 }, (_, i) => (
            <Card key={i}>
              <CardBody>
                <SkeletonRows rows={4} />
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
        {header}
        <Card>
          <ErrorState error={error ?? new Error('no data')} retry={reload} />
        </Card>
      </>
    )
  }

  const lanl = data.engine1?.lanl
  const cicids = data.engine1?.cicids
  const unsw = data.engine1?.unsw
  const predictor = data.engine2?.predictor
  const embeddings = data.engine2?.embeddings
  const netstate = data.engine3?.netstate
  const netstateRanking = data.engine3?.comparison

  const methods = predictor ? predictorMethods(predictor) : []
  const shipped = predictor?.shipped
  const shippedLabel = methods.find((m) => m.key === shipped)?.label

  const predBars: Bar1[] = methods.map((m) => ({
    name: m.label,
    value: m.value,
    shipped: m.key === shipped,
  }))

  const cicBars: Bar1[] = (
    [
      ['Autoencoder', cicids?.autoencoder_prauc, true],
      ['Isolation Forest', cicids?.iforest_prauc, false],
      ['Rule baseline', cicids?.rule_prauc, false],
      ['Random', cicids?.random_prauc, false],
    ] as const
  ).flatMap(([name, value, isShipped]) =>
    typeof value === 'number' ? [{ name, value, shipped: isShipped }] : [],
  )

  return (
    <>
      {header}

      <SectionLabel className="mb-2">Engine 1 · Anomaly detection</SectionLabel>
      <div className="grid gap-4 xl:grid-cols-3">
        <Card>
          <CardHeader>
            <CardTitle>LANL · lateral movement</CardTitle>
            <CardMeta>{lanl?.detector ? `${lanl.detector} shipped` : 'the moat'}</CardMeta>
          </CardHeader>
          <CardBody className="space-y-1">
            <StatRow label="ROC-AUC (0–1)">
              <MeasuredValue m={lanl?.roc_auc ?? null} digits={3} />
            </StatRow>
            <StatRow label="TPR at 1% FPR (fraction of red-team events)">
              <MeasuredValue m={lanl?.tpr_at_1pct_fpr ?? null} digits={3} />
            </StatRow>
            <StatRow label="TPR at 5% FPR (fraction)">
              <MeasuredValue m={lanl?.tpr_at_5pct_fpr ?? null} digits={3} />
            </StatRow>
            <StatRow label="ROC-AUC, NTLM feature ablated (0–1)">
              <MeasuredValue m={lanl?.behavioral_only_roc ?? null} digits={3} />
            </StatRow>
            <StatRow label="Isolation Forest TPR at 1% FPR (previous detector)">
              <MeasuredValue m={lanl?.iforest_tpr_at_1pct_fpr ?? null} digits={3} />
            </StatRow>
          </CardBody>
          {lanl?.note ? (
            <CardFooter>
              <span className="text-dim">Real red-team labels. </span>
              {lanl.note}
            </CardFooter>
          ) : null}
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>CIC-IDS2017</CardTitle>
            <CardMeta>benign-only training</CardMeta>
          </CardHeader>
          <CardBody className="space-y-1">
            <StatRow label="Autoencoder PR-AUC (0–1)">
              <MeasuredValue m={cicids?.autoencoder_prauc ?? null} digits={3} />
            </StatRow>
            <StatRow label="Isolation Forest PR-AUC (0–1)">
              <MeasuredValue m={cicids?.iforest_prauc ?? null} digits={3} />
            </StatRow>
            <StatRow label="Isolation Forest ROC-AUC (0–1)">
              <MeasuredValue m={cicids?.iforest_roc ?? null} digits={3} />
            </StatRow>
            <StatRow label="Rule baseline PR-AUC (0–1)">
              <MeasuredValue m={cicids?.rule_prauc ?? null} digits={3} />
            </StatRow>
            <StatRow label="Random PR-AUC (0–1)">
              <MeasuredValue m={cicids?.random_prauc ?? null} digits={3} />
            </StatRow>
          </CardBody>
          {cicids?.note ? (
            <CardFooter>
              <span className="text-dim">Honest baseline. </span>
              {cicids.note}
            </CardFooter>
          ) : null}
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>UNSW-NB15</CardTitle>
            <CardMeta>second benchmark</CardMeta>
          </CardHeader>
          <CardBody className="space-y-1">
            <StatRow label="ROC-AUC (0–1)">
              <MeasuredValue m={unsw?.roc_auc ?? null} digits={3} />
            </StatRow>
            <StatRow label="PR-AUC (0–1)">
              <MeasuredValue m={unsw?.prauc ?? null} digits={3} />
            </StatRow>
          </CardBody>
          {unsw?.note ? (
            <CardFooter>
              <span className="text-dim">Cross-check. </span>
              {unsw.note}
            </CardFooter>
          ) : null}
        </Card>
      </div>

      <Card className="mt-4">
        <CardHeader>
          <CardTitle>CIC-IDS2017 · precision-recall AUC by method</CardTitle>
          <CardMeta>higher is better</CardMeta>
        </CardHeader>
        <CardBody>
          {cicBars.length ? (
            <Bars
              data={cicBars}
              xLabel="Method"
              yLabel="PR-AUC (0–1)"
              seriesName="PR-AUC"
            />
          ) : (
            <EmptyState
              title="No CIC-IDS2017 figures in this payload"
              detail="Run the CIC-IDS evaluation to write engine1.cicids into reports/metrics.json."
            />
          )}
        </CardBody>
        <CardFooter>
          Dataset: CIC-IDS2017 network flows, models trained on benign traffic only.
          Source: /api/metrics · engine1.cicids. Accent bar is the shipped detector.
        </CardFooter>
      </Card>

      <SectionLabel className="mt-6 mb-2">Engine 2 · Prediction &amp; attribution</SectionLabel>
      <div className="grid gap-4 xl:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Next-technique predictor · top-3 accuracy</CardTitle>
            <CardMeta>{shippedLabel ? `${shippedLabel} shipped` : 'method comparison'}</CardMeta>
          </CardHeader>
          <CardBody>
            {predBars.length ? (
              <Bars
                data={predBars}
                xLabel="Method"
                yLabel="Top-3 accuracy (0–1)"
                seriesName="top-3 accuracy"
              />
            ) : (
              <EmptyState
                title="No predictor figures in this payload"
                detail="Run the prediction evaluation to write engine2.predictor into reports/metrics.json."
              />
            )}
          </CardBody>
          <CardFooter>
            Dataset: held-out ATT&amp;CK group and campaign sequences, split at sequence
            level. Source: /api/metrics · engine2.predictor.
            {predictor?.note ? ` Anti-circularity: ${predictor.note}` : ''}
          </CardFooter>
        </Card>

        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Predictor methods</CardTitle>
              <CardMeta>top-3 accuracy, 0–1</CardMeta>
            </CardHeader>
            <CardBody className="space-y-1">
              {methods.length ? (
                [...methods].reverse().map((m) => (
                  <StatRow
                    key={m.key}
                    label={m.key === shipped ? `${m.label} (shipped)` : m.label}
                  >
                    <MeasuredValue m={m.value} digits={3} />
                  </StatRow>
                ))
              ) : (
                <EmptyState title="No predictor methods returned" />
              )}
              <StatRow label="CERT-In analyst-verified orderings (top-3)">
                <MeasuredValue m={data.engine2?.manual_cert_in_top3 ?? null} digits={3} />
              </StatRow>
            </CardBody>
            <CardFooter>
              The CERT-In row is the harder, non-circular test and scores lower. It is
              published for that reason. Source: /api/metrics · engine2.
            </CardFooter>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Technique embeddings · cosine similarity</CardTitle>
              <CardMeta>−1 to 1</CardMeta>
            </CardHeader>
            <CardBody className="space-y-1">
              <StatRow label="Same-tactic pairs (mean cosine)">
                <MeasuredValue m={embeddings?.same_tactic_cos ?? null} digits={3} />
              </StatRow>
              <StatRow label="Random pairs (mean cosine)">
                <MeasuredValue m={embeddings?.random_cos ?? null} digits={3} />
              </StatRow>
            </CardBody>
            <CardFooter>
              Same-tactic techniques cluster above random pairs, so the embedding space
              carries signal. Source: /api/metrics · engine2.embeddings.
            </CardFooter>
          </Card>
        </div>
      </div>

      <SectionLabel className="mt-6 mb-2">Engine 3 &middot; Network world model</SectionLabel>
      <div className="grid gap-4 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader>
            <CardTitle>Next-window state prediction &middot; top-1 accuracy</CardTitle>
            <CardMeta>ranked by the evaluation, not by this screen</CardMeta>
          </CardHeader>
          <CardBody>
            <EstimatorRanking comparison={netstateRanking} />
          </CardBody>
          <CardFooter>
            {netstateRanking?.summary ? (
              <>
                <span className="text-dim">Where we stand. </span>
                {netstateRanking.summary}{' '}
              </>
            ) : null}
            Dataset: CIC-IDS2017 traffic windows, trained on the first three days and
            tested on held-out days. Source: /api/metrics &middot; engine3.
          </CardFooter>
        </Card>

        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Calibration</CardTitle>
              <CardMeta>the task it was built for</CardMeta>
            </CardHeader>
            <CardBody className="space-y-1">
              <StatRow label="Brier score, one step (lower is better)">
                <MeasuredValue m={netstate?.brier_1step ?? null} digits={5} />
              </StatRow>
              <StatRow label="Brier score, baseline (lower is better)">
                <MeasuredValue m={netstate?.brier_1step_baseline ?? null} digits={5} />
              </StatRow>
              <StatRow label="Next-state top-3 accuracy (0–1)">
                <MeasuredValue m={netstate?.next_state_top3 ?? null} digits={4} />
              </StatRow>
              <StatRow label="Window compromise ROC-AUC (0–1)">
                <MeasuredValue m={netstate?.compromise_roc_auc ?? null} digits={4} />
              </StatRow>
              <StatRow label="Window compromise PR-AUC (0–1)">
                <MeasuredValue m={netstate?.compromise_pr_auc ?? null} digits={4} />
              </StatRow>
            </CardBody>
            <CardFooter>
              <span className="text-dim">Deliberately not wired. </span>
              The compromise figures are a property of CIC-IDS2017 labels. This engine
              raises no alert, score or severity anywhere in the product, because its
              usefulness as an alert has not been measured: the same rule that keeps
              bare accuracy off the scoreboard.
            </CardFooter>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Model shape</CardTitle>
              <CardMeta>a quantised state space</CardMeta>
            </CardHeader>
            <CardBody className="space-y-1">
              <StatRow label="Latent states (count)">
                <MeasuredValue m={netstate?.n_states ?? null} digits={0} />
              </StatRow>
              <StatRow label="Window size (flows)">
                <MeasuredValue m={netstate?.window ?? null} digits={0} />
              </StatRow>
              <StatRow label="State vector (dimensions)">
                <MeasuredValue m={netstate?.state_dim ?? null} digits={0} />
              </StatRow>
              <StatRow label="Held-out test windows (count)">
                <MeasuredValue m={netstate?.n_windows_test ?? null} digits={0} />
              </StatRow>
            </CardBody>
            <CardFooter>
              It is quantised rather than a black box so every state can be printed.{' '}
              <Link to="/world-model" className="text-accent underline-offset-4 hover:underline">
                See all states and the transition matrix
              </Link>
              . Source: /api/metrics &middot; engine3.netstate.
            </CardFooter>
          </Card>
        </div>
      </div>

    </>
  )
}
