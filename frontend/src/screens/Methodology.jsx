import { CheckCircle2 } from 'lucide-react'
import { getMethodology } from '../api.js'
import { useFetch } from '../lib/useFetch.js'
import { Card, CardHeader, Loading, ErrorBox } from '../components/Card.jsx'

export default function Methodology() {
  const { data, error, loading } = useFetch(getMethodology)
  if (loading) return <Loading />
  if (error) return <ErrorBox error={error} />

  const { datasets, honesty_notes } = data

  return (
    <>
      <div className="section-label">Datasets</div>
      <div className="ds-grid">
        {datasets.map((d) => (
          <div className="ds" key={d.name}>
            <div className="dn">{d.name}</div>
            <div className="dr">{d.rows}</div>
            <div className="df">feeds: {d.feeds}</div>
          </div>
        ))}
      </div>

      <Card>
        <CardHeader title="Our rigor" meta={`${honesty_notes.length} honesty notes`} />
        <ul className="honesty">
          {honesty_notes.map((n, i) => (
            <li key={i}>
              <CheckCircle2 size={16} className="ck" aria-hidden="true" />
              <span>{n}</span>
            </li>
          ))}
        </ul>
      </Card>

      <div className="foot">
        Every metric is reported the way the data allows — <b>PR-AUC / TPR@FPR</b> for unsupervised
        detectors, honest baselines, and unverified manual mappings clearly flagged.
      </div>
    </>
  )
}
