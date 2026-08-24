import { CheckCircle2 } from 'lucide-react'
import { getMethodology } from '../api.js'
import { useFetch } from '../lib/useFetch.js'
import { Card, CardHeader, Loading, ErrorBox } from '../components/Card.jsx'
import Answer from '../components/Answer.jsx'

export default function Methodology() {
  const { data, error, loading } = useFetch(getMethodology)
  if (loading) return <Loading />
  if (error) return <ErrorBox error={error} />

  const { datasets, honesty_notes } = data

  return (
    <>
      <Answer headline="Where the numbers came from.">
        Every accuracy figure in this product was measured on one of the logs below,
        not on the log you are looking at. Two of them are real: the LANL
        authentication set carries labelled red-team activity, which is what makes
        it possible to say how much the detector actually caught rather than how
        much it flagged.
      </Answer>

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
        Every metric is reported the way the data allows: <b>PR-AUC / TPR@FPR</b> for unsupervised
        detectors, honest baselines, and unverified manual mappings clearly flagged.
      </div>
    </>
  )
}
