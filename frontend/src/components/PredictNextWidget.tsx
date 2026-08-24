/** On-demand, LLM-grounded next-technique forecast. */
import * as React from 'react'
import { BrainCircuit, Loader2 } from 'lucide-react'
import { predictNext } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { CardBody } from '@/components/ui/card'
import { ClaimStatus, EmptyState, ErrorState, SectionLabel } from '@/components/primitives'
import type { PredictNextResult } from '@/types/api'
import { techniqueName } from '@/lib/techniques'

export default function PredictNextWidget({ given }: { given: string[] }) {
  const [data, setData] = React.useState<PredictNextResult | null>(null)
  const [error, setError] = React.useState<unknown>(null)
  const [loading, setLoading] = React.useState(false)

  React.useEffect(() => { setData(null); setError(null) }, [given])

  async function runPrediction() {
    if (!given.length || loading) return
    setLoading(true); setError(null); setData(null)
    try { setData(await predictNext(given, 3)) }
    catch (cause: unknown) { setError(cause) }
    finally { setLoading(false) }
  }

  return (
    <CardBody className="space-y-3">
      {!given.length ? (
        <EmptyState title="No observed technique chain"
          detail="This incident has no mapped ATT&CK techniques, so the LLM has no evidence to continue from." />
      ) : (
        <>
          <p className="text-sm leading-relaxed text-dim">
            Ask the configured LLM to forecast the top three next techniques from this
            incident&apos;s observed ATT&amp;CK chain. The model is restricted to bundled ATT&amp;CK
            techniques and documented campaign examples.
          </p>
          <Button type="button" onClick={() => void runPrediction()} disabled={loading}>
            {loading ? <><Loader2 className="size-3.5 animate-spin" /> Generating prediction…</>
              : <><BrainCircuit className="size-3.5" /> Predict next attack</>}
          </Button>
          {error ? <ErrorState error={error} retry={() => void runPrediction()} /> : null}
          {data ? (
            <div className="space-y-3 pt-1">
              <div className="flex flex-wrap items-center gap-2">
                <SectionLabel>Top 3 predicted techniques</SectionLabel>
                <ClaimStatus status="predicted" />
                <span className="font-mono text-xs text-faint">{data.provider} · {data.model}</span>
              </div>
              {data.predictions.map((prediction) => (
                <article key={prediction.technique_id} className="rounded-md border border-border bg-surface-2 p-3">
                  <div className="flex items-baseline gap-2">
                    <span className="font-mono text-xs text-faint">#{prediction.rank}</span>
                    <h3 className="text-sm font-medium text-text">{techniqueName(prediction.technique_id, prediction.name)}</h3>
                    <span className="font-mono text-xs text-faint">{prediction.technique_id}</span>
                  </div>
                  <p className="mt-2 text-sm leading-relaxed text-dim">{prediction.reason}</p>
                  {prediction.previous_attacks?.length ? (
                    <div className="mt-3 space-y-2 border-t border-border pt-2">
                      <div className="text-xs font-medium text-text">Previous documented attack examples</div>
                      {prediction.previous_attacks.map((attack) => (
                        <div key={attack.name}>
                          <div className="text-xs font-medium text-dim">{attack.name}</div>
                          <p className="mt-0.5 text-xs leading-relaxed text-faint">{attack.brief}</p>
                        </div>
                      ))}
                    </div>
                  ) : null}
                </article>
              ))}
              <p className="text-xs text-faint">{data.disclaimer}</p>
            </div>
          ) : null}
        </>
      )}
    </CardBody>
  )
}
