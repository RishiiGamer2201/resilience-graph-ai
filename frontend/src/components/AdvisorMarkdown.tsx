/**
 * Lazy boundary around the markdown renderer.
 *
 * `react-markdown` plus `remark-gfm` is ~47 kB gzipped, and the beginner guide
 * that uses it mounts on EVERY page. Importing it directly pushed the entry
 * chunk from 165 kB to 212 kB gzipped for a feature nobody has used until they
 * open a chat panel -- the same mistake main already fixed once, in
 * "fix(ui): 2 MB of lazy libraries were loading on first paint".
 *
 * So the renderer is a separate chunk fetched on first use. Until it arrives
 * the fallback shows the reply as plain pre-wrapped text: the words are all
 * there and readable, only the bold and the bullets are missing for the moment
 * it takes to load. A reply that is briefly unstyled beats an entry chunk that
 * is permanently heavier.
 */
import { Suspense, lazy } from 'react'

const Body = lazy(() => import('@/components/AdvisorMarkdownBody'))

export default function AdvisorMarkdown({ text }: { text: string }) {
  if (!text) return null
  return (
    <Suspense fallback={<span className="whitespace-pre-wrap">{text}</span>}>
      <Body text={text} />
    </Suspense>
  )
}
