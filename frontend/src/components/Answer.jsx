import { useState } from 'react'
import { ChevronDown, ChevronRight } from 'lucide-react'
import { Link } from 'react-router-dom'

/* The two pieces that turn a wall into a page.
 *
 * Every screen in this product used to open with its densest artifact: Overview
 * with four metric tiles and eight equal-weight cards over 3,074 pixels, the
 * incident screen with 4,650 words. Everything was expanded, nothing was
 * ranked, and there was no sentence anywhere saying what the screen had
 * concluded. A reader who already knew the domain could assemble the answer
 * from the parts. Nobody else could find it.
 *
 * <Answer> is the conclusion, in one sentence, before any evidence for it.
 * <Reveal> is everything that supports the conclusion, closed until asked for.
 *
 * The rule they enforce together: a screen states its finding, then offers the
 * working. Not the other way round, and never both at once.
 */

/**
 * The lead: what this screen concluded, in plain words.
 *
 * @param {string}  headline  one sentence. Not a label, not a metric.
 * @param {node}    children  optional second sentence of context
 * @param {Array}   facts     [{k, v, hint}] at most three, the numbers that matter
 * @param {object}  next      {to, label} the step a reader should take from here
 * @param {string}  tone      'critical' | 'high' | 'ok' | undefined
 */
export default function Answer({ headline, children, facts = [], next, tone }) {
  return (
    <section className={`answer${tone ? ` t-${tone}` : ''}`}>
      <p className="answer-head">{headline}</p>
      {children && <div className="answer-body">{children}</div>}
      {facts.length > 0 && (
        <div className="answer-facts">
          {facts.slice(0, 3).map((f) => (
            <div className="answer-fact" key={f.k}>
              <span className="answer-v">{f.v}</span>
              <span className="answer-k">{f.k}</span>
              {f.hint && <span className="answer-hint">{f.hint}</span>}
            </div>
          ))}
        </div>
      )}
      {next && (
        <Link className="answer-next" to={next.to}>
          {next.label}
          <ChevronRight size={14} aria-hidden="true" />
        </Link>
      )}
    </section>
  )
}

/**
 * A section that is closed until someone wants it.
 *
 * The summary line is always visible and must say what is inside in plain
 * words, because a row of chevrons labelled "Detector benchmarks" and
 * "Independent cross-check" is a filing cabinet, not a page. A reader decides
 * whether to open something from the summary, so the summary carries the fact
 * and the panel carries the proof.
 *
 * @param {string}  title    what this is
 * @param {string}  summary  what it says, in one line, without opening it
 * @param {boolean} open     start open. Use sparingly; the default is closed.
 */
export function Reveal({ title, summary, open = false, children }) {
  const [on, setOn] = useState(open)
  return (
    <section className={`reveal${on ? ' on' : ''}`}>
      {/* The chevron is on the trailing edge, not the leading one. Two reasons:
          the title is content and the chevron is a control, and a leading
          chevron pushed every Reveal title 18px right of the Answer's text
          above it -- two competing left edges down the page, which is the
          thing a reader feels as unresolved without being able to name. */}
      <button className="reveal-h" onClick={() => setOn((o) => !o)} aria-expanded={on}>
        <span className="reveal-t">{title}</span>
        {summary && <span className="reveal-s">{summary}</span>}
        {on
          ? <ChevronDown size={15} aria-hidden="true" />
          : <ChevronRight size={15} aria-hidden="true" />}
      </button>
      {on && <div className="reveal-b">{children}</div>}
    </section>
  )
}
