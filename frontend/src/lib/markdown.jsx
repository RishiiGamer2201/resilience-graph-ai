/* A very small markdown renderer, for one job: advisor replies.
 *
 * A language model writes `**What is happening**` whether or not you ask it to,
 * and rendering that raw put literal asterisks on screen. The fix is either to
 * forbid markdown in the prompt -- which models ignore -- or to render the three
 * constructs they actually use. This does the second.
 *
 * Deliberately NOT a markdown library. The advisor is the one surface that shows
 * model-authored text, and the whole reason it is allowed to exist is that it
 * cannot do anything: no links, no images, no HTML, no script. A renderer that
 * only knows bold, bullets and paragraphs cannot be talked into more than that
 * by the text it is rendering, which a general parser plus `dangerouslySetInnerHTML`
 * absolutely can. It returns React elements, never HTML strings.
 *
 * Handles: **bold**, `code`, - bullets, and blank-line paragraphs. Everything
 * else renders as its own literal text, which is the safe failure.
 */

/** Split one line into plain text, <strong> and <code> runs. */
function inline(line, keyPrefix) {
  const out = []
  // one pass, alternating on the two delimiters we support
  const re = /(\*\*[^*]+\*\*|`[^`]+`)/g
  let last = 0
  let m
  let i = 0
  while ((m = re.exec(line)) !== null) {
    if (m.index > last) out.push(line.slice(last, m.index))
    const tok = m[0]
    if (tok.startsWith('**')) {
      out.push(<strong key={`${keyPrefix}-b${i}`}>{tok.slice(2, -2)}</strong>)
    } else {
      out.push(<code key={`${keyPrefix}-c${i}`}>{tok.slice(1, -1)}</code>)
    }
    last = m.index + tok.length
    i += 1
  }
  if (last < line.length) out.push(line.slice(last))
  return out.length ? out : [line]
}

/**
 * Render advisor markdown as React elements.
 * @param {string} text
 */
export default function Markdown({ text }) {
  if (!text) return null
  const blocks = String(text).split(/\n{2,}/)
  return (
    <>
      {blocks.map((block, bi) => {
        const lines = block.split('\n').filter((l) => l.trim() !== '')
        const bullets = lines.filter((l) => /^\s*[-*]\s+/.test(l))
        // a block is a list only if every line in it is a bullet, so a paragraph
        // that happens to contain a dash is not silently turned into one
        if (bullets.length && bullets.length === lines.length) {
          return (
            <ul key={bi} style={{ margin: '0 0 8px', paddingLeft: 18 }}>
              {lines.map((l, li) => (
                <li key={li} style={{ marginBottom: 3 }}>
                  {inline(l.replace(/^\s*[-*]\s+/, ''), `${bi}-${li}`)}
                </li>
              ))}
            </ul>
          )
        }
        return (
          <p key={bi} style={{ margin: '0 0 8px' }}>
            {lines.map((l, li) => (
              <span key={li}>
                {inline(l, `${bi}-${li}`)}
                {li < lines.length - 1 ? <br /> : null}
              </span>
            ))}
          </p>
        )
      })}
    </>
  )
}
