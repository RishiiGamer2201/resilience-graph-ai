/**
 * Markdown for advisor replies, configured once and shared.
 *
 * A language model writes `**What is happening**` and `- bullet` whether or not
 * you ask it to. Both the digital-twin advisor and the beginner guide rendered
 * that raw inside `whitespace-pre-wrap`, so asterisks, backticks and hyphens
 * landed on screen as literal characters.
 *
 * WHY A WRAPPER RATHER THAN CALLING ReactMarkdown AT EACH SITE. These two
 * surfaces are the only places in the product that display model-authored text,
 * and the reason they are allowed to exist is that they cannot do anything. The
 * safety properties belong in one file where they can be read and tested, not
 * copy-pasted into two call sites that will drift:
 *
 *   - no `rehype-raw`. react-markdown escapes embedded HTML by default and we
 *     keep it that way, so a model (or text injected into a model's context)
 *     cannot emit a <script>, an <iframe> or an onerror handler;
 *   - links are rendered as plain text, not anchors. A reply is grounded in
 *     incident facts, and a clickable URL a model produced is a phishing
 *     vector pointed at the responder reading it. The URL is still visible;
 *     it just is not a click target;
 *   - images are dropped for the same reason -- an <img src> is an outbound
 *     request to an address the model chose.
 *
 * GFM is on for tables and strikethrough, which models reach for when asked to
 * compare options.
 */
import ReactMarkdown, { type Components } from 'react-markdown'
import remarkGfm from 'remark-gfm'

/** Tailwind-styled elements. `prose` is not available here, so each element
 *  that an advisor reply can actually contain is given explicit spacing. */
const COMPONENTS: Components = {
  p: ({ children }) => <p className="mb-2 last:mb-0">{children}</p>,
  strong: ({ children }) => <strong className="font-semibold text-text">{children}</strong>,
  em: ({ children }) => <em className="italic">{children}</em>,
  ul: ({ children }) => <ul className="mb-2 list-disc space-y-1 pl-4 last:mb-0">{children}</ul>,
  ol: ({ children }) => <ol className="mb-2 list-decimal space-y-1 pl-4 last:mb-0">{children}</ol>,
  li: ({ children }) => <li className="leading-5">{children}</li>,
  code: ({ children }) => (
    <code className="rounded bg-surface px-1 font-mono text-xs">{children}</code>
  ),
  pre: ({ children }) => (
    <pre className="mb-2 overflow-x-auto rounded bg-surface p-2 font-mono text-xs last:mb-0">
      {children}
    </pre>
  ),
  // Headings inside a chat bubble should not shout. A model emitting `##` means
  // "this is a section", not "render this at 2rem".
  h1: ({ children }) => <p className="mb-1 font-semibold text-text">{children}</p>,
  h2: ({ children }) => <p className="mb-1 font-semibold text-text">{children}</p>,
  h3: ({ children }) => <p className="mb-1 font-semibold text-text">{children}</p>,
  h4: ({ children }) => <p className="mb-1 font-semibold text-text">{children}</p>,
  blockquote: ({ children }) => (
    <blockquote className="mb-2 border-l-2 border-border pl-3 text-dim last:mb-0">
      {children}
    </blockquote>
  ),
  hr: () => <hr className="my-2 border-border" />,
  table: ({ children }) => (
    <div className="mb-2 overflow-x-auto last:mb-0">
      <table className="w-full border-collapse text-xs">{children}</table>
    </div>
  ),
  th: ({ children }) => (
    <th className="border border-border px-2 py-1 text-left font-semibold">{children}</th>
  ),
  td: ({ children }) => <td className="border border-border px-2 py-1">{children}</td>,
  // Not anchors, and not images: see the note at the top of this file.
  a: ({ children }) => <span className="underline decoration-dotted">{children}</span>,
  img: () => null,
}

export default function AdvisorMarkdown({ text }: { text: string }) {
  if (!text) return null
  return (
    <ReactMarkdown remarkPlugins={[remarkGfm]} components={COMPONENTS}>
      {String(text)}
    </ReactMarkdown>
  )
}
