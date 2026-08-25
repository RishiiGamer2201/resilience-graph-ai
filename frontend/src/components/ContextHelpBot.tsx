import { useEffect, useRef, useState } from 'react'
import { Bot, ChevronDown, HelpCircle, Loader2, RotateCcw, Send, Sparkles } from 'lucide-react'
import { useLocation } from 'react-router-dom'
import AdvisorMarkdown from '@/components/AdvisorMarkdown'
import { twinChat } from '@/lib/api'
import { useAnalysis } from '@/providers/analysis'

interface Message {
  id: number
  from: 'bot' | 'user'
  text: string
  model?: string
  error?: boolean
}

interface SelectionPrompt {
  text: string
  nearby: string
  top: number
  left: number
}

const PAGE_TITLES: Record<string, string> = {
  '/': 'Welcome',
  '/investigate': 'Guided investigation',
  '/analyze': 'Analyze a security log',
  '/overview': 'Incident summary',
  '/incident': 'Incident timeline',
  '/graph': '2D attack map',
  '/digital-twin': 'Safe response test',
  '/attackers': 'Compromised accounts',
  '/threat-intel': 'Known threat comparison',
  '/threat-radar': 'External threat reports',
  '/metrics': 'Model performance',
  '/scoreboard': 'Evaluation results',
  '/methodology': 'Data and limitations',
}

const QUICK_QUESTIONS: Record<string, string[]> = {
  '/investigate': ['Where should I start?', 'How strong is the evidence?'],
  '/overview': ['What is the blast radius?', 'What should I check first?'],
  '/incident': ['Explain this timeline', 'What is an anomaly score?'],
  '/graph': ['How do I read this map?', 'What is a crown jewel?'],
  '/digital-twin': ['What does isolation change?', 'Which computer is safest to isolate?'],
  '/attackers': ['What is a compromised account?', 'What is an attacker pivot?'],
  '/threat-intel': ['Is this attribution proof?', 'What is MITRE ATT&CK?'],
  '/metrics': ['Explain these model scores', 'What is a false positive?'],
}

const HELP_SEEN_KEY = 'nextattacks-beginner-guide-seen'
const WELCOME_MESSAGE: Message = {
  id: 1,
  from: 'bot',
  text: 'Ask a question, or select page text and choose Explain.',
}

function selectedText(): { text: string; anchor: Element | null; nearby: string; rect: DOMRect | null } {
  const selection = window.getSelection()
  const text = selection?.toString().trim() ?? ''
  const rect = selection?.rangeCount ? selection.getRangeAt(0).getBoundingClientRect() : null
  const anchor = selection?.anchorNode instanceof Element
    ? selection.anchorNode
    : selection?.anchorNode?.parentElement ?? null
  const contextElement = anchor?.closest('p, li, td, th, button, a, label, h1, h2, h3, [data-help]') ?? anchor
  const nearby = (contextElement?.textContent ?? '').replace(/\s+/g, ' ').trim().slice(0, 1000)
  return { text, anchor, nearby, rect }
}

export default function ContextHelpBot() {
  const { pathname } = useLocation()
  const { bundle } = useAnalysis()
  const title = PAGE_TITLES[pathname] ?? 'Current page'
  const quickQuestions = QUICK_QUESTIONS[pathname] ?? ['What does this page show?', 'What should I do next?']
  const [open, setOpen] = useState(false)
  const [showCoach, setShowCoach] = useState(() => {
    try { return window.localStorage.getItem(HELP_SEEN_KEY) !== 'yes' } catch { return true }
  })
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  const [messages, setMessages] = useState<Message[]>([WELCOME_MESSAGE])
  const [selectionPrompt, setSelectionPrompt] = useState<SelectionPrompt | null>(null)
  const nextId = useRef(2)
  const panelRef = useRef<HTMLDivElement>(null)
  const lastSelection = useRef('')

  const openGuide = () => {
    window.getSelection()?.removeAllRanges()
    lastSelection.current = ''
    setSelectionPrompt(null)
    setOpen(true)
  }

  const acknowledgeCoach = () => {
    setShowCoach(false)
    openGuide()
    try { window.localStorage.setItem(HELP_SEEN_KEY, 'yes') } catch { /* storage can be disabled */ }
  }

  async function ask(text: string, source: 'question' | 'selection' = 'question', nearby = '') {
    const clean = text.trim()
    if (!clean || busy) return

    const userText = source === 'selection' ? `Explain: “${clean}”` : clean
    const history = messages
      .filter((message) => !message.error && message.id !== 1)
      .slice(-6)
      .map((message) => ({ role: message.from === 'bot' ? 'assistant' : 'user', content: message.text }))
    const uiContext = source === 'selection'
      ? `Selected cybersecurity interface text on the “${title}” page. Nearby interface text: “${nearby || clean}”.`
      : `Current cybersecurity application page: “${title}”.`

    setMessages((current) => [...current.slice(-7), { id: nextId.current++, from: 'user', text: userText }])
    setOpen(true)
    setBusy(true)
    try {
      const response = await twinChat({
        message: clean,
        ui_context: uiContext,
        history,
        graph: bundle?.graph,
        scenario: bundle?.meta?.scenario,
        incident_id: bundle?.incident?.incident_id ?? 'INC-LIVE-001',
        require_llm: true,
        assistant_mode: 'general',
      })
      setMessages((current) => [
        ...current,
        {
          id: nextId.current++,
          from: 'bot',
          text: response.reply,
          model: [response.method, response.model].filter(Boolean).join(' · '),
        },
      ])
    } catch (cause: unknown) {
      setMessages((current) => [
        ...current,
        {
          id: nextId.current++,
          from: 'bot',
          text: cause instanceof Error
            ? `The AI advisor could not answer right now: ${cause.message}`
            : 'The AI advisor could not answer right now. Please try again.',
          error: true,
        },
      ])
    } finally {
      setBusy(false)
    }
  }

  const explainPromptedSelection = () => {
    if (!selectionPrompt) return
    const { text, nearby } = selectionPrompt
    setShowCoach(false)
    openGuide()
    try { window.localStorage.setItem(HELP_SEEN_KEY, 'yes') } catch { /* storage can be disabled */ }
    void ask(text, 'selection', nearby)
  }

  useEffect(() => {
    if (open) return

    const offerExplanation = () => {
      const { text, anchor, nearby, rect } = selectedText()
      if (!text || !rect || panelRef.current?.contains(anchor)) {
        setSelectionPrompt(null)
        return
      }

      const promptWidth = 92
      const preferredLeft = rect.right + 8
      const left = preferredLeft + promptWidth <= window.innerWidth - 8
        ? preferredLeft
        : Math.max(8, rect.right - promptWidth)
      const preferredTop = rect.top - 38
      const top = preferredTop >= 8 ? preferredTop : Math.min(rect.bottom + 8, window.innerHeight - 38)
      setSelectionPrompt({ text, nearby, top, left })
    }
    const clearPrompt = () => {
      if (!window.getSelection()?.toString().trim()) setSelectionPrompt(null)
    }
    const dismissPrompt = () => setSelectionPrompt(null)

    document.addEventListener('pointerup', offerExplanation)
    document.addEventListener('selectionchange', clearPrompt)
    window.addEventListener('scroll', dismissPrompt, true)
    window.addEventListener('resize', dismissPrompt)
    return () => {
      document.removeEventListener('pointerup', offerExplanation)
      document.removeEventListener('selectionchange', clearPrompt)
      window.removeEventListener('scroll', dismissPrompt, true)
      window.removeEventListener('resize', dismissPrompt)
    }
  })

  useEffect(() => {
    if (!open) return

    const captureSelection = () => {
      const { text, anchor, nearby } = selectedText()
      if (!text || text === lastSelection.current || panelRef.current?.contains(anchor)) return
      lastSelection.current = text
      void ask(text, 'selection', nearby)
    }
    const clearSelectionMemory = () => {
      if (!window.getSelection()?.toString().trim()) lastSelection.current = ''
    }

    document.addEventListener('pointerup', captureSelection)
    document.addEventListener('selectionchange', clearSelectionMemory)
    return () => {
      document.removeEventListener('pointerup', captureSelection)
      document.removeEventListener('selectionchange', clearSelectionMemory)
    }
  })

  useEffect(() => {
    if (!open) return

    const onContextHelp = (event: Event) => {
      const detail = (event as CustomEvent<string>).detail
      if (detail) void ask(detail, 'selection')
    }
    window.addEventListener('context-help', onContextHelp)
    return () => window.removeEventListener('context-help', onContextHelp)
  })

  return (
    <>
      {selectionPrompt && !open ? (
        <button
          type="button"
          onPointerDown={(event) => event.preventDefault()}
          onClick={explainPromptedSelection}
          style={{ top: selectionPrompt.top, left: selectionPrompt.left }}
          className="fixed z-[90] flex items-center gap-1.5 rounded-full border border-accent/50 bg-accent px-3 py-2 text-xs font-semibold text-accent-fg shadow-xl transition hover:-translate-y-0.5"
          aria-label={`Explain selected text: ${selectionPrompt.text.slice(0, 80)}`}
        >
          <HelpCircle className="size-3.5" /> Explain
        </button>
      ) : null}

      <div ref={panelRef} className="fixed bottom-4 right-4 z-[80] flex max-w-[calc(100vw-2rem)] flex-col items-end sm:bottom-6 sm:right-6">
      {showCoach ? (
        <button type="button" onClick={acknowledgeCoach} className="mb-3 w-72 rounded-xl border border-accent/40 bg-surface p-3 text-left shadow-2xl">
          <span className="flex items-center gap-2 text-sm font-semibold text-text"><Sparkles className="size-4 text-accent" /> Need help?</span>
          <span className="mt-1 block text-xs leading-5 text-dim">Select words and tap Explain, or open this guide to ask questions and explain selections instantly. This tip disappears after you open it once.</span>
        </button>
      ) : null}

      {open ? (
        <section className="mb-3 flex h-[min(34rem,calc(100vh-7rem))] w-[min(24rem,calc(100vw-2rem))] flex-col overflow-hidden rounded-xl border border-border-strong bg-surface shadow-2xl" aria-label="AI beginner guide">
          <header className="flex items-center gap-3 border-b border-border bg-surface-2 px-4 py-3">
            <span className="grid size-9 place-items-center rounded-lg bg-accent-soft text-accent"><Bot className="size-4" /></span>
            <div className="min-w-0 flex-1"><div className="text-sm font-semibold text-text">AI beginner guide</div><div className="truncate text-xs text-faint">{title}</div></div>
            <button type="button" disabled={busy} onClick={() => { setMessages([WELCOME_MESSAGE]); setInput(''); nextId.current = 2 }} title="Start a new chat" aria-label="Start a new chat" className="grid size-8 place-items-center rounded-md text-dim hover:bg-surface-3 disabled:opacity-50"><RotateCcw className="size-4" /></button>
            <button type="button" onClick={() => setOpen(false)} aria-label="Close AI beginner guide" className="grid size-8 place-items-center rounded-md text-dim hover:bg-surface-3"><ChevronDown className="size-4" /></button>
          </header>

          <div className="flex-1 space-y-3 overflow-y-auto p-4" aria-live="polite">
            {messages.map((message) => (
              <div key={message.id} className={message.from === 'user' ? 'ml-auto max-w-[90%]' : 'max-w-[90%]'}>
                <div className={`rounded-lg px-3 py-2 text-sm leading-5 ${message.from === 'user' ? 'bg-accent text-accent-fg' : message.error ? 'border border-sev-high/40 bg-sev-high/10 text-text' : 'bg-surface-2 text-dim'}`}>{message.from === 'user' ? message.text : <AdvisorMarkdown text={message.text} />}</div>
                {message.model ? <div className="mt-1 px-1 font-mono text-[10px] text-faint">AI model · {message.model}</div> : null}
              </div>
            ))}
            {busy ? <div className="flex items-center gap-2 text-xs text-faint"><Loader2 className="size-3.5 animate-spin" /> Asking the AI advisor…</div> : null}
            <div className="flex flex-wrap gap-1.5">
              {quickQuestions.map((question) => <button key={question} type="button" disabled={busy} onClick={() => void ask(question)} className="rounded-full border border-border bg-bg px-2.5 py-1 text-xs text-dim hover:border-accent hover:text-text disabled:opacity-50">{question}</button>)}
            </div>
          </div>

          <form className="flex gap-2 border-t border-border p-3" onSubmit={(event) => { event.preventDefault(); void ask(input); setInput('') }}>
            <input value={input} onChange={(event) => setInput(event.target.value)} disabled={busy} placeholder="Ask what something means…" aria-label="Ask the AI beginner guide" className="min-w-0 flex-1 rounded-md border border-border bg-bg px-3 text-sm text-text outline-none placeholder:text-faint focus:border-accent" />
            <button type="submit" disabled={busy || !input.trim()} aria-label="Send question" className="grid size-9 place-items-center rounded-md bg-accent text-accent-fg disabled:opacity-50"><Send className="size-4" /></button>
          </form>
        </section>
      ) : null}

      <button type="button" onClick={() => { if (showCoach) acknowledgeCoach(); else if (open) setOpen(false); else openGuide() }} className="flex items-center gap-2 rounded-full border border-accent/50 bg-accent px-4 py-3 text-sm font-medium text-accent-fg shadow-xl" aria-label="Open AI beginner guide">
        {open ? <Sparkles className="size-4" /> : <HelpCircle className="size-4" />} Ask what this means
      </button>
      </div>
    </>
  )
}
