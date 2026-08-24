import { useEffect, useState } from 'react'
import { AnimatePresence, motion, useReducedMotion } from 'motion/react'
import { ArrowRight, BrainCircuit, CheckCircle2, LockKeyhole, MailWarning, Network, RefreshCw, ServerCrash, Wrench } from 'lucide-react'

const steps = [
  { phase: '1 · Initial access', title: 'Suspected phishing', detail: 'A deceptive email may have opened the first door.', icon: MailWarning, tone: 'text-sev-high' },
  { phase: '2 · Persistence', title: 'DLL hijack through msdtc.exe', detail: 'Malicious code stayed active by attaching itself to a trusted Windows process.', icon: Wrench, tone: 'text-sev-high' },
  { phase: '3 · Lateral movement', title: 'Weak network separation', detail: 'The attacker could move between systems because internal boundaries were too open.', icon: Network, tone: 'text-sev-critical' },
  { phase: 'Model prediction', title: 'Encryption forecast as imminent', detail: 'The model warned that file encryption was likely to happen next.', icon: BrainCircuit, tone: 'text-accent' },
  { phase: '4 · Confirmed outcome', title: 'CatB ransomware encryption', detail: 'About 100 servers were encrypted and became unavailable.', icon: ServerCrash, tone: 'text-sev-critical' },
  { phase: '5 · Extortion', title: 'About ₹200 crore demanded', detail: 'The attackers demanded payment after disrupting operations.', icon: LockKeyhole, tone: 'text-sev-critical' },
  { phase: 'Recovery', title: 'Manual operations and restoration', detail: 'Teams worked manually while systems were restored over about two weeks.', icon: RefreshCw, tone: 'text-ok' },
]

export default function AttackSimulation() {
  const reduced = useReducedMotion()
  const [active, setActive] = useState(0)

  useEffect(() => {
    if (reduced) return
    const timer = window.setInterval(() => setActive((value) => (value + 1) % steps.length), 2600)
    return () => window.clearInterval(timer)
  }, [reduced])

  const step = steps[active]
  const Icon = step.icon

  return (
    <section className="relative z-10 m-auto w-full max-w-2xl p-6 lg:p-10" aria-label="Animated ransomware attack example">
      <div className="mb-4 flex items-center justify-between">
        <div>
          <div className="font-mono text-[10px] uppercase tracking-[0.16em] text-accent">Example attack simulation</div>
          <h2 className="mt-1 text-lg font-semibold text-text">How one ransomware attack unfolded</h2>
          <p className="mt-1 text-xs leading-5 text-dim">Each box shows one stage, from first access to recovery.</p>
        </div>
        <span className="rounded-full border border-border bg-surface-2 px-2 py-1 font-mono text-xs text-dim">{active + 1} / {steps.length}</span>
      </div>

      <div className="relative min-h-56 overflow-hidden rounded-lg border border-border bg-bg/90 p-5 shadow-2xl">
        <div className="grid-bg absolute inset-0 opacity-40" aria-hidden />
        <AnimatePresence mode="wait">
          <motion.div
            key={step.title}
            initial={reduced ? false : { opacity: 0, scale: 0.94, y: 18 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={reduced ? undefined : { opacity: 0, scale: 0.98, y: -12 }}
            transition={{ duration: 0.35 }}
            className="relative flex min-h-44 flex-col justify-between rounded-lg border border-border-strong bg-surface p-5"
          >
            <div className="flex items-start gap-4">
              <span className={`grid size-11 shrink-0 place-items-center rounded-lg border border-border bg-surface-2 ${step.tone}`}><Icon className="size-5" /></span>
              <div>
                <div className={`font-mono text-[10px] uppercase tracking-[0.14em] ${step.tone}`}>{step.phase}</div>
                <h3 className="mt-2 text-xl font-semibold text-text">{step.title}</h3>
                <p className="mt-2 max-w-lg text-sm leading-6 text-dim">{step.detail}</p>
              </div>
            </div>
            <div className="mt-4 flex items-center gap-2 text-xs text-faint">
              {active === steps.length - 1 ? <CheckCircle2 className="size-3.5 text-ok" /> : <ArrowRight className="size-3.5 text-accent" />}
              {active === steps.length - 1 ? 'Recovery completes the story' : `Next: ${steps[active + 1].title}`}
            </div>
          </motion.div>
        </AnimatePresence>
      </div>

      <div className="mt-4 grid grid-cols-7 gap-1" aria-label="Simulation progress">
        {steps.map((item, index) => (
          <button key={item.title} type="button" onClick={() => setActive(index)} aria-label={`Show ${item.title}`} className={`h-1.5 rounded-full transition-colors ${index === active ? 'bg-accent' : index < active ? 'bg-accent/40' : 'bg-border-strong'}`} />
        ))}
      </div>
    </section>
  )
}
