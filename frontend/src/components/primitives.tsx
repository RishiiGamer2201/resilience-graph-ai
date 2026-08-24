/**
 * Domain primitives. These are not styling helpers - several of them ARE the
 * product's honesty guarantees, expressed as components so a screen cannot
 * quietly drop one.
 *
 * `NotMeasured` renders the words, never a zero. `ClaimStatus` makes an inferred
 * finding look different from an observed one. `ProvenanceLine` keeps "a model
 * wrote this" on screen. See frontend/DESIGN.md section 5.
 */
import * as React from 'react'
import { AlertTriangle, HelpCircle, Info, Minus } from 'lucide-react'
import { motion, useReducedMotion, type Variants } from 'motion/react'
import { cn } from '@/lib/utils'
import { EASE, fadeUp, STAGGER, STAGGER_MAX } from '@/lib/motion'
import { InfoTip } from '@/components/ui/tooltip'
import type { ClaimStatusValue, Measured, Severity } from '@/types/api'

// ─── Section label ───────────────────────────────────────────────────────────
/** Uppercase 11px eyebrow. Carries much of the console character. */
export const SectionLabel = ({
  className,
  ...props
}: React.HTMLAttributes<HTMLDivElement>) => (
  <div className={cn('section-label', className)} {...props} />
)

// ─── Severity ────────────────────────────────────────────────────────────────
const SEV_CLASS: Record<Severity, string> = {
  critical: 'border-sev-critical/40 bg-sev-critical/10 text-sev-critical',
  high: 'border-sev-high/40 bg-sev-high/10 text-sev-high',
  medium: 'border-sev-medium/40 bg-sev-medium/10 text-sev-medium',
  low: 'border-sev-low/40 bg-sev-low/10 text-sev-low',
  normal: 'border-sev-normal/40 bg-sev-normal/10 text-sev-normal',
  learning: 'border-warn/40 bg-warn/10 text-warn',
}

/** Severity always carries its word as well as its hue: colour is never the
 *  sole carrier of meaning. */
export function SeverityBadge({
  severity,
  className,
}: {
  severity: string | null | undefined
  className?: string
}) {
  const key = (severity ?? 'normal').toLowerCase() as Severity
  const cls = SEV_CLASS[key] ?? SEV_CLASS.normal
  return (
    <span
      className={cn(
        'inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium',
        cls,
        className,
      )}
    >
      {severity ?? 'unrated'}
    </span>
  )
}

/** A 3px severity spine down the left of a panel. Quieter than a full border. */
export const SeveritySpine = ({ severity }: { severity: string | null | undefined }) => {
  const key = (severity ?? 'normal').toLowerCase()
  const bg =
    key === 'critical'
      ? 'bg-sev-critical'
      : key === 'high'
        ? 'bg-sev-high'
        : key === 'medium'
          ? 'bg-sev-medium'
          : key === 'low'
            ? 'bg-sev-low'
            : 'bg-sev-normal'
  return <span className={cn('absolute left-0 top-0 h-full w-[3px] rounded-l-lg', bg)} />
}

// ─── Claim status ────────────────────────────────────────────────────────────
const CLAIM_META: Record<
  ClaimStatusValue,
  { cls: string; help: string }
> = {
  observed: {
    cls: 'border-ok/40 bg-ok/10 text-ok',
    help: 'Present in the logs. The strongest thing this system can say.',
  },
  confirmed: {
    cls: 'border-ok/40 bg-ok/10 text-ok',
    help: 'Corroborated against the public record for this incident.',
  },
  inferred: {
    cls: 'border-warn/40 bg-warn/10 text-warn',
    help:
      'Derived from behaviour, not directly observed. Could be wrong; the ' +
      'missing evidence is listed alongside it.',
  },
  predicted: {
    cls: 'border-accent/40 bg-accent-soft text-accent',
    help: 'A forecast about what may happen next. Has not been observed.',
  },
  disputed: {
    cls: 'border-sev-critical/40 bg-sev-critical/10 text-sev-critical',
    help: 'Two analyses disagree about this. Neither has been suppressed.',
  },
  retracted: {
    cls: 'border-border bg-surface-2 text-faint line-through',
    help: 'Withdrawn after later evidence contradicted it.',
  },
}

/** An inferred finding must never render identically to an observed one. */
export function ClaimStatus({
  status,
  className,
}: {
  status: string | null | undefined
  className?: string
}) {
  const key = (status ?? 'inferred').toLowerCase() as ClaimStatusValue
  const meta = CLAIM_META[key] ?? CLAIM_META.inferred
  return (
    <InfoTip label={meta.help}>
      <span
        className={cn(
          'inline-flex items-center gap-1 rounded-full border px-2 py-0.5',
          'font-mono text-xs',
          meta.cls,
          className,
        )}
      >
        {key}
      </span>
    </InfoTip>
  )
}

// ─── Not measured ────────────────────────────────────────────────────────────
/** The words, in faint text, with the reason on hover.
 *
 *  Never a 0, never an em dash, never an empty cell, never hidden. A missing
 *  metric that renders as zero is the single most damaging thing this interface
 *  could do, because zero is a claim. */
export function NotMeasured({ why, className }: { why?: string; className?: string }) {
  return (
    <span className={cn('inline-flex items-center gap-1 text-faint', className)}>
      <Minus className="size-3" aria-hidden />
      <span className="text-xs">Not measured</span>
      {why ? (
        <InfoTip label={why} accessibleLabel="Why this value was not measured">
          <HelpCircle className="size-3" />
        </InfoTip>
      ) : null}
    </span>
  )
}

/** Render a Measured, or say plainly that it was not measured. */
export function MeasuredValue({
  m,
  digits = 1,
  className,
}: {
  m: Measured | number | null | undefined
  digits?: number
  className?: string
}) {
  if (m == null) return <NotMeasured />
  if (typeof m === 'number') {
    return <span className={cn('font-mono tabular-nums', className)}>{fmt(m, digits)}</span>
  }
  if (m.value == null || m.state === 'not measured') return <NotMeasured why={m.why ?? m.note} />
  return (
    <span className={cn('font-mono tabular-nums', className)}>
      {fmt(m.value, digits)}
      {m.unit ? <span className="ml-0.5 text-faint">{m.unit}</span> : null}
    </span>
  )
}

const fmt = (n: number, digits: number) =>
  Number.isInteger(n) ? n.toLocaleString() : n.toFixed(digits)

// ─── Provenance ──────────────────────────────────────────────────────────────
/** "Where this text came from." Stays on screen; it is not chrome to tidy away.
 *  A template reading identically to a model answer is the bug this prevents. */
export function ProvenanceLine({
  method,
  model,
  error,
  className,
}: {
  method: string | null | undefined
  model?: string
  error?: string
  className?: string
}) {
  if (!method) return null
  const deterministic = method === 'deterministic' || method === 'template'
  return (
    <div className={cn('font-mono text-xs text-faint', className)}>
      {deterministic
        ? `template · no language model${error ? ` · ${error}` : ''}`
        : `${method}${model ? ` · ${model}` : ''} · reworded, not authoritative`}
    </div>
  )
}

// ─── Metrics ─────────────────────────────────────────────────────────────────
/** A figure with its unit and the context that makes it mean something.
 *  A bare number with no unit and no dataset is not a metric, it is decoration. */
export function MetricCard({
  label,
  value,
  unit,
  context,
  baseline,
  severity,
  className,
}: {
  label: string
  value: React.ReactNode
  unit?: string
  context?: string
  baseline?: string
  severity?: string
  className?: string
}) {
  return (
    <div className={cn('relative rounded-lg border border-border bg-surface p-4', className)}>
      {severity ? <SeveritySpine severity={severity} /> : null}
      <SectionLabel>{label}</SectionLabel>
      <div className="mt-1.5 flex items-baseline gap-1">
        <span className="font-mono text-2xl tabular-nums text-text">{value}</span>
        {unit ? <span className="text-sm text-dim">{unit}</span> : null}
      </div>
      {context ? <div className="mt-1 text-xs text-dim">{context}</div> : null}
      {baseline ? <div className="mt-0.5 text-xs text-faint">vs {baseline}</div> : null}
    </div>
  )
}

/** A label/value line inside a panel. The workhorse of every detail view. */
export function StatRow({
  label,
  children,
  mono = true,
  className,
}: {
  label: string
  children: React.ReactNode
  mono?: boolean
  className?: string
}) {
  return (
    <div
      className={cn(
        'flex items-baseline justify-between gap-4 border-b border-border py-1.5 last:border-0',
        className,
      )}
    >
      <span className="text-xs text-dim">{label}</span>
      <span className={cn('text-right text-sm text-text', mono && 'font-mono tabular-nums')}>
        {children}
      </span>
    </div>
  )
}

// ─── Empty and error states ──────────────────────────────────────────────────
/** An honest empty state. Never a fabricated example row. */
export function EmptyState({
  title,
  detail,
  icon: Icon = Info,
  action,
}: {
  title: string
  detail?: string
  icon?: React.ComponentType<{ className?: string }>
  action?: React.ReactNode
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-4 py-10 text-center">
      <Icon className="size-5 text-faint" />
      <div className="text-sm text-dim">{title}</div>
      {detail ? <div className="max-w-md text-xs text-faint">{detail}</div> : null}
      {action ? <div className="mt-2">{action}</div> : null}
    </div>
  )
}

/** A failed fetch. Shows the backend's own message: a 403 reason is the demo. */
export function ErrorState({ error, retry }: { error: unknown; retry?: () => void }) {
  const msg = error instanceof Error ? error.message : String(error)
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-4 py-10 text-center">
      <AlertTriangle className="size-5 text-sev-high" />
      <div className="text-sm text-dim">Could not load this</div>
      <div className="max-w-md font-mono text-xs text-faint">{msg}</div>
      {retry ? (
        <button
          type="button"
          onClick={retry}
          className="mt-2 text-xs text-accent underline-offset-4 hover:underline"
        >
          Try again
        </button>
      ) : null}
    </div>
  )
}

// ─── Motion ──────────────────────────────────────────────────────────────────
/** Content arriving. Respects prefers-reduced-motion by rendering statically. */
export function Reveal({
  children,
  delay = 0,
  className,
}: {
  children: React.ReactNode
  delay?: number
  className?: string
}) {
  const reduced = useReducedMotion()
  if (reduced) return <div className={className}>{children}</div>
  return (
    <motion.div
      className={className}
      initial="hidden"
      animate="show"
      variants={fadeUp}
      transition={{ delay }}
    >
      {children}
    </motion.div>
  )
}

/** A list whose children arrive in sequence. Capped so a long table does not
 *  cascade for most of a second. */
export function RevealList({
  children,
  className,
}: {
  children: React.ReactNode
  className?: string
}) {
  const reduced = useReducedMotion()
  const count = React.Children.count(children)
  if (reduced) return <div className={className}>{children}</div>
  const container: Variants = {
    hidden: {},
    show: { transition: { staggerChildren: count > STAGGER_MAX ? 0 : STAGGER } },
  }
  return (
    <motion.div className={className} initial="hidden" animate="show" variants={container}>
      {React.Children.map(children, (child, i) => (
        <motion.div key={i} variants={fadeUp}>
          {child}
        </motion.div>
      ))}
    </motion.div>
  )
}

/** A number that counts to its new value when the value changes.
 *
 *  Only for figures that genuinely change during a session (a live score, a
 *  running count). A static metric does not need to animate on mount. */
export function AnimatedNumber({
  value,
  digits = 0,
  className,
}: {
  value: number
  digits?: number
  className?: string
}) {
  const reduced = useReducedMotion()
  const [shown, setShown] = React.useState(value)
  const from = React.useRef(value)

  React.useEffect(() => {
    if (reduced || from.current === value) {
      setShown(value)
      from.current = value
      return
    }
    const start = performance.now()
    const a = from.current
    const b = value
    let raf = 0
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / 420)
      // The house curve, sampled: matches EASE closely enough at this length.
      const eased = 1 - Math.pow(1 - t, 3)
      setShown(a + (b - a) * eased)
      if (t < 1) raf = requestAnimationFrame(tick)
      else from.current = b
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [value, reduced])

  return (
    <span className={cn('font-mono tabular-nums', className)}>
      {shown.toFixed(digits)}
    </span>
  )
}

export { EASE }
