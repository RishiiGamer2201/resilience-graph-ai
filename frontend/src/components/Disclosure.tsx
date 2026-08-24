/**
 * "Show the arithmetic" - the affordance that turns a number into a claim you
 * can check.
 *
 * Seven panels need it (headline metrics, the four-axis assessment, claims,
 * the cross-check, the forecast, the case file, the vulnerability queue), so it
 * lives here rather than being re-inlined seven times with seven easings.
 *
 * The open/close is a layout change, which is a legitimate use of motion; the
 * `collapse` variant and `prefers-reduced-motion` are both honoured.
 */
import * as React from 'react'
import { ChevronDown, ChevronRight } from 'lucide-react'
import { AnimatePresence, motion, useReducedMotion } from 'motion/react'
import { collapse } from '@/lib/motion'
import { cn } from '@/lib/utils'

export function Disclosure({
  label,
  labelOpen,
  children,
  className,
  defaultOpen = false,
}: {
  label: string
  /** Defaults to `label`. Supply when the closed and open wording differ. */
  labelOpen?: string
  children: React.ReactNode
  className?: string
  defaultOpen?: boolean
}) {
  const [open, setOpen] = React.useState(defaultOpen)
  const reduced = useReducedMotion()
  const Chevron = open ? ChevronDown : ChevronRight

  return (
    <div className={className}>
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        className={cn(
          'inline-flex items-center gap-1 rounded-md text-xs text-accent',
          'underline-offset-4 hover:underline',
        )}
      >
        <Chevron className="size-3" aria-hidden />
        {open ? (labelOpen ?? label) : label}
      </button>
      <AnimatePresence initial={false}>
        {open ? (
          reduced ? (
            <div className="overflow-hidden pt-2">{children}</div>
          ) : (
            <motion.div
              initial="hidden"
              animate="show"
              exit="hidden"
              variants={collapse}
              className="overflow-hidden"
            >
              <div className="pt-2">{children}</div>
            </motion.div>
          )
        ) : null}
      </AnimatePresence>
    </div>
  )
}

/** The small print under a panel: method, caveat, provenance. Never a claim. */
export const FinePrint = ({
  className,
  ...props
}: React.HTMLAttributes<HTMLParagraphElement>) => (
  <p className={cn('text-xs leading-relaxed text-faint', className)} {...props} />
)

/** A stated absence: "we could not do this, and here is why". Distinct from an
 *  EmptyState because it sits inside a populated panel. */
export const Disclosed = ({
  className,
  ...props
}: React.HTMLAttributes<HTMLDivElement>) => (
  <div
    className={cn(
      'rounded-md border border-border bg-surface-2 px-3 py-2 text-xs text-dim',
      className,
    )}
    {...props}
  />
)
