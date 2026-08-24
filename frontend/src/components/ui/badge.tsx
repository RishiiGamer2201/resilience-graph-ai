import * as React from 'react'
import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '@/lib/utils'

const badgeVariants = cva(
  'inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs ' +
    'font-medium whitespace-nowrap',
  {
    variants: {
      variant: {
        default: 'border-border bg-surface-2 text-dim',
        accent: 'border-accent/30 bg-accent-soft text-accent',
        ok: 'border-ok/30 bg-ok/10 text-ok',
        warn: 'border-warn/30 bg-warn/10 text-warn',
        critical: 'border-sev-critical/30 bg-sev-critical/10 text-sev-critical',
        outline: 'border-border text-dim',
      },
    },
    defaultVariants: { variant: 'default' },
  },
)

export const Badge = ({
  className,
  variant,
  ...props
}: React.HTMLAttributes<HTMLSpanElement> & VariantProps<typeof badgeVariants>) => (
  <span className={cn(badgeVariants({ variant }), className)} {...props} />
)
