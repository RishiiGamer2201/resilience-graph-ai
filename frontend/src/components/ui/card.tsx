import * as React from 'react'
import { cn } from '@/lib/utils'

/** A panel. Border, not shadow: only things that genuinely float get elevation. */
export const Card = ({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) => (
  <div
    className={cn('rounded-lg border border-border bg-surface', className)}
    {...props}
  />
)

export const CardHeader = ({
  className,
  ...props
}: React.HTMLAttributes<HTMLDivElement>) => (
  <div
    className={cn(
      'flex items-center justify-between gap-3 border-b border-border px-4 py-2.5',
      className,
    )}
    {...props}
  />
)

export const CardTitle = ({
  className,
  ...props
}: React.HTMLAttributes<HTMLHeadingElement>) => (
  <h3 className={cn('text-sm font-medium text-text', className)} {...props} />
)

/** The right-hand slot of a header: units, counts, provenance. Never a claim. */
export const CardMeta = ({ className, ...props }: React.HTMLAttributes<HTMLSpanElement>) => (
  <span className={cn('font-mono text-xs text-faint', className)} {...props} />
)

export const CardBody = ({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) => (
  <div className={cn('p-4', className)} {...props} />
)

export const CardFooter = ({
  className,
  ...props
}: React.HTMLAttributes<HTMLDivElement>) => (
  <div
    className={cn('border-t border-border px-4 py-2.5 text-xs text-faint', className)}
    {...props}
  />
)
