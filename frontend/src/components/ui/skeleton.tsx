import { cn } from '@/lib/utils'

/** Loading placeholder. A quiet pulse, not a shimmer sweep. */
export const Skeleton = ({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) => (
  <div
    className={cn('animate-pulse rounded-md bg-surface-2', className)}
    aria-hidden
    {...props}
  />
)

/** The default loading shape for a panel body. */
export const SkeletonRows = ({ rows = 4 }: { rows?: number }) => (
  <div className="space-y-2" role="status" aria-label="Loading">
    {Array.from({ length: rows }, (_, i) => (
      <Skeleton key={i} className="h-6" style={{ width: `${100 - i * 7}%` }} />
    ))}
  </div>
)
