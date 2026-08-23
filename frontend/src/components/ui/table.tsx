import * as React from 'react'
import { cn } from '@/lib/utils'

/** Dense data table. Wrap in a div with overflow-x-auto for wide content. */
export const Table = ({ className, ...props }: React.HTMLAttributes<HTMLTableElement>) => (
  <div className="w-full overflow-x-auto" data-lenis-prevent>
    <table className={cn('w-full border-collapse text-sm', className)} {...props} />
  </div>
)

export const THead = ({ className, ...props }: React.HTMLAttributes<HTMLTableSectionElement>) => (
  <thead className={cn('bg-surface-2', className)} {...props} />
)

export const TBody = ({ className, ...props }: React.HTMLAttributes<HTMLTableSectionElement>) => (
  <tbody className={className} {...props} />
)

export const TR = ({ className, ...props }: React.HTMLAttributes<HTMLTableRowElement>) => (
  <tr
    className={cn('border-b border-border last:border-0 hover:bg-surface-2/60', className)}
    {...props}
  />
)

export const TH = ({ className, ...props }: React.ThHTMLAttributes<HTMLTableCellElement>) => (
  <th
    className={cn(
      'px-3 py-2 text-left text-xs font-medium uppercase tracking-wider text-faint',
      className,
    )}
    {...props}
  />
)

export const TD = ({ className, ...props }: React.TdHTMLAttributes<HTMLTableCellElement>) => (
  <td className={cn('px-3 py-2 align-top', className)} {...props} />
)

/** For IDs, hosts, scores, hashes. Tabular so columns line up. */
export const TDMono = ({ className, ...props }: React.TdHTMLAttributes<HTMLTableCellElement>) => (
  <td className={cn('px-3 py-2 align-top font-mono text-xs', className)} {...props} />
)
