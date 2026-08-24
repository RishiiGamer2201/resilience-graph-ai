import * as React from 'react'
import * as TooltipPrimitive from '@radix-ui/react-tooltip'
import { cn } from '@/lib/utils'

export const TooltipProvider = TooltipPrimitive.Provider
export const Tooltip = TooltipPrimitive.Root
export const TooltipTrigger = TooltipPrimitive.Trigger

export const TooltipContent = React.forwardRef<
  React.ElementRef<typeof TooltipPrimitive.Content>,
  React.ComponentPropsWithoutRef<typeof TooltipPrimitive.Content>
>(({ className, sideOffset = 6, ...props }, ref) => (
  <TooltipPrimitive.Portal>
    <TooltipPrimitive.Content
      ref={ref}
      sideOffset={sideOffset}
      className={cn(
        'z-50 max-w-xs rounded-md border border-border bg-surface px-2.5 py-1.5',
        'text-xs text-dim shadow-lg',
        'data-[state=delayed-open]:animate-in data-[state=closed]:animate-out',
        'data-[state=closed]:fade-out-0 data-[state=delayed-open]:fade-in-0',
        className,
      )}
      {...props}
    />
  </TooltipPrimitive.Portal>
))
TooltipContent.displayName = 'TooltipContent'

/** The common case: an info affordance explaining a number or a caveat. */
export const InfoTip = ({
  children,
  label,
  accessibleLabel,
}: {
  children: React.ReactNode
  label: string
  accessibleLabel?: string
}) => {
  const descriptionId = React.useId()
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          aria-label={accessibleLabel}
          aria-describedby={descriptionId}
          className="cursor-help text-faint hover:text-dim"
        >
          {children}
        </button>
      </TooltipTrigger>
      <TooltipContent id={descriptionId}>{label}</TooltipContent>
    </Tooltip>
  )
}
