import * as React from 'react'
import { Slot } from '@radix-ui/react-slot'
import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '@/lib/utils'

const buttonVariants = cva(
  'inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md ' +
    'text-sm font-medium transition-colors duration-[120ms] ' +
    'focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent ' +
    'disabled:pointer-events-none disabled:opacity-50 ' +
    "[&_svg]:pointer-events-none [&_svg:not([class*='size-'])]:size-4 shrink-0",
  {
    variants: {
      variant: {
        // Exactly one primary action per view.
        default: 'bg-accent text-accent-fg hover:bg-accent-hover',
        secondary: 'bg-surface-2 text-text border border-border hover:bg-surface-3',
        outline: 'border border-border bg-transparent text-text hover:bg-surface-2',
        ghost: 'text-dim hover:bg-surface-2 hover:text-text',
        link: 'text-accent underline-offset-4 hover:underline',
        // A proposal awaiting approval, never a live control. Response actions
        // in this product are simulated and human-gated; the button must read
        // that way. See DESIGN.md section 5.
        destructive:
          'border border-sev-critical/40 bg-sev-critical/10 text-sev-critical ' +
          'hover:bg-sev-critical/15',
      },
      size: {
        sm: 'h-7 px-2.5 text-xs',
        default: 'h-8 px-3',
        lg: 'h-9 px-4',
        icon: 'size-8',
      },
    },
    defaultVariants: { variant: 'default', size: 'default' },
  },
)

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, ...props }, ref) => {
    const Comp = asChild ? Slot : 'button'
    return (
      <Comp
        ref={ref}
        className={cn(buttonVariants({ variant, size }), className)}
        {...props}
      />
    )
  },
)
Button.displayName = 'Button'
export { buttonVariants }
