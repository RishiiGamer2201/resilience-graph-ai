import { Component, type ErrorInfo, type ReactNode } from 'react'
import { AlertTriangle } from 'lucide-react'

interface State {
  error: Error | null
}

/** A crashed screen shows what crashed. A blank panel teaches a reviewer
 *  nothing and hides a bug we would rather see. */
export default class ErrorBoundary extends Component<{ children: ReactNode }, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('screen crashed', error, info.componentStack)
  }

  render() {
    const { error } = this.state
    if (!error) return this.props.children
    return (
      <div className="flex flex-col items-center gap-2 rounded-lg border border-border bg-surface p-10 text-center">
        <AlertTriangle className="size-5 text-sev-critical" />
        <div className="text-sm text-dim">This screen failed to render</div>
        <pre className="max-w-2xl overflow-x-auto whitespace-pre-wrap font-mono text-xs text-faint">
          {error.message}
        </pre>
        <button
          type="button"
          onClick={() => this.setState({ error: null })}
          className="mt-2 text-xs text-accent underline-offset-4 hover:underline"
        >
          Try again
        </button>
      </div>
    )
  }
}
