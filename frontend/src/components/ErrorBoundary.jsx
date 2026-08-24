import React from 'react'
import { AlertTriangle, RefreshCw } from 'lucide-react'

export default class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props)
    this.state = { hasError: false, error: null }
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error }
  }

  componentDidCatch(error, errorInfo) {
    console.error('[ErrorBoundary] Caught runtime error:', error, errorInfo)
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{ padding: 24, margin: '20px auto', maxWidth: 800 }}>
          <div
            style={{
              padding: 20,
              background: 'var(--surface-raised, #1e293b)',
              borderRadius: 8,
              border: '1px solid var(--sev-critical, #ef4444)',
              color: 'var(--text, #f8fafc)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
              <AlertTriangle size={22} style={{ color: 'var(--sev-critical, #ef4444)' }} />
              <h3 style={{ margin: 0, fontSize: 17 }}>An error occurred in this view</h3>
            </div>
            <p style={{ fontSize: 13, color: 'var(--text-muted, #94a3b8)', marginBottom: 16 }}>
              {this.state.error?.message || String(this.state.error)}
            </p>
            <button
              className="btn primary"
              onClick={() => {
                this.setState({ hasError: false, error: null })
                window.location.reload()
              }}
              style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}
            >
              <RefreshCw size={13} /> Reload Page
            </button>
          </div>
        </div>
      )
    }
    return this.props.children
  }
}
