// Reusable surface card + header. Uses .card from theme.css.
export function Card({ children, className = '', style }) {
  return <section className={`card ${className}`} style={style}>{children}</section>
}

// title on the left; any children (actions/icons) + meta align to the right.
export function CardHeader({ title, meta, children }) {
  return (
    <div className="card-h">
      {title && <h3>{title}</h3>}
      <span className="spacer" />
      {children}
      {meta && <span className="meta" style={{ marginLeft: children ? 0 : 'auto' }}>{meta}</span>}
    </div>
  )
}

export function Loading({ label = 'Loading…' }) {
  return <div className="loading">{label}</div>
}

export function ErrorBox({ error }) {
  return (
    <div className="errbox">
      Could not reach the backend API.<br />
      <span className="mono" style={{ fontSize: 12 }}>{String(error?.message || error)}</span>
    </div>
  )
}
