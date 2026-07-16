import { NavLink } from 'react-router-dom'
import { LayoutDashboard, Radar, Waypoints, Shield, LineChart, Database, ScanSearch, Satellite } from 'lucide-react'

const OPERATIONS = [
  { to: '/analyze', label: 'Analyze Log', icon: ScanSearch },
  { to: '/overview', label: 'Overview', icon: LayoutDashboard },
  { to: '/incident', label: 'Live Incident', icon: Radar, alert: true },
  { to: '/graph', label: 'Attack Graph', icon: Waypoints },
  { to: '/threat-intel', label: 'Threat Intel & Attribution', icon: Shield },
  { to: '/threat-radar', label: 'Threat Radar', icon: Satellite },
]
const EVIDENCE = [
  { to: '/metrics', label: 'Models & Metrics', icon: LineChart },
  { to: '/methodology', label: 'Data & Methodology', icon: Database },
]

function NavItem({ to, label, icon: Icon, alert }) {
  return (
    <NavLink to={to} className={({ isActive }) => (isActive ? 'active' : undefined)}>
      <Icon className="ic" strokeWidth={2} aria-hidden="true" />
      <span>{label}</span>
      {alert && <span className="dot" aria-label="active alert" />}
    </NavLink>
  )
}

export default function Sidebar() {
  return (
    <aside className="rail">
      <div className="brand">
        <div className="mark">R</div>
        <div>
          <b>Resilience Graph AI</b>
          <span>SOC Command Center</span>
        </div>
      </div>

      <div className="nav-label">Operations</div>
      <nav className="nav" aria-label="Operations">
        {OPERATIONS.map((n) => <NavItem key={n.to} {...n} />)}
      </nav>

      <div className="nav-label">Evidence</div>
      <nav className="nav" aria-label="Evidence">
        {EVIDENCE.map((n) => <NavItem key={n.to} {...n} />)}
      </nav>

      <div className="rail-foot">PS7 · Critical National Infrastructure</div>
    </aside>
  )
}
