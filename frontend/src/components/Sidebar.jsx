import { NavLink } from 'react-router-dom'
import {
  ClipboardCheck, Crosshair, Cpu, Database, LayoutDashboard, LineChart,
  Radar, Satellite, ScanSearch, Shield, Users, Waypoints,
} from 'lucide-react'

/* Three groups, and the grouping is an argument rather than a filing system.
 *
 * ANALYSE is what you do to a log. EVIDENCE is what the system will show you to
 * back a claim. METHOD is how it was measured. A reader who never clicks past
 * the labels still learns that this product separates a finding from its
 * justification -- which is the thing it is actually for. */
const GROUPS = [
  {
    label: 'Analyse',
    hint: 'a log, end to end',
    items: [
      { to: '/investigate', label: 'Investigation', icon: Crosshair },
      { to: '/analyze', label: 'Analyse log', icon: ScanSearch },
      { to: '/overview', label: 'Overview', icon: LayoutDashboard },
      { to: '/incident', label: 'Incident timeline', icon: Radar },
      { to: '/graph', label: 'Attack path', icon: Waypoints },
      { to: '/attackers', label: 'Accounts', icon: Users },
    ],
  },
  {
    label: 'Evidence',
    hint: 'what backs a claim',
    items: [
      { to: '/threat-intel', label: 'Attribution', icon: Shield },
      { to: '/threat-radar', label: 'External intel', icon: Satellite },
      { to: '/digital-twin', label: 'Containment twin', icon: Cpu },
    ],
  },
  {
    label: 'Method',
    hint: 'how it was measured',
    items: [
      { to: '/scoreboard', label: 'Scoreboard', icon: ClipboardCheck },
      { to: '/metrics', label: 'Models & metrics', icon: LineChart },
      { to: '/methodology', label: 'Data & methodology', icon: Database },
    ],
  },
]

function NavItem({ to, label, icon: Icon }) {
  return (
    <NavLink to={to} className={({ isActive }) => (isActive ? 'active' : undefined)}>
      <Icon className="ic" strokeWidth={1.75} aria-hidden="true" />
      <span>{label}</span>
    </NavLink>
  )
}

export default function Sidebar() {
  return (
    <aside className="rail">
      {/* The wordmark is the ampersand, because the product is named for the
        * ATT&CK catalogue and that is the one glyph the name owns. The old mark
        * was a letter "R", left over from a previous name the product no longer
        * has. */}
      <div className="brand">
        <div className="mark" aria-hidden="true">&amp;</div>
        <div className="brand-text">
          <b>nextATT&amp;CKs</b>
          <span>Authentication-log forensics</span>
        </div>
      </div>

      {GROUPS.map((g) => (
        <div className="nav-group" key={g.label}>
          <div className="nav-label">
            {g.label}<em>{g.hint}</em>
          </div>
          <nav className="nav" aria-label={g.label}>
            {g.items.map((n) => <NavItem key={n.to} {...n} />)}
          </nav>
        </div>
      ))}

      <div className="rail-foot">
        <span className="mono">PS7</span> Critical National Infrastructure
      </div>
    </aside>
  )
}
