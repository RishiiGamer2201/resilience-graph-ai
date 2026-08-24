import { NavLink } from 'react-router-dom'
import {
  ClipboardCheck, Crosshair, Cpu, Database, LayoutDashboard, LineChart,
  Radar, Satellite, ScanSearch, Shield, Users, Waypoints,
} from 'lucide-react'

/* The nav is the instruction manual, so it is written as one.
 *
 * It used to be three groups -- Analyse, Evidence, Method -- with six items in
 * the first one and no indication that twelve of the thirteen screens only mean
 * anything AFTER you press Run. A first-time reader opened Overview, saw a
 * pre-computed sample, and had no way to know they were looking at a demo of a
 * step they had not taken.
 *
 * So the groups are numbered and phrased as the question each one answers, and
 * every downstream screen carries a caption naming what it will tell you. Order
 * is now information: 1 produces the analysis, 2 reads it, 3 backs it up, 4
 * shows the working.
 *
 * Deliberately NOT hiding or disabling steps 2 to 4 before a run. The sample
 * data is real and a judge should be able to land anywhere and see something;
 * the honest fix is the topbar pill saying SAMPLE, plus the caption here, not
 * a locked door. */
const GROUPS = [
  {
    n: '1',
    label: 'Start here',
    hint: 'pick a log and run it',
    items: [
      { to: '/investigate', label: 'Run an investigation', icon: Crosshair,
        caption: 'seven stages, about ten seconds' },
      { to: '/analyze', label: 'Use my own log', icon: ScanSearch,
        caption: 'upload a CSV of sign-in events' },
    ],
  },
  {
    n: '2',
    label: 'What happened',
    hint: 'the findings',
    items: [
      { to: '/overview', label: 'Summary', icon: LayoutDashboard,
        caption: 'how bad, and what to do' },
      { to: '/incident', label: 'Story of the attack', icon: Radar,
        caption: 'every step, in order' },
      { to: '/graph', label: 'Where it can spread', icon: Waypoints,
        caption: 'and the one host that stops it' },
      { to: '/attackers', label: 'Accounts involved', icon: Users,
        caption: 'who was used, and how much' },
    ],
  },
  {
    n: '3',
    label: 'Why believe it',
    hint: 'the evidence',
    items: [
      { to: '/threat-intel', label: 'Who it looks like', icon: Shield,
        caption: 'named groups, ranked, with the margin' },
      { to: '/threat-radar', label: 'Public advisories', icon: Satellite,
        caption: 'official warnings that match' },
      { to: '/digital-twin', label: 'Test a containment', icon: Cpu,
        caption: 'safe what-if, nothing is changed' },
    ],
  },
  {
    n: '4',
    label: 'Show the working',
    hint: 'how it was measured',
    items: [
      { to: '/scoreboard', label: 'Every claim scored', icon: ClipboardCheck,
        caption: 'including the ones we lost' },
      { to: '/metrics', label: 'Model accuracy', icon: LineChart,
        caption: 'against the baselines' },
      { to: '/methodology', label: 'Data and method', icon: Database,
        caption: 'what the numbers came from' },
    ],
  },
]

export { GROUPS }

function NavItem({ to, label, icon: Icon, caption, onNavigate }) {
  return (
    <NavLink to={to} onClick={onNavigate}
      className={({ isActive }) => (isActive ? 'active' : undefined)}>
      <Icon className="ic" strokeWidth={1.75} aria-hidden="true" />
      <span className="nav-text">
        {label}
        {caption && <em className="nav-cap">{caption}</em>}
      </span>
    </NavLink>
  )
}

export default function Sidebar({ onNavigate }) {
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
          <span>Finds attackers using real logins</span>
        </div>
      </div>

      {GROUPS.map((g) => (
        <div className="nav-group" key={g.label}>
          <div className="nav-label">
            <span className="nav-n" aria-hidden="true">{g.n}</span>
            {g.label}<em>{g.hint}</em>
          </div>
          <nav className="nav" aria-label={`${g.n}. ${g.label}`}>
            {g.items.map((n) => <NavItem key={n.to} {...n} onNavigate={onNavigate} />)}
          </nav>
        </div>
      ))}

      <div className="rail-foot">
        <span className="mono">PS7</span> Critical National Infrastructure
      </div>
    </aside>
  )
}
