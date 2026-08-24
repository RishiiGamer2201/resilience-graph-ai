import { useEffect, useState } from 'react'
import { Outlet, useLocation } from 'react-router-dom'
import Sidebar from './Sidebar.jsx'
import Topbar from './Topbar.jsx'
import { useAnalysis } from '../lib/analysis.jsx'

/* Page titles, and a subtitle that says what the screen ANSWERS rather than
 * what it is called. "Attack path / Blast radius & choke points" tells a reader
 * nothing they could not read off the nav; "which single host, if isolated,
 * severs the most" tells them why the screen exists.
 *
 * Rewritten once more for a reader who has never worked in a SOC. The old
 * subtitles were accurate and used "blast radius", "choke point", "crown jewel"
 * and "counterfactual" to be so. A title is the wrong place to teach a word:
 * the glossary handles that in the body, and the title just has to be true in
 * language anyone reads.
 *
 * Two subtitles used to be lies rather than labels. Overview said
 * "Grid operator - DOM1", a persona nobody chose and an org that is not in any
 * shipped log, and Incident hardcoded INC-PS7-LANL-001 while every payload
 * carried INC-PS7-LANL-CAMPAIGN. Both now come from the analysis or say nothing. */
const TITLES = {
  '/investigate': { title: 'Run an investigation', subtitle: 'pick a log, press Run, read what it found' },
  '/analyze': { title: 'Use my own log', subtitle: 'upload a CSV of sign-in events and run the same pipeline' },
  '/overview': { title: 'Summary', subtitle: 'how bad this is, what to do, and how sure we are' },
  '/digital-twin': { title: 'Test a containment', subtitle: 'what disconnecting a computer would stop, and what it would break' },
  '/attackers': { title: 'Accounts involved', subtitle: 'every account the attacker used, and how much each one moved' },
  '/incident': { title: 'Story of the attack', subtitle: null },
  '/graph': { title: 'Where it can spread', subtitle: 'and the single computer that, disconnected, stops the most of it' },
  '/threat-intel': { title: 'Who it looks like', subtitle: 'named groups this behaviour matches, ranked, with the margin between them' },
  '/threat-radar': { title: 'Public advisories', subtitle: 'official warnings that match what we found here' },
  '/scoreboard': { title: 'Every claim scored', subtitle: 'each number, what it was compared against, and the ones we did not measure' },
  '/metrics': { title: 'Model accuracy', subtitle: 'including the simpler methods that beat us' },
  '/methodology': { title: 'Data and method', subtitle: 'what the numbers were measured on' },
}

export default function Layout() {
  const { pathname } = useLocation()
  const { bundle } = useAnalysis() || {}
  const meta = TITLES[pathname] || { title: 'nextATT&CKs' }
  const [navOpen, setNavOpen] = useState(false)

  // A drawer that survives navigation is a trap on a phone: you tap a link, the
  // page changes underneath, and the thing covering it stays put.
  useEffect(() => { setNavOpen(false) }, [pathname])

  useEffect(() => {
    if (!navOpen) return undefined
    const esc = (e) => { if (e.key === 'Escape') setNavOpen(false) }
    document.addEventListener('keydown', esc)
    document.body.style.overflow = 'hidden'
    return () => {
      document.removeEventListener('keydown', esc)
      document.body.style.overflow = ''
    }
  }, [navOpen])

  // The incident screen names the incident it is actually showing, or nothing.
  const subtitle = pathname === '/incident'
    ? (bundle?.incident?.incident_id || null)
    : meta.subtitle

  return (
    <div className={`app${navOpen ? ' nav-open' : ''}`}>
      <Sidebar onNavigate={() => setNavOpen(false)} />
      {/* Tapping the dimmed page closes the drawer, which is what every phone
          user tries first. aria-hidden because it duplicates the close button. */}
      <button className="nav-scrim" aria-hidden="true" tabIndex={-1}
        onClick={() => setNavOpen(false)} />
      <div className="main">
        <Topbar title={meta.title} subtitle={subtitle}
          navOpen={navOpen} onToggleNav={() => setNavOpen((o) => !o)} />
        <div className="content">
          <Outlet />
        </div>
      </div>
    </div>
  )
}
