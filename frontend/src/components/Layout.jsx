import { Outlet, useLocation } from 'react-router-dom'
import Sidebar from './Sidebar.jsx'
import Topbar from './Topbar.jsx'
import { useAnalysis } from '../lib/analysis.jsx'

/* Page titles, and a subtitle that says what the screen ANSWERS rather than
 * what it is called. "Attack path / Blast radius & choke points" tells a reader
 * nothing they could not read off the nav; "which single host, if isolated,
 * severs the most" tells them why the screen exists.
 *
 * Two subtitles used to be lies rather than labels. Overview said
 * "Grid operator - DOM1", a persona nobody chose and an org that is not in any
 * shipped log, and Incident hardcoded INC-PS7-LANL-001 while every payload
 * carried INC-PS7-LANL-CAMPAIGN. Both now come from the analysis or say nothing. */
const TITLES = {
  '/investigate': { title: 'Investigation', subtitle: 'seven bounded stages, each one timed and each one able to report that it failed' },
  '/analyze': { title: 'Analyse log', subtitle: 'score every event, cluster the alerts, build the path' },
  '/overview': { title: 'Overview', subtitle: 'what this log shows, and how well established each part of it is' },
  '/digital-twin': { title: 'Containment twin', subtitle: 'what isolating a host would sever, and what it would cost' },
  '/attackers': { title: 'Accounts', subtitle: 'every account the campaign touched' },
  '/incident': { title: 'Incident timeline', subtitle: null },
  '/graph': { title: 'Attack path', subtitle: 'which single host, if isolated, severs the most' },
  '/threat-intel': { title: 'Attribution', subtitle: 'ranked candidates, with the margin between them' },
  '/threat-radar': { title: 'External intel', subtitle: 'public advisories, cross-referenced to this incident' },
  '/scoreboard': { title: 'Scoreboard', subtitle: 'every claim, its baseline, and the ones we did not measure' },
  '/metrics': { title: 'Models & metrics', subtitle: 'including the baselines that beat us' },
  '/methodology': { title: 'Data & methodology', subtitle: 'what the numbers were measured on' },
}

export default function Layout() {
  const { pathname } = useLocation()
  const { bundle } = useAnalysis() || {}
  const meta = TITLES[pathname] || { title: 'nextATT&CKs' }

  // The incident screen names the incident it is actually showing, or nothing.
  const subtitle = pathname === '/incident'
    ? (bundle?.incident?.incident_id || null)
    : meta.subtitle

  return (
    <div className="app">
      <Sidebar />
      <div className="main">
        <Topbar title={meta.title} subtitle={subtitle} />
        <div className="content">
          <Outlet />
        </div>
      </div>
    </div>
  )
}
