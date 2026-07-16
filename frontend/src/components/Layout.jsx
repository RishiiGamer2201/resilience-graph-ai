import { Outlet, useLocation } from 'react-router-dom'
import Sidebar from './Sidebar.jsx'
import Topbar from './Topbar.jsx'

const TITLES = {
  '/analyze': { title: 'Analyze Log', subtitle: 'Live pipeline' },
  '/overview': { title: 'Command Center', subtitle: 'Grid operator · DOM1' },
  '/incident': { title: 'Live Incident', subtitle: 'INC-PS7-LANL-001' },
  '/graph': { title: 'Attack-path Graph', subtitle: 'Blast radius & choke points' },
  '/threat-intel': { title: 'Threat Intel & Attribution', subtitle: 'ATT&CK-driven' },
  '/metrics': { title: 'Models & Metrics', subtitle: 'Evidence' },
  '/methodology': { title: 'Data & Methodology', subtitle: 'Our rigor' },
}

export default function Layout() {
  const { pathname } = useLocation()
  const meta = TITLES[pathname] || { title: 'Command Center' }
  return (
    <div className="app">
      <Sidebar />
      <div className="main">
        <Topbar title={meta.title} subtitle={meta.subtitle} />
        <div className="content">
          <Outlet />
        </div>
      </div>
    </div>
  )
}
