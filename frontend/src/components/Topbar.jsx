import { useEffect, useState } from 'react'
import { Sun, Moon, UserCog } from 'lucide-react'
import { useTheme } from '../lib/theme.jsx'
import { useAnalysis } from '../lib/analysis.jsx'
import { useSession } from '../lib/session.jsx'
import CalibrationBadge from './CalibrationBadge.jsx'

function useClock() {
  const [now, setNow] = useState(() => new Date())
  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 1000)
    return () => clearInterval(id)
  }, [])
  const p = (n) => String(n).padStart(2, '0')
  const date = `${now.getFullYear()}-${p(now.getMonth() + 1)}-${p(now.getDate())}`
  const time = `${p(now.getHours())}:${p(now.getMinutes())}:${p(now.getSeconds())}`
  return `${date} · ${time} IST`
}

export default function Topbar({ title, subtitle }) {
  const clock = useClock()
  const { theme, setTheme } = useTheme()
  const { source, bundle } = useAnalysis()
  const { role, actor, roles, setRole } = useSession()
  const live = source === 'live'

  return (
    <div className="topbar">
      <h1>{title}{subtitle && <small>{subtitle}</small>}</h1>
      <span className={`pill ${live ? 'live' : 'sample'}`}
        title={live ? 'Rendering a live analysis you ran' : 'Pre-computed sample analysis of a shipped real log'}>
        <span className="d" />
        {live ? `LIVE ANALYSIS · ${bundle?.meta?.n_events ?? ''} events` : 'SAMPLE DATA · pre-computed'}
      </span>
      {/* Which scale the scores below are on. Same provenance job as the pill
          beside it, so no screen can show a bare number without its basis. */}
      <CalibrationBadge />
      <div className="spacer" />
      <label className="rolepick" title={`Sent as X-Role and enforced server-side. Signed in as ${actor}.`}>
        <UserCog size={13} aria-hidden="true" />
        <span className="sr-only">Role</span>
        <select value={role} onChange={(e) => setRole(e.target.value)}>
          {roles.map((r) => <option key={r.role} value={r.role}>{r.label} — {r.can}</option>)}
        </select>
      </label>
      <span className="clock" aria-live="off">{clock}</span>
      <div className="toggle" role="group" aria-label="Theme">
        <button className={theme === 'light' ? 'on' : undefined}
          onClick={() => setTheme('light')} aria-pressed={theme === 'light'}>
          <Sun size={14} aria-hidden="true" /> Light
        </button>
        <button className={theme === 'dark' ? 'on' : undefined}
          onClick={() => setTheme('dark')} aria-pressed={theme === 'dark'}>
          <Moon size={14} aria-hidden="true" /> Dark
        </button>
      </div>
    </div>
  )
}
