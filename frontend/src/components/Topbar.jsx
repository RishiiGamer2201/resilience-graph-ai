import { useEffect, useState } from 'react'
import { Menu, Moon, Sun, UserCog, X } from 'lucide-react'
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

/* The bar carried six controls of equal weight: two status pills, a role
 * picker, a clock, and a two-button theme toggle. On a phone that is the whole
 * screen before any content, and none of them is what a reader came for.
 *
 * So it is now tiered. Always: the title and the source pill, because "am I
 * looking at my own run or the example?" is the one question the bar has to
 * answer. Behind "More": role, calibration basis, clock, theme.
 */
export default function Topbar({ title, subtitle, navOpen, onToggleNav }) {
  const clock = useClock()
  const { theme, setTheme } = useTheme()
  const { source, bundle } = useAnalysis()
  const { role, actor, roles, setRole } = useSession()
  const [more, setMore] = useState(false)
  const live = source === 'live'

  return (
    <div className={`topbar${more ? ' more-open' : ''}`}>
      <button className="navbtn" onClick={onToggleNav}
        aria-expanded={!!navOpen} aria-label={navOpen ? 'Close menu' : 'Open menu'}>
        {navOpen ? <X size={18} aria-hidden="true" /> : <Menu size={18} aria-hidden="true" />}
      </button>

      <div className="topbar-head">
        <h1>{title}</h1>
        {subtitle && <p className="topbar-sub">{subtitle}</p>}
      </div>

      <span className={`pill ${live ? 'live' : 'sample'}`}
        title={live
          ? 'You are looking at an analysis you ran'
          : 'A pre-computed example, so every screen shows something before you run anything'}>
        <span className="d" />
        {live ? `YOUR RUN · ${bundle?.meta?.n_events ?? ''} events` : 'EXAMPLE DATA'}
      </span>


      <div className="spacer" />

      <button className="morebtn" onClick={() => setMore((m) => !m)}
        aria-expanded={more}>
        {more ? 'Less' : 'More'}
      </button>

      <div className="topbar-more">
        <CalibrationBadge />
        <label className="rolepick"
          title={`Sent to the server on every request and enforced there. Signed in as ${actor}.`}>
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
    </div>
  )
}
