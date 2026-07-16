import { useEffect, useState } from 'react'
import { Sun, Moon } from 'lucide-react'
import { useTheme } from '../lib/theme.jsx'
import { useAnalysis } from '../lib/analysis.jsx'

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
  const live = source === 'live'

  return (
    <div className="topbar">
      <h1>{title}{subtitle && <small>{subtitle}</small>}</h1>
      <span className={`pill ${live ? 'live' : 'sample'}`}
        title={live ? 'Rendering a live analysis you ran' : 'Pre-computed sample analysis of a shipped real log'}>
        <span className="d" />
        {live ? `LIVE ANALYSIS · ${bundle?.meta?.n_events ?? ''} events` : 'SAMPLE DATA · pre-computed'}
      </span>
      <div className="spacer" />
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
