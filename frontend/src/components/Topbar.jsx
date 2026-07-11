import { useEffect, useState } from 'react'
import { Sun, Moon } from 'lucide-react'
import { useTheme } from '../lib/theme.jsx'

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

  return (
    <div className="topbar">
      <h1>{title}{subtitle && <small>{subtitle}</small>}</h1>
      <span className="pill live"><span className="d" />2 detectors live</span>
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
