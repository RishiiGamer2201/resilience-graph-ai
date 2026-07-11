import { createContext, useContext, useEffect, useState, useCallback } from 'react'

const ThemeContext = createContext({ theme: 'light', setTheme: () => {} })

const STORAGE_KEY = 'rga-theme'

function initial() {
  if (typeof window === 'undefined') return 'light'
  return localStorage.getItem(STORAGE_KEY) || 'light' // default = light
}

export function ThemeProvider({ children }) {
  const [theme, setThemeState] = useState(initial)

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    try { localStorage.setItem(STORAGE_KEY, theme) } catch { /* ignore */ }
  }, [theme])

  const setTheme = useCallback((t) => setThemeState(t), [])

  return (
    <ThemeContext.Provider value={{ theme, setTheme }}>
      {children}
    </ThemeContext.Provider>
  )
}

export const useTheme = () => useContext(ThemeContext)
