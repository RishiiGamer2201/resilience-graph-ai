import { createContext, useCallback, useContext, useEffect, useState } from 'react'
import { setSession as setApiSession } from '../api.js'

// Who the backend thinks is calling. The role is sent as a header and enforced
// SERVER-SIDE on every mutating endpoint — switching it here cannot grant
// permission, it only changes which refusal you get back. That is the point:
// a judge can flip to Viewer and watch the API say no.
const ROLES = [
  { role: 'viewer', actor: 'viewer@soc', label: 'Viewer', can: 'read only' },
  { role: 'analyst', actor: 'asha@soc', label: 'Analyst', can: 'investigate, propose' },
  { role: 'responder', actor: 'ravi@soc', label: 'Responder', can: 'approve containment' },
  { role: 'admin', actor: 'admin@soc', label: 'Admin', can: 'everything' },
]

const SessionContext = createContext({ role: 'analyst', actor: 'asha@soc', setRole: () => {}, roles: ROLES })

export function SessionProvider({ children }) {
  const [current, setCurrent] = useState(ROLES[1])
  useEffect(() => { setApiSession({ role: current.role, actor: current.actor }) }, [current])
  const setRole = useCallback((role) => {
    setCurrent(ROLES.find((r) => r.role === role) || ROLES[1])
  }, [])
  return (
    <SessionContext.Provider value={{ ...current, setRole, roles: ROLES }}>
      {children}
    </SessionContext.Provider>
  )
}

export const useSession = () => useContext(SessionContext)
