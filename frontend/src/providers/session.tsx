import { createContext, useCallback, useContext, useEffect, useState } from 'react'
import { setSession as setApiSession } from '@/lib/api'
import type { Role } from '@/types/api'

/**
 * Who the backend thinks is calling.
 *
 * The role is sent as a header and enforced SERVER-SIDE on every mutating
 * endpoint. Switching it here cannot grant permission; it only changes which
 * refusal comes back. That is the demo: flip to Viewer and watch the API say no.
 */
export interface Principal {
  role: Role
  actor: string
  label: string
  can: string
}

export const ROLES: Principal[] = [
  { role: 'viewer', actor: 'viewer@soc', label: 'Viewer', can: 'read only' },
  { role: 'analyst', actor: 'asha@soc', label: 'Analyst', can: 'investigate, propose' },
  { role: 'responder', actor: 'ravi@soc', label: 'Responder', can: 'approve containment' },
  { role: 'admin', actor: 'admin@soc', label: 'Admin', can: 'everything' },
]

interface SessionValue extends Principal {
  setRole: (role: Role) => void
  roles: Principal[]
}

const SessionContext = createContext<SessionValue>({
  ...ROLES[1],
  setRole: () => {},
  roles: ROLES,
})

export function SessionProvider({ children }: { children: React.ReactNode }) {
  const [current, setCurrent] = useState<Principal>(ROLES[1])

  useEffect(() => {
    setApiSession({ role: current.role, actor: current.actor })
  }, [current])

  const setRole = useCallback((role: Role) => {
    setCurrent(ROLES.find((r) => r.role === role) ?? ROLES[1])
  }, [])

  return (
    <SessionContext.Provider value={{ ...current, setRole, roles: ROLES }}>
      {children}
    </SessionContext.Provider>
  )
}

export const useSession = () => useContext(SessionContext)
