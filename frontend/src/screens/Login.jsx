import { useNavigate } from 'react-router-dom'
import { ArrowRight, ShieldCheck } from 'lucide-react'
import { useSession } from '../lib/session.jsx'

export default function Login() {
  const navigate = useNavigate()
  const { role, roles, setRole } = useSession()
  return (
    <div className="login">
      <div className="login-card">
        <div className="mark">R</div>
        <h1>{'nextATT&CKs'}</h1>
        <div className="tagline">SOC Command Center · PS7 Cyber Resilience</div>
        <p className="desc">
          Real-time anomaly detection, attack-path reasoning and ATT&amp;CK-driven
          attribution for critical national infrastructure.
        </p>

        <label className="login-role">
          <span>Sign in as</span>
          <select value={role} onChange={(e) => setRole(e.target.value)}>
            {roles.map((r) => (
              <option key={r.role} value={r.role}>{r.label} — {r.can}</option>
            ))}
          </select>
        </label>
        <p className="login-note">
          <ShieldCheck size={13} aria-hidden="true" />
          The role travels with every request and is enforced by the API, not by this
          screen. Picking Responder here does not grant anything — try approving a
          crown-jewel action as an Analyst and the server refuses. This is
          authorisation without authentication, on purpose, so the demo needs no signup.
        </p>

        <button className="btn primary" onClick={() => navigate('/investigate')}>
          Enter demo environment <ArrowRight size={16} aria-hidden="true" />
        </button>
        <div className="login-meta">
          No credentials · no API key · no network required
        </div>
      </div>
    </div>
  )
}
