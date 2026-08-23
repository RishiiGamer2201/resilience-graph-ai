import { useNavigate } from 'react-router-dom'
import { ArrowRight } from 'lucide-react'
import { useSession } from '../lib/session.jsx'

/* The four marks every claim in this product carries. Showing them here, before
 * any screen uses them, makes the entry page the key to the notation rather than
 * a splash: by the time a reader reaches the Investigation screen they already
 * know that a dashed grey square means "we did not measure this".
 *
 * `unmeasured` is deliberately last and deliberately present. Most security
 * products have no way to say it. */
const MARKS = [
  { k: 'observed', g: 'O', label: 'Observed', desc: 'seen directly in the log' },
  { k: 'inferred', g: 'I', label: 'Inferred', desc: 'a rule fired, evidence is indirect' },
  { k: 'disputed', g: 'D', label: 'Disputed', desc: 'another signal contradicts it' },
  { k: 'unmeasured', g: '·', label: 'Not measured', desc: 'and it will say so' },
]

export default function Login() {
  const navigate = useNavigate()
  const { role, roles, setRole } = useSession()
  return (
    <div className="login">
      <div className="login-card">
        <header className="login-head">
          <div className="mark" aria-hidden="true">&amp;</div>
          <div>
            <h1>nextATT&amp;CKs</h1>
            <p className="tagline">Authentication-log forensics</p>
          </div>
        </header>

        <p className="login-thesis">
          Finds the attacker who already has valid credentials, in the logs you
          already keep.
        </p>
        <p className="desc">
          Every number it shows you carries where it came from. Some are measured
          against real red-team labels, some are inferred from a rule, and some it
          did not measure at all &mdash; and it says which.
        </p>

        <ul className="marklegend">
          {MARKS.map((m) => (
            <li key={m.k}>
              <span className={`mark ${m.k}`} aria-hidden="true">{m.g}</span>
              <b>{m.label}</b>
              <span>{m.desc}</span>
            </li>
          ))}
        </ul>

        <label className="login-role">
          <span>Sign in as</span>
          <select value={role} onChange={(e) => setRole(e.target.value)}>
            {roles.map((r) => (
              <option key={r.role} value={r.role}>{r.label} &mdash; {r.can}</option>
            ))}
          </select>
        </label>
        <p className="login-note">
          The role travels with every request and the API enforces it, not this
          screen. Pick Analyst and try to approve a crown-jewel action: the server
          refuses, and the refusal is written to the audit chain. Authorisation
          without authentication, on purpose, so the demo needs no signup.
        </p>

        <button className="btn primary" onClick={() => navigate('/investigate')}>
          Open the console <ArrowRight size={16} aria-hidden="true" />
        </button>
        <div className="login-meta">
          No credentials, no API key, no network.
        </div>
      </div>
    </div>
  )
}
