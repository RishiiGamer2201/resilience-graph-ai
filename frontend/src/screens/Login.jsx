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
            <p className="tagline">Finds attackers using real logins</p>
          </div>
        </header>

        <p className="login-thesis">
          Some attackers do not break in. They sign in.
        </p>
        <p className="desc">
          This reads the sign-in log every organisation already keeps and finds the
          person using a real employee&rsquo;s credentials -- the one normal defences
          miss, because nothing they do is technically forbidden. Every number it
          shows you says where it came from, and the ones it could not measure say
          so instead of guessing.
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
              <option key={r.role} value={r.role}>{r.label} -- {r.can}</option>
            ))}
          </select>
        </label>
        <p className="login-note">
          There is no password: this is a demo, and the role only changes what the
          server will let you do. Pick <b>Analyst</b> and try to approve a
          containment later -- the server refuses, and writes the refusal down.
        </p>

        <button className="btn primary" onClick={() => navigate('/investigate')}>
          Start <ArrowRight size={16} aria-hidden="true" />
        </button>
        <div className="login-meta">
          Runs entirely on this machine. No account, no API key, no internet.
        </div>
      </div>
    </div>
  )
}
