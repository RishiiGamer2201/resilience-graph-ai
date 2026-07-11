import { useNavigate } from 'react-router-dom'
import { ArrowRight } from 'lucide-react'

export default function Login() {
  const navigate = useNavigate()
  return (
    <div className="login">
      <div className="login-card">
        <div className="mark">R</div>
        <h1>Resilience Graph AI</h1>
        <div className="tagline">SOC Command Center · PS7 Cyber Resilience</div>
        <p className="desc">
          Real-time anomaly detection, attack-path reasoning and ATT&amp;CK-driven
          attribution for critical national infrastructure.
        </p>
        <button className="btn primary" onClick={() => navigate('/overview')}>
          Sign in as Analyst <ArrowRight size={16} aria-hidden="true" />
        </button>
        <div className="login-meta">Demo environment · no credentials required</div>
      </div>
    </div>
  )
}
