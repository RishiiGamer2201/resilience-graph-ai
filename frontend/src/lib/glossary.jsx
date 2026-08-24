import { useState } from 'react'

/* Definitions, at the point of use.
 *
 * This product renders "blast radius", "choke point", "crown jewel", "MTTD",
 * "ROC-AUC", "noisy-OR", "pivot" and "calibrated anomaly score" without ever
 * defining one of them. Someone who works in a SOC reads those fluently.
 * Nobody else does, and the people this is built for -- a hospital IT lead, an
 * executive, a judge -- are mostly nobody else.
 *
 * There is no plain/technical switch. A mode toggle asks the reader to declare
 * their expertise before they have seen anything, and it doubles every screen.
 * The product speaks plainly by default and the words that cannot be replaced
 * -- T1550.002, ROC-AUC, an incident id -- carry their definition inline.
 *
 *     <Term k="blast radius" />                 the word, with its definition
 *     <Term k="roc-auc" as="ROC-AUC 0.992" />   any label, same definition
 */

// One line each, written for someone who has never worked in security. No term
// may be defined using another term from this list without that one also being
// marked up, or the definition is just a second wall.
export const GLOSSARY = {
  'blast radius': 'How many computers the attacker could still reach from where they already are.',
  'choke point': 'The one computer that, if disconnected, cuts off the most of that reach.',
  'crown jewel': 'A system you named as critical -- a patient database, a domain controller.',
  pivot: 'A computer the attacker is using as a base to reach others.',
  'lateral movement': 'Moving sideways from one computer to another using credentials they already stole.',
  'pass the hash': 'Signing in with a stolen password fingerprint instead of the password itself.',
  'brute force': 'Guessing a password by trying many of them quickly.',
  'valid accounts': 'Using a real employee login rather than breaking in, which is why normal defences miss it.',
  'att&ck': 'A public catalogue by MITRE that gives every known attacker behaviour an ID like T1110.',
  technique: 'One named attacker behaviour from the ATT&CK catalogue, such as T1110 Brute Force.',
  tactic: 'The attacker goal a technique serves, such as getting in, or spreading.',
  'anomaly score': 'How unusual an event looked, from 0 to 100. Unusual is not the same as malicious.',
  calibration: 'Which scale a score is on, and therefore whether it can be compared to another log.',
  'ranked-within-this-log': 'Scores are positions inside THIS log only. A 90 here and a 90 elsewhere are not the same.',
  'fixed anchors': 'Scores are on a fixed scale measured against a reference log, so they compare across logs.',
  mttd: 'Mean time to detect: how long an attacker went unnoticed.',
  dwell: 'How long an attacker was inside before anyone noticed.',
  'roc-auc': 'A score out of 1 for how well the detector separates attack from normal. 0.5 is a coin flip.',
  'pr-auc': 'Like ROC-AUC, but honest about rare events. A low number here is normal when attacks are rare.',
  'tpr@1%fpr': 'Of every real attack, the share caught while wrongly flagging only 1 in 100 normal events.',
  'false positive': 'A normal event the system wrongly flagged as an attack.',
  baseline: 'The dumb method we compare against. If we cannot beat it, we say so.',
  'noisy-or': 'A way of combining several weak signals without letting copies of the same signal stack up.',
  'horizon confidence': 'How far ahead the forecast is still worth reading. Past it, treat the numbers as a shape, not a value.',
  observed: 'Seen directly in the log.',
  inferred: 'A rule fired on indirect evidence. Weaker than observed.',
  disputed: 'Another signal contradicts it.',
  'not measured': 'We did not measure this, and we are saying so rather than guessing.',
  'crown-jewel exposure': 'How much of what you called critical the attacker can currently reach.',
  containment: 'Cutting a computer off the network to stop the spread.',
  'counterfactual': 'A what-if: we recompute the graph as though a host were already disconnected. Nothing is changed for real.',
  'digital twin': 'A copy of your network we can experiment on safely, because it is only a model.',
  'audit chain': 'A tamper-evident log: every entry seals the one before it, so a changed record is detectable.',
  rbac: 'Who is allowed to do what. Enforced by the server, not by hiding buttons.',
  soar: 'Automated response. Here every action is simulated and needs a human to approve it.',
  'attack path': 'The route from where the attacker got in to what you care about.',
  'kill chain': 'The ordered stages of an attack, from first access to impact.',
  ioc: 'Indicator of compromise: a concrete artefact, like an address or a file hash, tied to an attack.',
  'threat actor': 'The named group a set of behaviours is attributed to.',
  'kev': 'CISA Known Exploited Vulnerabilities: flaws confirmed to be exploited in the wild right now.',
  cvss: 'A 0 to 10 severity score for a vulnerability. Severity is not the same as urgency.',
  epss: 'The estimated probability a vulnerability gets exploited in the next 30 days.',
  autoencoder: 'A model trained only on normal activity. Anything it reconstructs badly is unusual.',
  'out of distribution': 'This log does not look like the one the model was tuned on, so the fixed scale does not transfer.',
}

export function define(term) {
  return GLOSSARY[String(term || '').trim().toLowerCase()] || null
}

/* ── The term itself ──────────────────────────────────────────────────────── */
/**
 * A jargon word that carries its own definition.
 *
 * `title` gives desktop hover for free; the button gives keyboard and touch a
 * real target, because a tooltip you can only reach with a mouse is not on a
 * phone at all.
 *
 * @param {string} k     glossary key
 * @param {string} [as]  the words to display, if not the key itself
 */
export function Term({ k, as, children }) {
  const [open, setOpen] = useState(false)
  const def = define(k)
  const label = as || children || k
  if (!def) return <>{label}</>
  return (
    <span className="term-wrap">
      <button type="button" className="term" title={def}
        aria-expanded={open} onClick={() => setOpen((o) => !o)}>
        {label}
      </button>
      {open && (
        <span className="term-pop" role="note">
          <strong>{label}</strong>
          {def}
        </span>
      )}
    </span>
  )
}
