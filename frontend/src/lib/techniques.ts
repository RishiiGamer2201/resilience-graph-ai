/** Human-readable MITRE ATT&CK names used by the shipped and live demo data. */
export const TECHNIQUE_NAMES: Record<string, string> = {
  T0814: 'Denial of Service',
  T1005: 'Data from Local System',
  T1021: 'Remote Services',
  'T1021.001': 'Remote Desktop Protocol',
  'T1021.002': 'SMB / Windows Admin Shares',
  'T1021.004': 'SSH',
  'T1021.006': 'Windows Remote Management',
  T1055: 'Process Injection',
  T1059: 'Command and Scripting Interpreter',
  'T1059.001': 'PowerShell',
  T1068: 'Exploitation for Privilege Escalation',
  'T1071.001': 'Web Protocols',
  'T1071.004': 'DNS',
  'T1074.001': 'Local Data Staging',
  T1078: 'Valid Accounts',
  T1102: 'Web Service',
  T1105: 'Ingress Tool Transfer',
  T1110: 'Brute Force',
  T1113: 'Screen Capture',
  T1119: 'Automated Collection',
  T1133: 'External Remote Services',
  T1190: 'Exploit Public-Facing Application',
  T1195: 'Supply Chain Compromise',
  'T1204.002': 'Malicious File',
  'T1219.001': 'IDE Tunneling',
  T1498: 'Network Denial of Service',
  T1505: 'Server Software Component',
  'T1550.002': 'Pass the Hash',
  'T1560.001': 'Archive via Utility',
  'T1560.003': 'Archive via Custom Method',
  T1566: 'Phishing',
  T1570: 'Lateral Tool Transfer',
  'T1584.005': 'Botnet',
}

const ID_PATTERN = /^T\d{4}(?:\.\d{3})?$/i

/** Prefer ATT&CK's name. A name supplied by the API covers newer techniques. */
export function techniqueName(id: string | null | undefined, suppliedName?: string | null): string {
  if (!id) return 'Technique not identified'
  const known = TECHNIQUE_NAMES[id.toUpperCase()]
  if (known) return known
  if (suppliedName && !ID_PATTERN.test(suppliedName)) {
    const parts = suppliedName.split(':')
    return parts[parts.length - 1].trim()
  }
  return 'MITRE technique not named'
}

export function techniqueList(ids: string[] | null | undefined, separator = ' → '): string {
  return ids?.length ? ids.map((id) => techniqueName(id)).join(separator) : 'No technique identified'
}

export function techniqueExplanation(id: string): string | null {
  const name = techniqueName(id)
  if (name === 'MITRE technique not named') return null
  const beginner: Record<string, string> = {
    'Pass the Hash': 'An attacker reuses a stolen password fingerprint to sign in without knowing the actual password.',
    'Valid Accounts': 'The attacker used a real account, which can make malicious activity look normal.',
    'Brute Force': 'Many password guesses were tried until one worked or an account was locked.',
    'Remote Services': 'A remote access service was used to move from one computer to another.',
    Phishing: 'A deceptive message or file was used to persuade someone to give access or run malicious content.',
    PowerShell: 'Windows PowerShell was used to run commands or scripts.',
    'Data Encrypted for Impact': 'Files were encrypted so the organization could no longer use them.',
  }
  return beginner[name] ?? `${name} is the official MITRE ATT&CK name for this attacker behavior.`
}
