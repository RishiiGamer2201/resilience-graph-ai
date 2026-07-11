# Shared-Spine Incident Report (real LANL red-team data)

**Incident:** INC-PS7-LANL-001 · **Severity:** CRITICAL (max anomaly 100/100)
**Compromised account:** U66@DOM1 · **alerts:** 131 correlated from 215 events (alert-fatigue reduction).

## S2 — Correlated attack chain (ATT&CK tactics)
`Lateral Movement (×67) · Credential Access (×30)`
- Techniques: T1550.002, T1110

## S4 — Attack-path graph
- Graph: **94 hosts**, 93 movement edges.
- Entry / pivot host: **C17693** (fan-out to 93 hosts).
- Critical assets reachable: ['C2388'].
- Choke points to isolate (betweenness): ['C17693', 'C3435', 'C3755'].
- **Recommended isolation: C17693** → cuts a blast radius of 93 hosts.

## S5 — Simulated SOAR response (confidence-gated)
- Policy: low=monitor · medium=ticket · high=contain · critical-asset=human approval
- ATT&CK mitigations: Privileged Account Management, Update Software, Account Use Policies, Multi-factor Authentication

| Tactic | Action | Mode |
|---|---|---|
| Lateral Movement | Isolate the pivot host, block SMB/NTLM between segments | requires human approval |
| Credential Access | Force password reset + enable MFA | requires human approval |
| Containment | Isolate choke-point host C17693 (cuts blast radius of 93 hosts) | requires human approval |
| Coordination | Open incident ticket INC-PS7-LANL-001 + notify SOC lead | automatic |

_All response actions are simulated. Built on real LANL red-team authentications; scores from the E1.3 IsolationForest detector._