# PS7 Demo Incident Report

Incident: INC-PS7-DEMO-001
Title: Compromised account with lateral movement and possible exfiltration
Severity: critical
Max anomaly score: 100

## Attack Timeline
- t=200: failed_login_burst from C17693 to AUTH-SRV mapped to Credential Access / Brute Force (T1110); score=55.
- t=214: unusual_successful_login from C17693 to AUTH-SRV mapped to Initial Access / Valid Accounts (T1078); score=65.
- t=260: discovery_command from C17693 to C305 mapped to Discovery / System Network Configuration Discovery (T1016); score=50.
- t=310: lateral_movement from C17693 to C728 mapped to Lateral Movement / Remote Services (T1021); score=78.
- t=360: critical_asset_access from C728 to DB-CITIZEN-01 mapped to Collection / Data from Information Repositories (T1213); score=90.
- t=420: large_outbound_transfer from DB-CITIZEN-01 to EXT-185.77.21.9 mapped to Exfiltration / Exfiltration Over Web Service (T1567); score=100.

## Recommended Response
- Disable or step-up verify compromised account on U748@GOV (human approval required): Valid account activity appears in multiple attack stages.
- Isolate critical asset session and preserve forensic snapshot on DB-CITIZEN-01, EXT-185.77.21.9 (simulated containment): Critical asset access and possible exfiltration detected.
- Block suspicious external destination on EXT-185.77.21.9 (simulated firewall block): Large outbound transfer mapped to Exfiltration.
- Open incident ticket and notify SOC lead on INC-PS7-DEMO-001 (automatic): Critical severity incident requires response coordination.