"""
India scenario — synthetic hospital auth log styled after the AIIMS Delhi 2022
ransomware incident (a real, well-known attack on Indian critical infrastructure).

Everything is invented — fictional hospital domain, staff accounts, ward PCs, EMR
and patient-DB servers — but the SHAPE mirrors a real ransomware intrusion the way
it appears in authentication logs: a phished ward PC becomes the pivot, the account
moves laterally via NTLM across ward machines, reaches the EMR and radiology
servers, and finally the patient database (the crown jewel). Encryption itself
isn't an auth event; the detectable story is the lateral movement to critical
health-care systems.

Upload this on Analyze Log (or pick it from the scenario list) to see the whole
pipeline render a concrete Indian incident.

    ./.venv/Scripts/python.exe -m scripts.make_india_scenario
    -> data/demo/scenarios/aiims_ransomware.csv
"""
from __future__ import annotations

import csv
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "demo" / "scenarios" / "aiims_ransomware.csv"

COLS = ["timestamp", "user", "source_host", "destination_host", "event_type",
        "status", "protocol", "port", "bytes_out", "command", "asset_criticality", "label"]

STAFF = ["dr.sharma@AIIMS", "nurse.patel@AIIMS", "reception.rao@AIIMS", "lab.iyer@AIIMS"]
WARD_PCS = [f"WARD-PC-{i:03d}" for i in range(1, 45)]
SERVERS = ["EMR-SRV-01", "PACS-RADIOLOGY-01", "PHARMACY-SRV-01", "BILLING-SRV-01"]
CROWN = ["PATIENT-DB-01", "DC-AIIMS-01"]        # patient records DB + domain controller
PIVOT = "WARD-PC-013"                            # phished reception/ward machine
COMPROMISED = "reception.rao@AIIMS"


def rows() -> list[list]:
    rng = random.Random(11)
    out: list[list] = []
    t = 1_500_000

    def add(user, src, dst, status, proto, malicious, cmd=""):
        nonlocal t
        t += rng.randint(15, 150)
        out.append([t, user, src, dst, "auth", status, proto, 445, 0, cmd,
                    "critical" if dst in CROWN else "medium", int(malicious)])

    # benign hospital background — each staffer has a HOME machine and a couple of
    # servers they use repeatedly (established patterns -> low anomaly, not alerts,
    # so they don't pollute the attacker view).
    home = {s: WARD_PCS[40 + i] for i, s in enumerate(STAFF)}   # dedicated PCs, off the attack path
    routine = {s: rng.sample(SERVERS[:2], 2) for s in STAFF}
    for _ in range(90):
        s = rng.choice(STAFF)
        add(s, home[s], rng.choice(routine[s]), "success", "Kerberos", False)

    # intrusion: reception.rao phished; WARD-PC-013 becomes the pivot
    add(COMPROMISED, PIVOT, "EMR-SRV-01", "fail", "NTLM", True)          # failed PtH probe
    add(COMPROMISED, PIVOT, "EMR-SRV-01", "fail", "NTLM", True)
    add(COMPROMISED, PIVOT, "EMR-SRV-01", "success", "NTLM", True)
    # lateral spread across ward PCs (each a new host = lateral movement)
    for w in rng.sample([w for w in WARD_PCS if w != PIVOT], 22):
        add(COMPROMISED, PIVOT, w, "success", "NTLM", True)
    # reach the hospital's core systems, then the crown jewels
    for s in SERVERS:
        add(COMPROMISED, PIVOT, s, "success", "NTLM", True)
    add(COMPROMISED, PIVOT, "DC-AIIMS-01", "success", "NTLM", True, cmd="net group 'Domain Admins'")
    add(COMPROMISED, PIVOT, "PATIENT-DB-01", "success", "NTLM", True, cmd="bulk read patient records")

    # a second staff account compromised from a different ward PC (multi-pivot)
    b = "lab.iyer@AIIMS"
    for w in rng.sample(WARD_PCS, 5):
        add(b, "WARD-PC-031", w, "success", "NTLM", True)
    add(b, "WARD-PC-031", "PATIENT-DB-01", "success", "NTLM", True, cmd="db export")

    out.sort(key=lambda r: r[0])
    return out


def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    data = rows()
    with OUT.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(COLS)
        w.writerows(data)
    mal = sum(r[-1] for r in data)
    print(f"wrote {OUT.relative_to(ROOT)} — {len(data)} events · {mal} malicious · "
          f"2 compromised accounts · crown jewels PATIENT-DB-01, DC-AIIMS-01")


if __name__ == "__main__":
    main()
