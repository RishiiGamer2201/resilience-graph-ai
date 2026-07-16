"""
Generate a SYNTHETIC auth log (common event schema) you can upload to prove the
pipeline analyses arbitrary input rather than being wired to the two LANL files.

Everything here is invented — a fictional Indian bank, obviously-not-LANL host
and account names — so when you upload it the whole app (scoring, correlation,
graph, SOAR, attribution, prediction) renders THIS incident, not the demo one.

    ./.venv/Scripts/python.exe -m scripts.make_sample_upload
    -> data/demo/uploads/sample_bank_incident.csv   (upload this on Analyze Log)
"""
from __future__ import annotations

import csv
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "demo" / "uploads" / "sample_bank_incident.csv"

COLS = ["timestamp", "user", "source_host", "destination_host", "event_type",
        "status", "protocol", "port", "bytes_out", "command", "asset_criticality", "label"]

# Fictional estate — deliberately nothing like LANL's C#### / U####@DOM1.
ACCOUNTS = ["arjun.mehta@BANK", "priya.nair@BANK", "svc_backup@BANK",
            "rohan.das@BANK", "admin_helpdesk@BANK"]
WORKSTATIONS = [f"WKSTN-{i:03d}" for i in range(1, 40)]
SERVERS = ["FILESRV-01", "MAILSRV-01", "APP-UPI-01", "JUMPHOST-01"]
CROWN = ["DC-MUMBAI-01", "DB-COREBANK-01"]          # domain controller + core banking DB
ATTACKER_PIVOT = "WKSTN-013"                         # the compromised entry workstation


def rows() -> list[list]:
    rng = random.Random(7)
    out: list[list] = []
    t = 1_000_000

    def add(user, src, dst, status, proto, malicious, port=445, cmd=""):
        nonlocal t
        t += rng.randint(20, 180)
        out.append([t, user, src, dst, "auth", status, proto, port, 0, cmd,
                    "critical" if dst in CROWN else "medium", int(malicious)])

    # --- benign background: normal people using normal machines (Kerberos) ---
    for _ in range(60):
        u = rng.choice(ACCOUNTS[:2] + [ACCOUNTS[3]])
        add(u, rng.choice(WORKSTATIONS), rng.choice(SERVERS), "success", "Kerberos", False)

    # --- the incident: arjun.mehta compromised, attacker pivots off WKSTN-013 ---
    a = "arjun.mehta@BANK"
    add(a, ATTACKER_PIVOT, "FILESRV-01", "fail", "NTLM", True)          # failed pass-the-hash probe
    add(a, ATTACKER_PIVOT, "FILESRV-01", "fail", "NTLM", True)
    add(a, ATTACKER_PIVOT, "FILESRV-01", "success", "NTLM", True)       # in
    # fan out across many workstations via NTLM (new hosts each time = lateral movement)
    for w in rng.sample(WORKSTATIONS, 18):
        add(a, ATTACKER_PIVOT, w, "success", "NTLM", True)
    # reach servers, then the crown jewels
    for s in SERVERS:
        add(a, ATTACKER_PIVOT, s, "success", "NTLM", True)
    add(a, ATTACKER_PIVOT, "DC-MUMBAI-01", "success", "NTLM", True, cmd="net group 'Domain Admins'")
    add(a, ATTACKER_PIVOT, "DB-COREBANK-01", "success", "NTLM", True, cmd="bulk export")

    # --- a SECOND compromised account, from a different pivot (multi-attacker) ---
    b = "svc_backup@BANK"
    for w in rng.sample(WORKSTATIONS, 6):
        add(b, "JUMPHOST-01", w, "success", "NTLM", True)
    add(b, "JUMPHOST-01", "DB-COREBANK-01", "success", "NTLM", True, cmd="shadow copy")

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
          f"2 compromised accounts · crown jewels DC-MUMBAI-01, DB-COREBANK-01")


if __name__ == "__main__":
    main()
