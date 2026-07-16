"""
India scenarios — synthetic auth logs styled after real, well-known attacks on
Indian critical infrastructure:

  * AIIMS Delhi 2022 ransomware — a phished ward PC pivots across the hospital to
    the patient database and domain controller.
  * CBSE-style education-board breach — a phished office PC pivots to the exam-
    paper server, results database and student-data store (paper leak / result
    tampering).

Everything is invented (fictional domains, staff, hosts) but the SHAPE mirrors a
real intrusion as it appears in authentication logs: a compromised account moves
laterally via NTLM across workstations, reaches core systems, and finally the
crown-jewel servers. Encryption/exfil itself isn't an auth event; the detectable
story is the lateral movement to critical sector systems.

Pick either from the scenario list on Analyze Log, or upload the CSV.

    ./.venv/Scripts/python.exe -m scripts.make_india_scenario
    -> data/demo/scenarios/{aiims_ransomware,cbse_exam_breach}.csv
"""
from __future__ import annotations

import csv
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "data" / "demo" / "scenarios"

COLS = ["timestamp", "user", "source_host", "destination_host", "event_type",
        "status", "protocol", "port", "bytes_out", "command", "asset_criticality", "label"]

# Each scenario: staff accounts, workstation pool, core servers, crown jewels,
# the phished pivot + account, a second compromised account, and the crown-jewel
# access commands that give the incident its sector flavour.
SCENARIOS = {
    "aiims_ransomware": {
        "seed": 11,
        "staff": ["dr.sharma@AIIMS", "nurse.patel@AIIMS", "reception.rao@AIIMS", "lab.iyer@AIIMS"],
        "wks": [f"WARD-PC-{i:03d}" for i in range(1, 45)],
        "servers": ["EMR-SRV-01", "PACS-RADIOLOGY-01", "PHARMACY-SRV-01", "BILLING-SRV-01"],
        "crown": ["PATIENT-DB-01", "DC-AIIMS-01"],
        "pivot": "WARD-PC-013", "actor": "reception.rao@AIIMS",
        "second": ("lab.iyer@AIIMS", "WARD-PC-031"),
        "crown_cmds": {"DC-AIIMS-01": "net group 'Domain Admins'",
                       "PATIENT-DB-01": "bulk read patient records"},
    },
    "cbse_exam_breach": {
        "seed": 23,
        "staff": ["exam.admin@CBSE", "it.staff@CBSE", "clerk.singh@CBSE", "controller.rao@CBSE"],
        "wks": [f"OFFICE-PC-{i:03d}" for i in range(1, 40)],
        "servers": ["FILESHARE-01", "REGISTRATION-SRV-01", "PORTAL-SRV-01", "MAIL-SRV-01"],
        "crown": ["EXAM-PAPERS-SRV-01", "RESULTS-DB-01", "STUDENT-DATA-DB-01", "DC-CBSE-01"],
        "pivot": "OFFICE-PC-009", "actor": "clerk.singh@CBSE",
        "second": ("it.staff@CBSE", "OFFICE-PC-021"),
        "crown_cmds": {"EXAM-PAPERS-SRV-01": "download sealed question papers",
                       "RESULTS-DB-01": "update marks table",
                       "STUDENT-DATA-DB-01": "export student records",
                       "DC-CBSE-01": "net group 'Domain Admins'"},
    },
}


def build(cfg: dict) -> list[list]:
    rng = random.Random(cfg["seed"])
    crown = set(cfg["crown"])
    out: list[list] = []
    t = 1_500_000

    def add(user, src, dst, status, proto, malicious, cmd=""):
        nonlocal t
        t += rng.randint(15, 150)
        out.append([t, user, src, dst, "auth", status, proto, 445, 0, cmd,
                    "critical" if dst in crown else "medium", int(malicious)])

    staff, wks, servers = cfg["staff"], cfg["wks"], cfg["servers"]
    # benign background: each staffer has a HOME machine + a couple of routine
    # servers (established patterns -> low anomaly, so they stay out of the alerts).
    home = {s: wks[len(wks) - 1 - i] for i, s in enumerate(staff)}   # dedicated PCs off the path
    routine = {s: rng.sample(servers[:2], 2) for s in staff}
    for _ in range(90):
        s = rng.choice(staff)
        add(s, home[s], rng.choice(routine[s]), "success", "Kerberos", False)

    # intrusion: the phished account works from the pivot
    pivot, actor = cfg["pivot"], cfg["actor"]
    add(actor, pivot, servers[0], "fail", "NTLM", True)          # failed pass-the-hash probe
    add(actor, pivot, servers[0], "fail", "NTLM", True)
    add(actor, pivot, servers[0], "success", "NTLM", True)
    for w in rng.sample([w for w in wks if w != pivot], 20):     # lateral spread
        add(actor, pivot, w, "success", "NTLM", True)
    for s in servers:                                            # reach core systems
        add(actor, pivot, s, "success", "NTLM", True)
    for c in cfg["crown"]:                                       # then the crown jewels
        add(actor, pivot, c, "success", "NTLM", True, cfg["crown_cmds"].get(c, ""))

    # a second compromised account from a different workstation (multi-pivot)
    b_user, b_pivot = cfg["second"]
    for w in rng.sample(wks, 5):
        add(b_user, b_pivot, w, "success", "NTLM", True)
    add(b_user, b_pivot, cfg["crown"][0], "success", "NTLM", True, "db export")

    out.sort(key=lambda r: r[0])
    return out


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for name, cfg in SCENARIOS.items():
        data = build(cfg)
        out = OUT_DIR / f"{name}.csv"
        with out.open("w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(COLS)
            w.writerows(data)
        mal = sum(r[-1] for r in data)
        print(f"wrote {out.relative_to(ROOT)} — {len(data)} events · {mal} malicious · "
              f"crown jewels {', '.join(cfg['crown'])}")


if __name__ == "__main__":
    main()
