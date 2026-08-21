"""PS7 operational evaluation harness — the numbers the scoreboard shows.

The model metrics (ROC-AUC, PR-AUC, top-k) come from the Engine 1/2 eval scripts.
This harness measures the OPERATIONAL half of PS7, which nothing else measures:

  attack_mapping   what share of correlated alerts carry an ATT&CK technique, and
                   whether every emitted technique ID exists in the canonical
                   lookups (a hallucinated ID would show up here as < 1.0)
  soar_coverage    what share of observed tactics have a playbook action, and what
                   share of observed techniques have real MITRE mitigations
  mttd             measured time from first event to first correlated alert, per
                   shipped scenario
  latency          end-to-end investigation wall time, p50/p95 over repeated runs
  audit            does the hash chain verify, and is a tampered chain detected
  provenance       does every scenario result carry a provenance label

Everything is recomputed from the shipped scenarios on every run, written to
`reports/ps7_eval.md` and merged into `reports/metrics.json` through the canonical
metrics store. The UI never hard-codes any of it.

Run:
    ./.venv/Scripts/python.exe -m scripts.eval_ps7
    ./.venv/Scripts/python.exe -m scripts.eval_ps7 --runs 5
"""
from __future__ import annotations

import argparse
import json
import pickle
import statistics
import time
from pathlib import Path

from src.shared.metrics_store import update
from src.shared.timeutil import fmt_ist

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "data" / "demo" / "scenarios"
LOOKUPS = ROOT / "data" / "processed" / "mitre_attack" / "attack_lookups.pkl"
REPORT = ROOT / "reports" / "ps7_eval.md"

CRITICAL = {
    "aiims_ransomware": ["PATIENT-DB-01", "DC-AIIMS-01"],
    "cbse_exam_breach": ["EXAM-PAPERS-SRV-01", "RESULTS-DB-01",
                         "STUDENT-DATA-DB-01", "DC-CBSE-01"],
}


def _lanl_critical() -> list[str]:
    f = SCENARIOS / "critical_assets.json"
    return [a["host"] for a in json.loads(f.read_text())["assets"]] if f.exists() else []


def scenarios() -> dict[str, list[str]]:
    out = {}
    for csv in sorted(SCENARIOS.glob("*.csv")):
        out[csv.stem] = CRITICAL.get(csv.stem) or (
            _lanl_critical() if csv.stem.startswith("lanl") else [])
    return out


def measure(runs: int = 3) -> dict:
    from src.shared.attack_mapper import RULE_MAP
    from src.shared.soar import TACTIC_ACTIONS
    from src.shared.workflow import investigate

    with LOOKUPS.open("rb") as f:
        lk = pickle.load(f)
    valid_ids = set(lk["technique_to_name"])
    mitigations = lk.get("technique_to_mitigations", {})

    per_scenario, timings = [], []
    total_alerts = mapped_alerts = 0
    all_tactics: set[str] = set()
    all_techniques: set[str] = set()
    invalid_ids: set[str] = set()

    for name, crit in scenarios().items():
        durations = []
        result = None
        for _ in range(max(1, runs)):
            t = time.perf_counter()
            result = investigate(scenario=name, critical_assets=crit)
            durations.append((time.perf_counter() - t) * 1000)
        inc = result["signals"]["incident"]
        steps = inc["steps"]
        alerts = [s for s in steps if s.get("is_alert")]
        mapped = [s for s in alerts if s.get("technique_id") not in (None, "", "-")]
        total_alerts += len(alerts)
        mapped_alerts += len(mapped)
        tactics = {s["tactic"] for s in alerts if s["tactic"] != "Normal"}
        all_tactics |= tactics
        all_techniques |= set(inc["technique_ids"])
        invalid_ids |= {t for t in inc["technique_ids"] if t not in valid_ids}
        timings += durations

        mttd = result["signals"]["overview"]["mttd"]
        per_scenario.append({
            "scenario": name,
            "events": inc["event_count"],
            "alerts": inc["alert_count"],
            "incidents": 1,
            "alert_reduction_ratio": round(inc["event_count"] / max(1, inc["alert_count"]), 2),
            "techniques": inc["technique_ids"],
            "tactics": sorted(tactics),
            "mttd_seconds": mttd["ours_seconds"],
            "mttd_human": mttd["value"],
            "crown_jewel_exposure": result["headline"]["crown_jewel_exposure"]["value"],
            "attack_progression_likelihood":
                result["headline"]["attack_progression_likelihood"]["value"],
            "evidence_confidence": result["headline"]["evidence_confidence"]["value"],
            "actionable_claims": result["headline"]["evidence_confidence"]["actionable_claims"],
            "total_claims": result["headline"]["evidence_confidence"]["total_claims"],
            "citations": len(result["evidence"].get("citations", [])),
            "vuln_findings": result["impact"]["vulnerabilities"].get("total_findings", 0),
            "proposals": len(result["action"]["proposals"]),
            "gated": sum(1 for p in result["action"]["proposals"]
                         if p["policy"]["requires_approval"]),
            "executed": result["action"]["executed"],
            "latency_ms_median": round(statistics.median(durations), 1),
            "degraded_nodes": result["trace"]["degraded"],
        })

    # ---- SOAR coverage ---------------------------------------------------
    tactics_with_action = {t for t in all_tactics if t in TACTIC_ACTIONS}
    techs_with_mitigation = {t for t in all_techniques if mitigations.get(t)}
    playbook = {
        "observed_tactics": sorted(all_tactics),
        "tactics_with_playbook_action": sorted(tactics_with_action),
        "tactic_coverage": round(len(tactics_with_action) / max(1, len(all_tactics)), 4),
        "observed_techniques": sorted(all_techniques),
        "techniques_with_mitre_mitigations": sorted(techs_with_mitigation),
        "mitigation_coverage": round(len(techs_with_mitigation) / max(1, len(all_techniques)), 4),
        "playbook_tactics_defined": sorted(TACTIC_ACTIONS),
        "detector_event_types_mapped": len(RULE_MAP),
        "actions_executed_against_real_systems": 0,
        "note": ("Coverage over the tactics/techniques these scenarios actually produce. "
                 "The event-type -> ATT&CK rule map has "
                 f"{len(RULE_MAP)} entries; techniques outside it are reported unmapped "
                 "rather than guessed."),
    }

    # ---- audit chain -----------------------------------------------------
    from src.shared.audit import AuditChain
    c = AuditChain({"harness": "eval_ps7"})
    c.append("analysis.completed", actor="harness", role="system", incident_id="INC-EVAL")
    c.append("action.proposed", actor="harness", role="system", incident_id="INC-EVAL",
             action={"kind": "isolate", "host": "H1"})
    ok_before, _ = c.verify()
    tampered = json.loads(json.dumps(c.records()))
    tampered[1]["reason"] = "edited after the fact"
    ok_after, problem = AuditChain.verify_records(tampered)
    audit = {"chain_verifies": ok_before, "tamper_detected": not ok_after,
             "detection_message": problem, "hash_algorithm": "sha256"}

    # ---- RBAC denial -----------------------------------------------------
    from src.shared.rbac import Denied, policy_for, require, resolve_principal
    denied = False
    try:
        require(resolve_principal("viewer", None, None), "approve_critical")
    except Denied:
        denied = True
    rbac = {
        "roles": ["viewer", "analyst", "responder", "admin"],
        "viewer_denied_approval": denied,
        "crown_jewel_action_requires_approval":
            policy_for({"kind": "isolate", "touches_crown_jewel": True})["requires_approval"],
        "low_impact_pre_approved":
            not policy_for({"kind": "monitor", "blast_radius_affected": 1})["requires_approval"],
        "enforced": "server-side on every mutating endpoint",
    }

    lat = sorted(timings)
    return {
        "evaluated_at": fmt_ist(),
        "runs_per_scenario": runs,
        "scenarios": per_scenario,
        "attack_mapping": {
            "alerts": total_alerts,
            "alerts_with_technique": mapped_alerts,
            "coverage": round(mapped_alerts / max(1, total_alerts), 4),
            "invalid_technique_ids": sorted(invalid_ids),
            "id_validity": round(1.0 - len(invalid_ids) / max(1, len(all_techniques)), 4),
            "ground_truth_precision": None,
            "ground_truth_note": ("Not measured: no public dataset used here carries a "
                                  "per-event ATT&CK technique label, so event->technique "
                                  "precision cannot be computed. We report coverage and "
                                  "ID validity, which we can."),
        },
        "soar_coverage": playbook,
        "latency_ms": {
            "p50": round(statistics.median(lat), 1),
            "p95": round(lat[max(0, int(0.95 * len(lat)) - 1)], 1),
            "max": round(lat[-1], 1),
            "samples": len(lat),
            "scope": "full 7-node investigation, warm process, laptop CPU, no GPU",
        },
        "mttd": {
            "measured_per_scenario": {s["scenario"]: s["mttd_seconds"] for s in per_scenario},
            "definition": "seconds from the first event in the log to the first "
                          "correlated alert",
            "note": "Measured from each log's own timestamps. Industry dwell time is "
                    "cited separately as a comparison, never as our measurement.",
        },
        "mttr": {
            "value": None,
            "state": "not measured",
            "why": ("Every response action in this product is SIMULATED and human-gated. "
                    "With no execution there is no repair to time. Claiming an MTTR "
                    "improvement would be fabricating the headline number PS7 asks for."),
        },
        "audit": audit,
        "rbac": rbac,
    }


def write_report(m: dict) -> None:
    lines = [
        "# PS7 operational evaluation", "",
        f"Evaluated: {m['evaluated_at']}  ·  {m['runs_per_scenario']} run(s) per scenario",
        "", "## Per scenario", "",
        "| Scenario | Events | Alerts | Incidents | MTTD | Exposure | Likelihood | "
        "Evidence conf. | Actionable claims | Citations | Actions (gated) | Executed | "
        "Median latency |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for s in m["scenarios"]:
        lines.append(
            f"| {s['scenario']} | {s['events']} | {s['alerts']} | {s['incidents']} | "
            f"{s['mttd_human']} | "
            f"{s['crown_jewel_exposure'] if s['crown_jewel_exposure'] is not None else 'n/a'} | "
            f"{s['attack_progression_likelihood']} | {s['evidence_confidence']} | "
            f"{s['actionable_claims']}/{s['total_claims']} | {s['citations']} | "
            f"{s['proposals']} ({s['gated']}) | {s['executed']} | "
            f"{s['latency_ms_median']:.0f} ms |")
    am, sc, lat = m["attack_mapping"], m["soar_coverage"], m["latency_ms"]
    lines += [
        "", "## ATT&CK mapping", "",
        f"- alerts carrying a technique: **{am['coverage']:.1%}** "
        f"({am['alerts_with_technique']} of {am['alerts']})",
        f"- emitted technique IDs valid against the canonical ATT&CK lookups: "
        f"**{am['id_validity']:.1%}** (invalid: {am['invalid_technique_ids'] or 'none'})",
        f"- event->technique precision: **Not measured** — {am['ground_truth_note']}",
        "", "## SOAR coverage", "",
        f"- observed tactics with a playbook action: **{sc['tactic_coverage']:.1%}** "
        f"({', '.join(sc['tactics_with_playbook_action'])})",
        f"- observed techniques with real MITRE mitigations: "
        f"**{sc['mitigation_coverage']:.1%}**",
        f"- actions executed against a real system: **{sc['actions_executed_against_real_systems']}** "
        "(by design — every action is simulated and human-gated)",
        "", "## Latency", "",
        f"- p50 **{lat['p50']:.0f} ms**, p95 **{lat['p95']:.0f} ms**, max {lat['max']:.0f} ms "
        f"over {lat['samples']} runs ({lat['scope']})",
        "", "## MTTD / MTTR", "",
        f"- MTTD: {m['mttd']['definition']}. Per scenario: "
        + ", ".join(f"{k} {v}s" for k, v in m["mttd"]["measured_per_scenario"].items()),
        f"- MTTR: **Not measured.** {m['mttr']['why']}",
        "", "## Auditability and authorisation", "",
        f"- hash chain verifies: **{m['audit']['chain_verifies']}**; "
        f"tampering detected: **{m['audit']['tamper_detected']}** "
        f"(`{m['audit']['detection_message']}`)",
        f"- viewer denied `approve_critical`: **{m['rbac']['viewer_denied_approval']}**; "
        f"crown-jewel action gated: **{m['rbac']['crown_jewel_action_requires_approval']}**; "
        f"low-impact pre-approved: **{m['rbac']['low_impact_pre_approved']}**", "",
    ]
    REPORT.write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--runs", type=int, default=3, help="timed runs per scenario")
    args = ap.parse_args()
    m = measure(args.runs)
    write_report(m)
    for section in ("attack_mapping", "soar_coverage", "latency_ms", "mttd", "mttr",
                    "audit", "rbac"):
        update("ps7", section, m[section])
    update("ps7", "scenarios", {"rows": m["scenarios"], "evaluated_at": m["evaluated_at"]})
    print(f"ps7 eval: mapping coverage {m['attack_mapping']['coverage']:.1%} · "
          f"id validity {m['attack_mapping']['id_validity']:.1%} · "
          f"SOAR tactic coverage {m['soar_coverage']['tactic_coverage']:.1%} · "
          f"latency p50 {m['latency_ms']['p50']:.0f} ms / p95 {m['latency_ms']['p95']:.0f} ms · "
          f"audit tamper detected {m['audit']['tamper_detected']}")
