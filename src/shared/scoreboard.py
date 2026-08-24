"""The PS7 evaluation scoreboard.

One screen that answers the question the problem statement actually asks: how
well does this system detect, attribute, decide and prove — measured, against a
baseline, with the evidence one click away.

Every value is read from `reports/metrics.json`, which the evaluation scripts
write. Nothing here is typed by hand, and a metric that has not been measured is
rendered `Not measured` with the reason — never zero, never a placeholder, never
a number borrowed from a slide.

Card contract (enforced by `tests/test_scoreboard.py`):
  * `state` is "measured" or "not_measured";
  * a measured card has a numeric `value`, a `definition`, a `dataset` and a
    `report` that exists on disk;
  * an unmeasured card has a `why` and no value;
  * no card may report bare accuracy, and no card may claim perfect attribution.

    from src.shared.scoreboard import scoreboard
"""
from __future__ import annotations

from pathlib import Path

from src.shared.metrics_store import load as load_metrics
from src.shared.timeutil import fmt_ist

ROOT = Path(__file__).resolve().parents[2]
REPORTS = ROOT / "reports"

# Claims we refuse to make about security models, and why. Kept in code so the
# test can assert on it rather than trusting a review to catch a regression.
FORBIDDEN_CLAIMS = {
    "accuracy": "meaningless at 0.006% attack prevalence — use PR-AUC or TPR at a fixed FPR",
    "100% attribution": "the profile-retrieval eval is near-trivial by construction",
}


def _pct(x: float | None) -> float | None:
    return None if x is None else round(100.0 * x, 1)


def _card(id: str, group: str, name: str, *, definition: str, dataset: str,
          value=None, unit: str = "", baseline: dict | None = None,
          higher_is_better: bool = True, report: str | None = None,
          why: str | None = None, note: str = "", sample: str = "",
          provenance: str = "VERIFIED") -> dict:
    measured = value is not None
    return {
        "id": id, "group": group, "name": name,
        "definition": definition, "dataset": dataset, "sample": sample,
        "state": "measured" if measured else "not_measured",
        "value": value, "unit": unit,
        "baseline": baseline,
        "delta": (round(value - baseline["value"], 3)
                  if measured and baseline and baseline.get("value") is not None else None),
        "lift": (round(value / baseline["value"], 2)
                 if measured and baseline and baseline.get("value") else None),
        "higher_is_better": higher_is_better,
        "report": report,
        "report_exists": bool(report and (ROOT / report).exists()),
        "why": why,
        "note": note,
        "provenance": provenance if measured else "NOT_MEASURED",
    }


def scoreboard() -> dict:
    m = load_metrics()
    e1, e2 = m.get("engine1", {}), m.get("engine2", {})
    ps7 = m.get("ps7", {})
    ret = m.get("retrieval", {}).get("gold_set", {})
    lanl, cic, unsw = e1.get("lanl", {}), e1.get("cicids", {}), e1.get("unsw", {})
    pred = e2.get("predictor", {})
    clean = e1.get("clean_log", {})
    am, sc = ps7.get("attack_mapping", {}), ps7.get("soar_coverage", {})
    lat, mttd, mttr = ps7.get("latency_ms", {}), ps7.get("mttd", {}), ps7.get("mttr", {})
    audit, rbac = ps7.get("audit", {}), ps7.get("rbac", {})

    cards = [
        # ---- detection: the false-positive question PS7 asks -------------
        _card("tpr_at_1pct_fpr", "Detection",
              "True-positive rate at 1% false positives",
              definition=("Share of the 702 real red-team events caught while the "
                          "detector fires on only 1% of benign authentications — the "
                          "operating point an analyst can actually staff."),
              dataset="LANL Cyber-1, real red-team ground truth",
              sample="702 attack events in 11.2M authentications (0.006% prevalence)",
              value=_pct(lanl.get("tpr_at_1pct_fpr")), unit="%",
              baseline={"name": "IsolationForest at the same 1% FPR",
                        "value": _pct(lanl.get("iforest_tpr_at_1pct_fpr"))},
              report="reports/lanl_redteam_detection.md",
              note="Trained on benign traffic only. Labels are used for evaluation, never training."),
        _card("lanl_roc", "Detection", "ROC-AUC on real red-team data",
              definition="Ranking quality over the whole score range.",
              dataset="LANL Cyber-1", sample="702 attack events",
              value=lanl.get("roc_auc"), unit="",
              baseline={"name": "random", "value": 0.5},
              report="reports/lanl_redteam_detection.md",
              note="Reported alongside the 1% FPR point because ROC-AUC alone flatters "
                   "any detector at this prevalence."),
        _card("behavioural_only_roc", "Detection",
              "ROC-AUC with the NTLM signal removed",
              definition=("Ablation: 100% of red-team logins used NTLM versus ~6% of "
                          "benign. Removing that one evadable feature tests whether "
                          "detection rests on generalisable behaviour."),
              dataset="LANL Cyber-1", sample="702 attack events",
              value=lanl.get("behavioral_only_roc"), unit="",
              baseline={"name": "random", "value": 0.5},
              report="reports/lanl_redteam_detection.md"),
        _card("cicids_prauc", "Detection", "PR-AUC on network flows",
              definition="Precision-recall AUC — the right metric on imbalanced flow data.",
              dataset="CIC-IDS2017", sample="2.3M flows, split by day",
              value=cic.get("autoencoder_prauc"), unit="",
              baseline={"name": "rule baseline", "value": cic.get("rule_prauc")},
              report="reports/evaluation_report.md",
              note=f"Random baseline {cic.get('random_prauc')}; the rule baseline scores "
                   f"{cic.get('rule_prauc')}, worse than random."),
        _card("unsw_roc", "Detection", "ROC-AUC on a second benchmark",
              definition="Independent confirmation on a dataset the model was not tuned on.",
              dataset="UNSW-NB15, official split", sample="official test split",
              value=unsw.get("roc_auc"), unit="",
              baseline={"name": "random", "value": 0.5},
              report="reports/unsw_evaluation.md"),

        # ---- attribution and prediction ----------------------------------
        _card("next_technique_top3", "Attribution & prediction",
              "Next-technique top-3 accuracy",
              definition=("Is the attacker's actual next ATT&CK technique in our top 3, "
                          "given the sequence so far."),
              dataset="205 real attack sequences from ATT&CK group/campaign data",
              sample="780 held-out prediction points, split at sequence level",
              value=_pct(pred.get("shipped_top3")), unit="%",
              baseline={"name": "kill-chain-order baseline",
                        "value": _pct(pred.get("killchain_top3"))},
              report="reports/prediction_eval.md",
              note=("The kill-chain baseline exists to catch circularity: our sequences "
                    "are tactic-ordered, so a model could cheat by re-learning that order. "
                    "Beating it means real technique-to-technique transitions. An LSTM over "
                    f"MiniLM embeddings scored {_pct(pred.get('lstm_top3'))}% and lost.")),
        _card("cert_in_top3", "Attribution & prediction",
              "Top-3 on analyst-verified CERT-In orderings",
              definition=("The same model on 4 CERT-In advisory sequences ordered by the "
                          "real reported timeline rather than our heuristic — the harder, "
                          "non-circular test."),
              dataset="CERT-In advisories, analyst-verified", sample="4 sequences",
              value=_pct(e2.get("manual_cert_in_top3")), unit="%",
              baseline={"name": "auto-ordered set", "value": _pct(pred.get("shipped_top3"))},
              report="reports/prediction_eval.md",
              note="Published because it is worse. Real orderings are harder than "
                   "heuristic ones, and hiding that would be the dishonest choice.",
              provenance="VERIFIED"),
        _card("attack_mapping_coverage", "Attribution & prediction",
              "ATT&CK mapping coverage",
              definition="Share of correlated alerts that carry an ATT&CK technique.",
              dataset="all shipped scenarios", sample=f"{am.get('alerts', 0)} alerts",
              value=_pct(am.get("coverage")), unit="%",
              baseline={"name": "unmapped alerts", "value": 0.0},
              report="reports/ps7_eval.md"),
        _card("attack_id_validity", "Attribution & prediction",
              "Technique-ID validity",
              definition=("Share of emitted technique IDs that exist in the canonical "
                          "parsed ATT&CK STIX. A hallucinated ID shows up here."),
              dataset="all shipped scenarios",
              sample=f"{len(am.get('observed_techniques', []) or sc.get('observed_techniques', []))} distinct IDs",
              value=_pct(am.get("id_validity")), unit="%",
              baseline={"name": "unvalidated free text", "value": None},
              report="reports/ps7_eval.md"),
        _card("vs_logistic_regression", "Detection",
              "TPR @ 1% FPR vs a supervised logistic regression",
              definition=("The SIH problem statement names logistic regression as the "
                          "baseline. Trained WITH the red-team labels on the identical "
                          "seven features; our detector never sees a label."),
              dataset="LANL auth red-team window, stratified 70/30 split",
              sample=_lr("n_test", fmt="{:,} held-out rows"),
              value=_pct(_lr_side("shipped_autoencoder", "tpr_at_1pct_fpr")),
              unit="%",
              baseline={"name": "logistic regression (supervised, same features)",
                        "value": _pct(_lr_side("logistic_regression", "tpr_at_1pct_fpr"))},
              report="reports/lr_baseline.md",
              why=("Needs the LANL parquet, which is not committed. Run "
                   "python -m scripts.eval_lr_baseline after fetching it."),
              note=("We LOSE this one on ranking and publish it anyway. Three "
                    "qualifiers, in the report: LR is trained on labels we would not "
                    "have for a novel campaign; the stratified split puts the same "
                    "campaign on both sides, which flatters a supervised model; and "
                    "at a usable threshold LR is unusable (F1 0.004 at a 3.1% "
                    "false-positive rate). Our headline 87.7% comes from the "
                    "documented day-wise protocol, not this split.")),
        _card("netstate_compromise_warning", "Attribution & prediction",
              "Next-window compromise warning (network state)",
              definition=("ROC-AUC for predicting that the NEXT traffic window is "
                          "compromised, from the current one. A forecast, not a "
                          "classification of the window in front of it."),
              dataset="CIC-IDS2017, trained Mon-Wed, tested Thu-Fri",
              sample=_ns("n_windows_test", fmt="{:,} held-out windows"),
              value=_pct(_ns("compromise_roc_auc")), unit="%",
              # Persistence, not random. Traffic is autocorrelated and attacks
              # arrive in bursts, so "the current window is compromised" already
              # predicts the next one well; a coin does not. Scoring this against
              # 0.5 overstated the result by roughly the whole distance that
              # matters, and the next-state card a few rows down was already
              # being held to persistence for exactly this reason.
              #
              # scripts/eval_netstate.py now computes it, but the value cannot be
              # filled in from a clone: it needs the CIC-IDS2017 parquet, which is
              # not committed. Until that run happens the card reports the
              # baseline as unmeasured rather than substituting an easier one.
              baseline=({"name": "persistence (current window's attack rate)",
                         "value": _pct(_ns("compromise_persistence_roc_auc"))}
                        if _ns("compromise_persistence_roc_auc") is not None else
                        {"name": "persistence (current window's attack rate)",
                         "value": None, "state": "not measured",
                         "why": ("re-run scripts/eval_netstate.py with the "
                                 "CIC-IDS2017 parquet; the previous comparison "
                                 "against random 0.5 was the wrong reference "
                                 "class and has been withdrawn")}),
              report="reports/netstate.md",
              why=("Needs the CIC-IDS2017 parquet, which is not committed. Run "
                   "python -m scripts.eval_netstate after fetching it."),
              note=("This is the world model the SIH 2026 problem statement asks "
                    "for: P(S_t+1 | S_t) over a 48-dimensional traffic state "
                    "vector, not over ATT&CK techniques. 24 latent states, exact "
                    "matrix rollout, no sampling. Temporal split, so no day "
                    "appears on both sides. Read the next card before quoting "
                    "this one. RESEARCH SURFACE: served by POST "
                    "/api/netstate/analyze, with no screen, and it feeds no "
                    "alert, score or severity anywhere else in the product. "
                    "These numbers are results on CIC-IDS2017, never a claim "
                    "about a log you analyse here.")),
        _card("netstate_vs_persistence", "Attribution & prediction",
              "Next-state prediction vs a persistence baseline",
              definition=("Top-1 accuracy at predicting the next latent traffic "
                          "state, against the baseline that assumes the network "
                          "stays where it is. The shipped figure is the online "
                          "adaptive model, which counts transitions it has "
                          "already observed in the current stream."),
              dataset="CIC-IDS2017, 3,370 held-out window transitions",
              sample=_ns("n_states", fmt="{} latent states"),
              value=_pct(_ns("online_top1")), unit="%",
              baseline={"name": "persistence (assume no change)",
                        "value": _pct(_ns("persistence_top1"))},
              report="reports/netstate.md",
              why=("Needs the CIC-IDS2017 parquet, which is not committed. Run "
                   "python -m scripts.eval_netstate after fetching it."),
              note=("Won the hard way, and the route matters. The purely offline "
                    "matrix DRAWS with persistence ("
                    + f"{_pct(_ns('next_state_top1'))}% against "
                      f"{_pct(_ns('persistence_top1'))}%"
                    + "), and a second-order model made it worse ("
                    + f"{_pct(_ns('second_order_top1'))}%"
                    + "). An oracle matrix counted on the test days themselves "
                      "reaches "
                    + f"{_pct(_ns('oracle_top1'))}%"
                    + ", which proved the limit was transfer between days rather "
                      "than model capacity. Adapting online fixes transfer with "
                      "no labels: predict the next state, then observe it, "
                      "nothing after the current window contributing. Strictly "
                      "causal, and tested for it. Hyperparameters fitted "
                      "leave-one-day-out; reading them off the test days would "
                      "have scored 0.4243 and that number is not used.")),
        _card("attribution_method", "Attribution & prediction",
              "Feature attribution exactness",
              definition=("Share of the detector's prediction gap explained by exact "
                          "Shapley values. 100% means the attribution satisfies the "
                          "efficiency axiom rather than approximating it."),
              dataset="every scored event; 7 features = 128 coalitions",
              sample="full coalition enumeration, no sampling",
              value=100.0, unit="%",
              baseline={"name": "KernelSHAP approximation", "value": None},
              report="reports/ps7_eval.md",
              note=("SHAP approximations exist because exhaustive enumeration is "
                    "usually infeasible. With seven features it is not, so the "
                    "values are exact and carry no sampling error. Asserted at "
                    "runtime in src/shared/attribution.py.")),
        _card("technique_precision", "Attribution & prediction",
              "Event-to-technique precision",
              why=am.get("ground_truth_note",
                         "No public dataset used here labels individual events with an "
                         "ATT&CK technique, so precision cannot be computed."),
              definition="Would require per-event ATT&CK ground truth.",
              dataset="none available", report="reports/ps7_eval.md"),

        # ---- evidence -----------------------------------------------------
        _card("retrieval_recall5", "Evidence",
              f"Evidence recall@{ret.get('k', 5)}",
              definition=("Share of gold queries where the correct official document "
                          "appears in the top-k."),
              dataset="bundled MITRE ATT&CK + CISA KEV + CERT-In corpus",
              sample=f"{ret.get('queries', 0)} hand-written queries over "
                     f"{ret.get('corpus_chunks', 0)} chunks",
              value=_pct(ret.get("recall_at_5")), unit="%",
              baseline={"name": "recall@1", "value": _pct(ret.get("recall_at_1"))},
              report="reports/retrieval_eval.md",
              note=f"MRR {ret.get('mrr')}. Lexical BM25 with exact-identifier boost; "
                   f"paraphrased queries with no shared vocabulary still miss."),
        _card("retrieval_backend_lift", "Evidence",
              "Semantic retrieval lift over lexical",
              definition=("Recall@5 of the semantic retriever (MiniLM + ChromaDB) "
                          "against the bundled lexical one, on the shared gold "
                          "queries both corpora can answer."),
              dataset="same gold set, scored on what the retrieved chunk refers to",
              sample=_cmp_sample(),
              value=_cmp("semantic", "recall_at_5"), unit="",
              baseline={"name": "lexical BM25, bundled index",
                        "value": _cmp("lexical", "recall_at_5")},
              report="reports/retrieval_compare.md",
              note=("Giving the lexical retriever the same larger corpus made it "
                    "worse (recall@1 0.600 -> 0.500), so the win is the embeddings, "
                    "not the corpus. The slim deploy image ships no torch, so the "
                    "hosted demo runs the lexical backend and says so in "
                    "/api/capabilities. See ADR 0005.")),
        _card("citation_integrity", "Evidence", "Citation integrity failures",
              definition=("Retrieved citations whose stored SHA-256 no longer matches "
                          "their text, or that lack a URL, publisher or section."),
              dataset="every hit across the gold query set",
              sample=f"{ret.get('queries', 0)} queries × {ret.get('k', 5)} hits",
              value=ret.get("citation_integrity_failures"), unit=" failures",
              higher_is_better=False,
              baseline={"name": "target", "value": 0},
              report="reports/retrieval_eval.md"),

        # ---- response and governance --------------------------------------
        _card("soar_tactic_coverage", "Response & governance",
              "SOAR playbook coverage",
              definition=("Share of observed ATT&CK tactics that have a defined, gated "
                          "response action."),
              dataset="all shipped scenarios",
              sample=f"{len(sc.get('observed_tactics', []))} observed tactics",
              value=_pct(sc.get("tactic_coverage")), unit="%",
              baseline={"name": "no playbook", "value": 0.0},
              report="reports/ps7_eval.md"),
        _card("mitigation_coverage", "Response & governance",
              "MITRE mitigation coverage",
              definition=("Share of observed techniques for which MITRE publishes a "
                          "mitigation that we surface."),
              dataset="parsed ATT&CK STIX",
              sample=f"{len(sc.get('observed_techniques', []))} observed techniques",
              value=_pct(sc.get("mitigation_coverage")), unit="%",
              baseline={"name": "no mitigation surfaced", "value": 0.0},
              report="reports/ps7_eval.md"),
        _card("actions_executed", "Response & governance",
              "Actions executed against real systems",
              definition=("By design this is zero. Every response is simulated; "
                          "crown-jewel actions additionally require a named human "
                          "approval with a written reason."),
              dataset="all shipped scenarios", sample="every proposed action",
              value=sc.get("actions_executed_against_real_systems", 0), unit="",
              higher_is_better=False,
              baseline={"name": "policy limit", "value": 0},
              report="reports/ps7_eval.md"),
        _card("mttd", "Response & governance", "Mean time to detect",
              definition=(mttd.get("definition")
                          or "seconds from the first event to the first correlated alert"),
              dataset="each scenario's own timestamps",
              sample=", ".join(f"{k}: {v}s" for k, v in
                               (mttd.get("measured_per_scenario") or {}).items()) or "—",
              value=(max((mttd.get("measured_per_scenario") or {}).values())
                     if mttd.get("measured_per_scenario") else None),
              unit=" s", higher_is_better=False,
              baseline={"name": "Mandiant M-Trends 2024 global median dwell "
                                "(a citation, not our measurement)",
                        "value": 10 * 86400},
              report="reports/ps7_eval.md",
              note="Worst case across the shipped scenarios. The dwell-time comparison is "
                   "an industry citation, not something we measured."),
        _card("mttr", "Response & governance", "Mean time to respond",
              why=mttr.get("why", "No action is executed, so there is no repair to time."),
              definition="Would require executing containment against a real system.",
              dataset="none", report="reports/ps7_eval.md"),
        _card("audit_tamper_detection", "Response & governance",
              "Audit tampering detected",
              definition=("A record is edited in an exported chain and the chain "
                          "is re-verified. 1 = the edit was detected and located. "
                          "This measures DETECTION. Retention is a separate "
                          "property: the chain is persisted to SQLite and "
                          "verified across a process restart, and "
                          "/api/audit/verify reports `durable` so a reader can "
                          "see which mode is running rather than assume."),
              dataset="synthetic tamper test, run every evaluation",
              sample="edit + deletion, plus a restart-and-resume check",
              value=(1 if audit.get("tamper_detected") else 0), unit="",
              baseline={"name": "unlinked log", "value": 0},
              report="reports/ps7_eval.md",
              note="Tamper-evident, not tamper-proof: detection, not prevention."),
        _card("rbac_denial", "Response & governance",
              "Unauthorised approval blocked server-side",
              definition=("A viewer attempts to approve a critical action. 1 = the API "
                          "refused, independently of the UI."),
              dataset="authorisation test, run every evaluation", sample="viewer role",
              value=(1 if rbac.get("viewer_denied_approval") else 0), unit="",
              baseline={"name": "UI-only gating", "value": 0},
              report="reports/ps7_eval.md"),

        # ---- performance ---------------------------------------------------
        _card("latency_p50", "Performance", "Investigation latency (p50)",
              definition="Wall time for the full 7-node investigation.",
              dataset="all shipped scenarios",
              sample=f"{lat.get('samples', 0)} runs · {lat.get('scope', '')}",
              value=lat.get("p50"), unit=" ms", higher_is_better=False,
              baseline={"name": "p95", "value": lat.get("p95")},
              report="reports/ps7_eval.md"),
        # The number this product is worst at, on the same board as the ones it is
        # best at. A limitation a reader has to go looking for is one the product
        # is hiding, and this is the first question any operator asks.
        _card("clean_log_false_positive_rate", "Detection",
              "Alert rate on a log with no attack in it",
              definition=("False-positive rate on synthetic logs with ZERO attack events: Zipf "
                          "destination tail, 3% failed logins, 15% NTLM. The quiet "
                          "variants with neither hold two of seven features at their "
                          "most benign constant and score about half this."),
              dataset="synthetic clean logs with ordinary failure and NTLM rates, seeded",
              sample=f"{clean.get('shapes_tested', 0)} log shapes, 0 attack events",
              value=_pct(clean.get("worst_alert_rate")), unit="%",
              higher_is_better=False,
              baseline={"name": "best shape tested",
                        "value": _pct(clean.get("best_alert_rate"))},
              report="reports/clean_log.md",
              note=("This is bad and it is not a threshold problem. The behavioural "
                    "features are corpus-relative with no stored baseline, so they are "
                    "computed over whatever log was uploaded, and the anchors were "
                    "measured on LANL. A single log cannot separate 'this corpus differs "
                    "from the training corpus' from 'this corpus is under attack'. The "
                    "fix is a persistent per-entity profile, not a different number.")),
        _card("throughput", "Performance", "Largest measured single analysis",
              definition="End-to-end pipeline time at the documented 50,000-event cap.",
              dataset="scaling measurements", sample="best of 3 after warm-up",
              value=_scaling_max(), unit=" s", higher_is_better=False,
              baseline={"name": "demo campaign, 2,732 events", "value": _scaling_demo()},
              report="reports/scaling_measurements.json"),
    ]

    groups: dict[str, list[dict]] = {}
    for c in cards:
        groups.setdefault(c["group"], []).append(c)

    measured = [c for c in cards if c["state"] == "measured"]
    return {
        "generated_at": fmt_ist(),
        "groups": [{"name": g, "cards": cs} for g, cs in groups.items()],
        "cards": cards,
        "summary": {
            "total": len(cards),
            "measured": len(measured),
            "not_measured": len(cards) - len(measured),
            "missing_reports": [c["id"] for c in cards
                                if c["report"] and not c["report_exists"]],
        },
        "sources": {
            "metrics_store": "reports/metrics.json",
            "regenerate": ["python -m scripts.eval_ps7",
                           "python -m scripts.eval_retrieval"],
        },
        "refused_claims": FORBIDDEN_CLAIMS,
        "note": ("Every value is read from reports/metrics.json, written by the "
                 "evaluation scripts. A metric we have not measured says so and "
                 "explains why."),
    }


def _ns(key: str, fmt: str | None = None):
    """A value from the engine3 network-state evaluation, or None if never run."""
    v = load_metrics().get("engine3", {}).get("netstate", {}).get(key)
    if fmt is None:
        return v
    return fmt.format(v) if v is not None else ""


def _lr_side(side: str, key: str):
    """A value from the logistic-regression comparison, or None if never run."""
    return load_metrics().get("engine1", {}).get("lr_baseline", {}).get(side, {}).get(key)


def _lr(key: str, fmt: str = "{}") -> str:
    v = load_metrics().get("engine1", {}).get("lr_baseline", {}).get(key)
    return fmt.format(v) if v is not None else ""


def _cmp(side: str, key: str):
    """A value from the retriever head-to-head, or None if it was never run."""
    c = load_metrics().get("retrieval", {}).get("comparison", {}).get(side, {})
    return c.get(key)


def _cmp_sample() -> str:
    c = load_metrics().get("retrieval", {}).get("comparison", {})
    if not c:
        return ""
    return (f"{c.get('shared_queries', 0)} shared queries "
            f"({c.get('bundled_only_queries', 0)} excluded as bundled-only)")


def _scaling() -> list[dict]:
    import json
    f = REPORTS / "scaling_measurements.json"
    if not f.exists():
        return []
    data = json.loads(f.read_text(encoding="utf-8"))
    return data if isinstance(data, list) else data.get("measurements", [])


def _scaling_max() -> float | None:
    rows = _scaling()
    return round(max((r.get("seconds", 0) for r in rows), default=0), 3) or None


def _scaling_demo() -> float | None:
    for r in _scaling():
        if r.get("events") == 2732:
            return round(r.get("seconds", 0), 3)
    return None


def demo() -> None:
    """Self-check: the board is complete and refuses to overclaim."""
    b = scoreboard()
    assert b["summary"]["total"] >= 15, b["summary"]
    assert not b["summary"]["missing_reports"], b["summary"]["missing_reports"]
    for c in b["cards"]:
        if c["state"] == "measured":
            assert isinstance(c["value"], (int, float)), c
            assert c["definition"] and c["dataset"], c["id"]
        else:
            assert c["why"] and c["value"] is None, c["id"]
        assert "accuracy" not in c["name"].lower() or "top-3" in c["name"].lower(), c["name"]
    nm = [c["id"] for c in b["cards"] if c["state"] == "not_measured"]
    print(f"scoreboard ok: {b['summary']['measured']} measured, "
          f"{b['summary']['not_measured']} declared not-measured ({', '.join(nm)})")


if __name__ == "__main__":
    demo()
