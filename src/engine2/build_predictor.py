"""
Milestone 3 · Task E2.4 — ATT&CK technique-association ranker.

Given observed ATT&CK techniques, rank techniques associated with them in ATT&CK
group/campaign profiles. Most rows are sorted by a tactic heuristic, not observed
chronology, so this build fails closed on next-move claims unless an independent
report-ordered benchmark demonstrates an improvement over temporal baselines.

⚠️ Anti-circularity (see decision_memo / final_pipeline E2.4):
  Sequences are ordered by kill-chain tactic order (a heuristic). A model could
  score a held-out profile position by just re-learning that ordering. So we include a
  **kill-chain-order baseline** measures how much of the profile-position task can
  be recovered from the imposed ordering. Beating it does not turn a profile into
  an observed timeline.

Baselines:
  most_frequent  — always predict globally most-common techniques (context-free)
  markov         — first-order transition P(next | last technique), backoff to freq
  killchain      — most-frequent train techniques in the NEXT kill-chain tactic
Model:
  lstm           — LSTM over frozen MiniLM technique embeddings -> softmax over vocab

Metric: top-1 / top-3 / top-5 accuracy over held-out test sequences' positions.

Run (needs E2.3 embeddings first):
    ./.venv/Scripts/python.exe -m src.engine2.build_predictor
"""
from __future__ import annotations

import json
import pickle
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
E2 = ROOT / "data" / "processed" / "engine2"
SEQS = E2 / "sequences.json"
EMB = E2 / "technique_embeddings.pkl"
LOOKUPS = ROOT / "data" / "processed" / "mitre_attack" / "attack_lookups.pkl"
REPORT = ROOT / "reports" / "prediction_eval.md"
MODEL_OUT = ROOT / "models" / "next_technique_lstm.pt"

KS = (1, 3, 5)
SEED = 42


# --------------------------------------------------------------------------- #
# Data                                                                        #
# --------------------------------------------------------------------------- #
def load():
    seqs = json.loads(SEQS.read_text(encoding="utf-8"))
    with EMB.open("rb") as f:
        emb = pickle.load(f)
    with LOOKUPS.open("rb") as f:
        lk = pickle.load(f)
    train = [s["ordered_technique_ids"] for s in seqs if s["split"] == "train"]
    val = [s["ordered_technique_ids"] for s in seqs if s["split"] == "val"]
    test = [s["ordered_technique_ids"] for s in seqs if s["split"] == "test"]
    # manual (report-ordered CERT-In) sequences — the non-circular test subset
    manual = [s["ordered_technique_ids"] for s in seqs if s.get("is_manual")]
    return train, val, test, manual, emb, lk


def positions(seqs):
    """Yield (prefix_last_technique, full_prefix, true_next) for each step."""
    for s in seqs:
        for i in range(1, len(s)):
            yield s[i - 1], s[:i], s[i]


# --------------------------------------------------------------------------- #
# Baselines                                                                    #
# --------------------------------------------------------------------------- #
def baseline_most_frequent(train, vocab):
    freq = Counter(t for s in train for t in s)
    ranked = [t for t, _ in freq.most_common()]
    return lambda last, prefix: ranked


def baseline_markov(train, vocab):
    trans = defaultdict(Counter)
    freq = Counter(t for s in train for t in s)
    backoff = [t for t, _ in freq.most_common()]
    for s in train:
        for i in range(1, len(s)):
            trans[s[i - 1]][s[i]] += 1

    def predict(last, prefix):
        if last in trans and trans[last]:
            ranked = [t for t, _ in trans[last].most_common()]
            seen = set(ranked)
            return ranked + [t for t in backoff if t not in seen]
        return backoff
    return predict


def baseline_killchain(train, vocab, lk):
    order = lk["tactics_order"]
    tac = lk["technique_to_tactics"]
    freq = Counter(t for s in train for t in s)
    backoff = [t for t, _ in freq.most_common()]
    # most-frequent train techniques bucketed by their (earliest) tactic
    by_tactic = defaultdict(list)
    for t, _ in freq.most_common():
        idxs = [order.index(x) for x in tac.get(t, []) if x in order]
        if idxs:
            by_tactic[min(idxs)].append(t)

    def predict(last, prefix):
        idxs = [order.index(x) for x in tac.get(last, []) if x in order]
        cur = min(idxs) if idxs else -1
        ranked = []
        for nxt in range(cur + 1, len(order)):     # techniques in later tactics
            ranked.extend(by_tactic.get(nxt, []))
        seen = set(ranked)
        return ranked + [t for t in backoff if t not in seen]
    return predict


def eval_ranker(predict, test, vocab_set):
    hits = {k: 0 for k in KS}
    n = oov = 0
    for last, prefix, nxt in positions(test):
        n += 1
        if nxt not in vocab_set:
            oov += 1
            continue                     # unpredictable — counts as miss in denom
        ranked = [t for t in predict(last, prefix) if t in vocab_set]
        for k in KS:
            if nxt in ranked[:k]:
                hits[k] += 1
    return {k: hits[k] / n for k in KS}, n, oov


def chronological_gate(model_predict, baselines: dict, timelines, vocab_set,
                       *, reps: int = 2000) -> dict:
    """Gate chronological claims with a sequence-level paired bootstrap.

    The benchmark is independent of training, but only four source-provenanced
    CERT-In timelines currently exist. Resampling whole timelines keeps within-
    incident positions together and exposes the uncertainty that point-level
    accuracy hides.
    """
    def counts(predict, seq):
        hits = n = oov = 0
        for last, prefix, nxt in positions([seq]):
            n += 1
            if nxt not in vocab_set:
                oov += 1
                continue
            ranked = [t for t in predict(last, prefix) if t in vocab_set]
            hits += int(nxt in ranked[:3])
        return hits, n, oov

    model_rows = [counts(model_predict, seq) for seq in timelines]
    baseline_rows = {
        name: [counts(predict, seq) for seq in timelines]
        for name, predict in baselines.items()
    }
    total_n = sum(row[1] for row in model_rows)
    model_top3 = sum(row[0] for row in model_rows) / max(total_n, 1)
    baseline_top3 = {
        name: sum(row[0] for row in rows) / max(total_n, 1)
        for name, rows in baseline_rows.items()
    }
    strongest = max(baseline_top3, key=baseline_top3.get) if baseline_top3 else "none"
    strongest_rows = baseline_rows.get(strongest, [])

    diffs = []
    if timelines and strongest_rows:
        rng = np.random.default_rng(SEED)
        for _ in range(reps):
            sample = rng.integers(0, len(timelines), size=len(timelines))
            n = sum(model_rows[i][1] for i in sample) or 1
            model_hits = sum(model_rows[i][0] for i in sample)
            baseline_hits = sum(strongest_rows[i][0] for i in sample)
            diffs.append((model_hits - baseline_hits) / n)
    ci = (np.percentile(diffs, [2.5, 97.5]).tolist() if diffs else [0.0, 0.0])
    gain = model_top3 - baseline_top3.get(strongest, 0.0)
    enabled = bool(timelines and gain > 0 and ci[0] > 0)
    reason = (
        "Independent chronological validation beats the strongest temporal baseline "
        "with a positive sequence-bootstrap lower bound."
        if enabled else
        "Chronological next-move prediction is disabled: the source-provenanced "
        "timeline benchmark does not yet show a statistically reliable improvement "
        "over the strongest baseline."
    )
    return {
        "enabled": enabled,
        "mode": "chronological-next-move" if enabled else "association-only",
        "reason": reason,
        "data_basis": {
            "kind": "ATT&CK group/campaign technique profiles",
            "ordering": "heuristic MITRE ATT&CK tactic order",
            "observed_timeline": False,
        },
        "benchmark": {
            "kind": "source-provenanced report-ordered CERT-In timelines",
            "independent_of_training": True,
            "sequences": len(timelines),
            "prediction_points": total_n,
            "oov": sum(row[2] for row in model_rows),
            "model_top3": round(model_top3, 4),
            "baselines_top3": {k: round(v, 4) for k, v in baseline_top3.items()},
            "strongest_baseline": strongest,
            "gain_over_strongest": round(gain, 4),
            "gain_sequence_bootstrap_95": [round(float(x), 4) for x in ci],
            "bootstrap_repetitions": reps,
        },
    }


# --------------------------------------------------------------------------- #
# Neural (LSTM over frozen embeddings)                                         #
# --------------------------------------------------------------------------- #
def train_lstm(train, val, emb, vocab, idx):
    import torch
    import torch.nn as nn

    torch.manual_seed(SEED)
    dim = len(next(iter(emb.values())))
    V = len(vocab)

    def emb_of(t):
        return emb[t] if t in emb else np.zeros(dim, dtype="float32")

    class Net(nn.Module):
        def __init__(self):
            super().__init__()
            self.lstm = nn.LSTM(dim, 128, batch_first=True)
            self.drop = nn.Dropout(0.3)
            self.out = nn.Linear(128, V)

        def forward(self, x):
            h, _ = self.lstm(x)
            return self.out(self.drop(h))

    net = Net()
    opt = torch.optim.Adam(net.parameters(), lr=1e-3, weight_decay=1e-4)
    lossf = nn.CrossEntropyLoss(ignore_index=-1)

    def batches(seqs):
        for s in seqs:
            if len(s) < 2:
                continue
            X = torch.tensor(np.stack([emb_of(t) for t in s[:-1]])[None], dtype=torch.float32)
            y = torch.tensor([[idx.get(t, -1) for t in s[1:]]], dtype=torch.long)
            yield X, y

    best_val, best_state, patience = -1.0, None, 0
    for epoch in range(60):
        net.train()
        for X, y in batches(train):
            opt.zero_grad()
            logits = net(X).reshape(-1, V)
            loss = lossf(logits, y.reshape(-1))
            loss.backward()
            opt.step()
        # validate: top-3 accuracy
        vacc = lstm_topk(net, val, emb_of, dim, set(vocab), idx)[3]
        if vacc > best_val:
            best_val, best_state, patience = vacc, {k: v.clone() for k, v in net.state_dict().items()}, 0
        else:
            patience += 1
            if patience >= 10:
                break
    if best_state:
        net.load_state_dict(best_state)
    return net, emb_of, dim


def lstm_topk(net, seqs, emb_of, dim, vocab_set, idx):
    import torch
    inv = {v: k for k, v in idx.items()}
    net.eval()
    hits = {k: 0 for k in KS}
    n = 0
    with torch.no_grad():
        for s in seqs:
            for i in range(1, len(s)):
                n += 1
                if s[i] not in vocab_set:
                    continue
                X = torch.tensor(np.stack([emb_of(t) for t in s[:i]])[None], dtype=torch.float32)
                logits = net(X)[0, -1]
                topk = torch.topk(logits, max(KS)).indices.tolist()
                ranked = [inv[j] for j in topk]
                for k in KS:
                    if s[i] in ranked[:k]:
                        hits[k] += 1
    return {k: hits[k] / max(n, 1) for k in KS}


# --------------------------------------------------------------------------- #
# Main                                                                         #
# --------------------------------------------------------------------------- #
def baseline_markov_interp(train, val, vocab):
    """Interpolated Markov — the SHIPPED predictor.

    Blends second-order, first-order and unigram estimates:
        P = l2*P(next|prev,last) + l1*P(next|last) + l0*P(next)
    with the weights chosen on the validation split. On a small corpus a pure
    second-order model is sharp when it has seen the exact bigram and useless
    when it has not; interpolation keeps the higher-order signal without
    collapsing to zero on unseen context.
    """
    t2, t1 = defaultdict(Counter), defaultdict(Counter)
    uni = Counter(t for s in train for t in s)
    n_uni = sum(uni.values()) or 1
    for s in train:
        for i in range(1, len(s)):
            t1[s[i - 1]][s[i]] += 1
            if i >= 2:
                t2[(s[i - 2], s[i - 1])][s[i]] += 1

    def make(l2, l1, l0):
        def predict(last, prefix):
            a = prefix[-2] if len(prefix) >= 2 else None
            b = prefix[-1] if prefix else last
            d2 = t2.get((a, b)) if a is not None else None
            d1 = t1.get(b)
            n2 = sum(d2.values()) if d2 else 1
            n1 = sum(d1.values()) if d1 else 1
            scored = []
            for c in vocab:
                p = l0 * (uni.get(c, 0) / n_uni)
                if d1:
                    p += l1 * (d1.get(c, 0) / n1)
                if d2:
                    p += l2 * (d2.get(c, 0) / n2)
                if p > 0:
                    scored.append((p, c))
            scored.sort(reverse=True)
            return [c for _, c in scored]
        return predict

    grid = [(a, b, round(1 - a - b, 2))
            for a in (0.2, 0.4, 0.6, 0.8) for b in (0.1, 0.3, 0.5)
            if 0.0 < 1 - a - b < 1.0]
    vs = set(vocab)
    best_w, best_v = (0.2, 0.3, 0.5), -1.0
    for w in grid:
        r, _, _ = eval_ranker(make(*w), val, vs)
        if r[3] > best_v:
            best_v, best_w = r[3], w
    return make(*best_w), best_w, (t2, t1, uni)


def save_markov(train, path, lambdas=(0.2, 0.3, 0.5), tables=None,
                *, temporal_validation: dict | None = None):
    """Persist the interpolated profile-association model.

    Stores [technique, count] pairs plus the fail-closed temporal claim gate.
    Read by src/shared/predictor.py at runtime.
    """
    if tables is None:
        t2, t1 = defaultdict(Counter), defaultdict(Counter)
        uni = Counter(t for s in train for t in s)
        for s in train:
            for i in range(1, len(s)):
                t1[s[i - 1]][s[i]] += 1
                if i >= 2:
                    t2[(s[i - 2], s[i - 1])][s[i]] += 1
    else:
        t2, t1, uni = tables
    payload = {
        "version": 3,
        "order2": {k: [[t, int(n)] for t, n in c.most_common()] for k, c in t2.items()},
        "order1": {k: [[t, int(n)] for t, n in c.most_common()] for k, c in t1.items()},
        "unigram": [[t, int(n)] for t, n in uni.most_common()],
        "lambdas": list(lambdas),
        "task": "attack-technique-association-ranking",
        "temporal_validation": temporal_validation or {
            "enabled": False,
            "mode": "association-only",
            "reason": "No independent chronological validation was supplied at build time.",
        },
    }
    with path.open("wb") as f:
        pickle.dump(payload, f)


def main() -> None:
    import sys
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    MODEL_OUT.parent.mkdir(parents=True, exist_ok=True)

    train, val, test, manual, emb, lk = load()
    vocab = sorted({t for s in train for t in s})
    vocab_set = set(vocab)
    idx = {t: i for i, t in enumerate(vocab)}
    print(f"train {len(train)} / val {len(val)} / test {len(test)} "
          f"(manual {len(manual)}) sequences · vocab {len(vocab)}")

    results = {}
    frequency_predict = baseline_most_frequent(train, vocab)
    killchain_predict = baseline_killchain(train, vocab, lk)
    markov_predict = baseline_markov(train, vocab)
    interp_predict, interp_w, interp_tables = baseline_markov_interp(train, val, vocab)
    results["most_frequent"], n_test, oov = eval_ranker(frequency_predict, test, vocab_set)
    results["markov"], _, _ = eval_ranker(markov_predict, test, vocab_set)
    results["markov_interp"], _, _ = eval_ranker(interp_predict, test, vocab_set)
    results["killchain"], _, _ = eval_ranker(killchain_predict, test, vocab_set)

    # non-circular headline: the SHIPPED model on the manual CERT-In sequences
    manual_res = manual_n = manual_oov = None
    if manual:
        manual_res, manual_n, manual_oov = eval_ranker(interp_predict, manual, vocab_set)
    temporal_validation = chronological_gate(
        interp_predict,
        {"most_frequent": frequency_predict, "killchain_order": killchain_predict},
        manual,
        vocab_set,
    )

    print("Training LSTM ...")
    net, emb_of, dim = train_lstm(train, val, emb, vocab, idx)
    results["lstm"] = lstm_topk(net, test, emb_of, dim, vocab_set, idx)

    import torch
    torch.save({"state": net.state_dict(), "vocab": vocab, "dim": dim}, MODEL_OUT)
    save_markov(train, ROOT / "models" / "next_technique_markov.pkl",
                lambdas=interp_w, tables=interp_tables,
                temporal_validation=temporal_validation)

    # honest model selection: best method by top-3 accuracy
    best = max(results, key=lambda m: results[m][3])
    # anti-circularity is measured against the SHIPPED model
    mk_vs_kc = results["markov_interp"][3] / max(results["killchain"][3], 1e-9)
    lstm_vs_mk = results["lstm"][3] / max(results["markov"][3], 1e-9)

    # write the canonical numbers so the Metrics screen never drifts from this run
    try:
        from src.shared.metrics_store import update as _update
        _update("engine2", "predictor", {
            "most_frequent_top3": round(results["most_frequent"][3], 3),
            "killchain_top3": round(results["killchain"][3], 3),
            "lstm_top3": round(results["lstm"][3], 3),
            "markov_top3": round(results["markov"][3], 3),
            "markov_interp_top3": round(results["markov_interp"][3], 3),
            "shipped": "markov_interp",
            "shipped_top3": round(results["markov_interp"][3], 3),
            "lambdas": list(interp_w),
            "task": "ATT&CK technique-association ranking",
            "temporal_validation": temporal_validation,
            "note": f"Interpolated Markov association ranker; {mk_vs_kc:.1f}x the "
                    f"kill-chain baseline on tactic-sorted profiles does not validate chronology",
        })
        if manual_res is not None:
            _update("engine2", "manual_cert_in_top3", round(manual_res[3], 3))
    except Exception as e:                       # reporting must never break the eval
        print(f"  [metrics_store skipped: {e}]")

    lines = [
        "# Engine 2.4 — ATT&CK Technique-Association Ranker",
        "",
        f"Rank a held-out profile technique from a partial tactic-sorted profile. Test = "
        f"{n_test} prediction points across {len(test)} held-out sequences "
        f"(vocab {len(vocab)}, OOV next-techniques counted as misses: {oov}).",
        "",
        "| Method | top-1 | top-3 | top-5 |",
        "|---|---|---|---|",
    ]
    label = {"most_frequent": "Most-frequent (baseline)",
             "markov": "Markov 1st-order (previous)",
             "markov_interp": f"Markov interpolated λ={tuple(interp_w)} (SHIPPED)",
             "killchain": "Kill-chain order (baseline ⚠️)",
             "lstm": "LSTM (embeddings)"}
    for m in ["most_frequent", "markov", "markov_interp", "killchain", "lstm"]:
        r = results[m]
        lines.append(f"| {label[m]} | {r[1]*100:.1f}% | {r[3]*100:.1f}% | {r[5]*100:.1f}% |")

    lines += [
        "",
        "## Interpretation (data-driven)",
        f"- **Shipped association ranker: {label[best]}** — best profile-position top-3 ({results[best][3]*100:.1f}%) "
        + ("and the most explainable choice. On only "
           f"{len(train)} training sequences a first-order Markov transition model "
           "beats the LSTM — so we ship Markov (honest > fancy)."
           if best == "markov" else
           "on this data."),
        f"- **Profile-position comparison:** shipped ranker top-3 ({results['markov_interp'][3]*100:.1f}%) is "
        f"**{mk_vs_kc:.1f}× the kill-chain-order baseline** ({results['killchain'][3]*100:.1f}%). "
        f"The rows are ATT&CK group/campaign profiles sorted by a tactic heuristic, not "
        f"observed timelines. Beating this baseline supports **association ranking only**; "
        f"it does not establish real chronological transitions.",
        f"- **Neural is not justified here (honest negative result):** the LSTM "
        f"({results['lstm'][3]*100:.1f}% top-3) is {lstm_vs_mk:.2f}× Markov — it beats the "
        f"naive baselines but not the transition model at this data scale. Kept as a "
        f"documented comparison, not the deliverable.",
        f"- Top-1 is a hard bar with a {len(vocab)}-way vocabulary and {len(train)} "
        f"training profiles; **top-3/top-5 describe held-out profile positions**, not the "
        f"probability of an attacker making a next move.",
        "",
    ]
    if manual_res is not None:
        lines += [
            "## Independent chronological gate — CERT-In / India timelines",
            f"- Shipped Markov model on **{len(manual)} hand-curated** report-ordered "
            f"sequences ({manual_n} prediction points, {manual_oov} OOV): "
            f"**top-1 {manual_res[1]*100:.1f}% · top-3 {manual_res[3]*100:.1f}% · "
            f"top-5 {manual_res[5]*100:.1f}%**.",
            f"- Strongest baseline: **{temporal_validation['benchmark']['strongest_baseline']}**; "
            f"gain: **{temporal_validation['benchmark']['gain_over_strongest']*100:.1f} points**; "
            f"sequence-bootstrap 95% interval: "
            f"**[{temporal_validation['benchmark']['gain_sequence_bootstrap_95'][0]*100:.1f}, "
            f"{temporal_validation['benchmark']['gain_sequence_bootstrap_95'][1]*100:.1f}] points**.",
            f"- **Chronological next-move output enabled: {str(temporal_validation['enabled']).lower()}.** "
            f"{temporal_validation['reason']}",
            "",
        ]
    lines += [
        f"_Shipped: `models/next_technique_markov.pkl` · LSTM comparison: "
        f"`{MODEL_OUT.relative_to(ROOT)}` · sequences E2.2 · embeddings E2.3._",
    ]
    REPORT.write_text("\n".join(lines), encoding="utf-8")

    print("\n=== top-k accuracy (test) ===")
    print(f"{'method':<26}{'top-1':>8}{'top-3':>8}{'top-5':>8}")
    for m in ["most_frequent", "markov", "markov_interp", "killchain", "lstm"]:
        r = results[m]
        print(f"{label[m]:<26}{r[1]*100:>7.1f}%{r[3]*100:>7.1f}%{r[5]*100:>7.1f}%")
    print(f"\nShipped association ranker: {label[best]} "
          f"(profile-position top-3 {results[best][3]*100:.1f}%). "
          f"Profile comparison: Markov {mk_vs_kc:.1f}x kill-chain; "
          f"LSTM {lstm_vs_mk:.2f}x Markov. "
          f"Chronological output enabled={temporal_validation['enabled']}.")
    print(f"-> {REPORT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
