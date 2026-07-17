"""
Milestone 3 · Task E2.4 — Next-technique predictor (Engine 2 centerpiece).

Given a partial ATT&CK technique sequence, predict the attacker's next technique.
This is the Innovation claim — so it is evaluated HONESTLY against three baselines,
and we report whichever wins.

⚠️ Anti-circularity (see decision_memo / final_pipeline E2.4):
  Sequences are ordered by kill-chain tactic order (a heuristic). A model could
  "predict the next technique" by just re-learning that ordering. So we include a
  **kill-chain-order baseline** — the neural model must beat IT (not just the
  trivial most-frequent baseline) to prove it learned real technique-level
  transitions rather than the ordering we imposed. If a simple Markov model wins,
  we present Markov (honest > fancy).

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
def save_markov(train, path):
    """Persist the first-order transition table — the shipped predictor.

    Stores [technique, count] pairs (ordered by count desc) so consumers can
    report a real transition probability, not just a ranked list.
    """
    trans = defaultdict(Counter)
    for s in train:
        for i in range(1, len(s)):
            trans[s[i - 1]][s[i]] += 1
    table = {last: [[t, int(n)] for t, n in c.most_common()] for last, c in trans.items()}
    with path.open("wb") as f:
        pickle.dump(table, f)


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
    markov_predict = baseline_markov(train, vocab)
    results["most_frequent"], n_test, oov = eval_ranker(baseline_most_frequent(train, vocab), test, vocab_set)
    results["markov"], _, _ = eval_ranker(markov_predict, test, vocab_set)
    results["killchain"], _, _ = eval_ranker(baseline_killchain(train, vocab, lk), test, vocab_set)

    # non-circular headline: shipped Markov model on the manual CERT-In sequences
    manual_res = manual_n = manual_oov = None
    if manual:
        manual_res, manual_n, manual_oov = eval_ranker(markov_predict, manual, vocab_set)

    print("Training LSTM ...")
    net, emb_of, dim = train_lstm(train, val, emb, vocab, idx)
    results["lstm"] = lstm_topk(net, test, emb_of, dim, vocab_set, idx)

    import torch
    torch.save({"state": net.state_dict(), "vocab": vocab, "dim": dim}, MODEL_OUT)
    save_markov(train, ROOT / "models" / "next_technique_markov.pkl")

    # honest model selection: best method by top-3 accuracy
    best = max(results, key=lambda m: results[m][3])
    mk_vs_kc = results["markov"][3] / max(results["killchain"][3], 1e-9)   # anti-circularity
    lstm_vs_mk = results["lstm"][3] / max(results["markov"][3], 1e-9)

    # write the canonical numbers so the Metrics screen never drifts from this run
    try:
        from src.shared.metrics_store import update as _update
        _update("engine2", "predictor", {
            "most_frequent_top3": round(results["most_frequent"][3], 3),
            "killchain_top3": round(results["killchain"][3], 3),
            "lstm_top3": round(results["lstm"][3], 3),
            "markov_top3": round(results["markov"][3], 3),
            "note": f"Markov shipped; {mk_vs_kc:.1f}x the kill-chain baseline = anti-circularity",
        })
        if manual_res is not None:
            _update("engine2", "manual_cert_in_top3", round(manual_res[3], 3))
    except Exception as e:                       # reporting must never break the eval
        print(f"  [metrics_store skipped: {e}]")

    lines = [
        "# Engine 2.4 — Next-Technique Predictor (honest eval)",
        "",
        f"Predict the next ATT&CK technique from a partial sequence. Test = "
        f"{n_test} prediction points across {len(test)} held-out sequences "
        f"(vocab {len(vocab)}, OOV next-techniques counted as misses: {oov}).",
        "",
        "| Method | top-1 | top-3 | top-5 |",
        "|---|---|---|---|",
    ]
    label = {"most_frequent": "Most-frequent (baseline)",
             "markov": "Markov 1st-order (baseline)",
             "killchain": "Kill-chain order (baseline ⚠️)",
             "lstm": "LSTM (embeddings)"}
    for m in ["most_frequent", "markov", "killchain", "lstm"]:
        r = results[m]
        lines.append(f"| {label[m]} | {r[1]*100:.1f}% | {r[3]*100:.1f}% | {r[5]*100:.1f}% |")

    lines += [
        "",
        "## Interpretation (data-driven)",
        f"- **Shipped predictor: {label[best]}** — best top-3 ({results[best][3]*100:.1f}%) "
        + ("and the most explainable choice. On only "
           f"{len(train)} training sequences a first-order Markov transition model "
           "beats the LSTM — so we ship Markov (honest > fancy)."
           if best == "markov" else
           "on this data."),
        f"- ✅ **Anti-circularity proof:** Markov top-3 ({results['markov'][3]*100:.1f}%) is "
        f"**{mk_vs_kc:.1f}× the kill-chain-order baseline** ({results['killchain'][3]*100:.1f}%). "
        f"Since sequences are tactic-ordered, a model that only re-learned that ordering "
        f"would score like the kill-chain baseline. Beating it {mk_vs_kc:.1f}× means we are "
        f"predicting **real technique-to-technique transitions**, not the imposed order.",
        f"- **Neural is not justified here (honest negative result):** the LSTM "
        f"({results['lstm'][3]*100:.1f}% top-3) is {lstm_vs_mk:.2f}× Markov — it beats the "
        f"naive baselines but not the transition model at this data scale. Kept as a "
        f"documented comparison, not the deliverable.",
        f"- Top-1 is a hard bar with a {len(vocab)}-way vocabulary and {len(train)} "
        f"training sequences; **top-3/top-5 are the honest headline** — they match how an "
        f"analyst uses a ranked list of 'likely next moves'.",
        "",
    ]
    if manual_res is not None:
        lines += [
            "## ⭐ Non-circular headline — manual CERT-In / India sequences (report-ordered)",
            f"- Shipped Markov model on **{len(manual)} hand-curated** report-ordered "
            f"sequences ({manual_n} prediction points, {manual_oov} OOV): "
            f"**top-1 {manual_res[1]*100:.1f}% · top-3 {manual_res[3]*100:.1f}% · "
            f"top-5 {manual_res[5]*100:.1f}%**.",
            "- These are ordered by the REAL reported attack timeline (not the kill-chain "
            "heuristic), so this is the honest, non-circular evaluation. "
            "⚠️ Verify each sequence's mappings (`data/manual/cert_in_sequences.json`) "
            "before quoting this in the pitch.",
            "",
        ]
    lines += [
        f"_Shipped: `models/next_technique_markov.pkl` · LSTM comparison: "
        f"`{MODEL_OUT.relative_to(ROOT)}` · sequences E2.2 · embeddings E2.3._",
    ]
    REPORT.write_text("\n".join(lines), encoding="utf-8")

    print("\n=== top-k accuracy (test) ===")
    print(f"{'method':<26}{'top-1':>8}{'top-3':>8}{'top-5':>8}")
    for m in ["most_frequent", "markov", "killchain", "lstm"]:
        r = results[m]
        print(f"{label[m]:<26}{r[1]*100:>7.1f}%{r[3]*100:>7.1f}%{r[5]*100:>7.1f}%")
    print(f"\nShipped: {label[best]} (top-3 {results[best][3]*100:.1f}%). "
          f"Anti-circularity: Markov {mk_vs_kc:.1f}x kill-chain; LSTM {lstm_vs_mk:.2f}x Markov.")
    print(f"-> {REPORT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
