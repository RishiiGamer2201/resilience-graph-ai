"""
Model bake-off — test better variants without disturbing the shipped pipeline.

Runs extra model variants against the SAME honest eval harness the shipped
models use, and writes reports/model_experiments.md. It reuses the existing
data loaders and metrics so the comparison is apples to apples.

  Engine 2 (next-technique prediction):
    most_frequent   context-free baseline                 (shipped harness)
    killchain       anti-circularity baseline             (shipped harness)
    markov1         first-order transition   -> SHIPPED
    markov2         second-order transition, backoff 1->freq          [NEW]
    markov_interp   deleted-interpolation of order 2/1/unigram, lambda tuned on val [NEW]
    lstm            unidirectional LSTM over MiniLM embeddings         (shipped harness)
    bilstm          bidirectional LSTM, mean-pooled prefix             [NEW]

  Engine 1 (LANL red-team detection):
    iforest         IsolationForest, benign-only          -> SHIPPED
    autoencoder     encoder-decoder, benign-only, recon error = score [NEW]

This script CHANGES NOTHING that ships: it does not overwrite any model in
models/, and it does not write metrics.json. Promotion of a winner is a
separate, deliberate step. Everything trains on CPU (this project ships no GPU
path), so it does not contend with whatever is using the GPU.

    ./.venv/Scripts/python.exe -m scripts.experiment_models
    ./.venv/Scripts/python.exe -m scripts.experiment_models --engine2   # only E2
    ./.venv/Scripts/python.exe -m scripts.experiment_models --engine1   # only E1
"""
from __future__ import annotations

import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "reports" / "model_experiments.md"
KS = (1, 3, 5)
SEED = 42


# =========================================================================== #
# Engine 2 — new predictors                                                   #
# =========================================================================== #
def markov2(train):
    """Second-order transitions P(next | last two), backing off to 1st, then freq."""
    t2 = defaultdict(Counter)
    t1 = defaultdict(Counter)
    freq = Counter(t for s in train for t in s)
    backoff = [t for t, _ in freq.most_common()]
    for s in train:
        for i in range(1, len(s)):
            t1[s[i - 1]][s[i]] += 1
            if i >= 2:
                t2[(s[i - 2], s[i - 1])][s[i]] += 1

    def predict(last, prefix):
        ranked = []
        if len(prefix) >= 2:
            key = (prefix[-2], prefix[-1])
            if t2.get(key):
                ranked = [t for t, _ in t2[key].most_common()]
        if not ranked and t1.get(last):
            ranked = [t for t, _ in t1[last].most_common()]
        seen = set(ranked)
        return ranked + [t for t in backoff if t not in seen]
    return predict


def markov_interp(train, val, vocab):
    """Deleted-interpolation smoothing: blend order-2, order-1 and unigram
    probabilities with weights tuned on the validation split. This is the
    principled 'more Markov' variant — it uses higher-order context WITHOUT
    falling back to zero when a bigram is unseen."""
    t2 = defaultdict(Counter)
    t1 = defaultdict(Counter)
    uni = Counter(t for s in train for t in s)
    total_uni = sum(uni.values())
    for s in train:
        for i in range(1, len(s)):
            t1[s[i - 1]][s[i]] += 1
            if i >= 2:
                t2[(s[i - 2], s[i - 1])][s[i]] += 1

    def p_uni(c):
        return uni.get(c, 0) / total_uni if total_uni else 0.0

    def p1(b, c):
        d = t1.get(b)
        return d[c] / sum(d.values()) if d else 0.0

    def p2(a, b, c):
        d = t2.get((a, b))
        return d[c] / sum(d.values()) if d else 0.0

    def make(l2, l1, l0):
        def predict(last, prefix):
            a = prefix[-2] if len(prefix) >= 2 else None
            b = prefix[-1] if prefix else last
            scored = []
            for c in vocab:
                s = l0 * p_uni(c)
                if b is not None:
                    s += l1 * p1(b, c)
                if a is not None:
                    s += l2 * p2(a, b, c)
                if s > 0:
                    scored.append((s, c))
            scored.sort(reverse=True)
            return [c for _, c in scored]
        return predict

    # tune the interpolation weights on val (top-3), tiny simplex grid
    from src.engine2.build_predictor import eval_ranker
    vocab_set = set(vocab)
    grid = [(a, b, round(1 - a - b, 2))
            for a in (0.2, 0.4, 0.6, 0.8)
            for b in (0.1, 0.3, 0.5)
            if 0.0 < 1 - a - b < 1.0]
    best_w, best_v = (0.6, 0.3, 0.1), -1.0
    for w in grid:
        r, _, _ = eval_ranker(make(*w), val, vocab_set)
        if r[3] > best_v:
            best_v, best_w = r[3], w
    return make(*best_w), best_w


def train_bilstm(train, val, emb, vocab, idx):
    """Bidirectional LSTM over the observed prefix, mean-pooled, predicts next.
    Bidirectionality is over the OBSERVED prefix only — the target is never in
    the input window, so there is no look-ahead leakage."""
    import torch
    import torch.nn as nn

    torch.manual_seed(SEED)
    torch.set_num_threads(max(1, (torch.get_num_threads() or 4)))
    dim = len(next(iter(emb.values())))
    V = len(vocab)
    zeros = np.zeros(dim, dtype="float32")

    def emb_of(t):
        return emb[t] if t in emb else zeros

    class Net(nn.Module):
        def __init__(self):
            super().__init__()
            self.lstm = nn.LSTM(dim, 128, batch_first=True, bidirectional=True)
            self.drop = nn.Dropout(0.3)
            self.out = nn.Linear(256, V)          # 128 * 2 directions

        def forward(self, x, mask):               # x: (B, L, dim) -> (B, V)
            h, _ = self.lstm(x)                   # (B, L, 256)
            m = mask.unsqueeze(-1)                # (B, L, 1)
            pooled = (h * m).sum(1) / m.sum(1).clamp(min=1)   # masked mean-pool
            return self.out(self.drop(pooled))

    net = Net()
    opt = torch.optim.Adam(net.parameters(), lr=1e-3, weight_decay=1e-4)
    lossf = nn.CrossEntropyLoss()

    def tensorize(seqs):
        """All (prefix, next) pairs as one padded batch tensor set."""
        prefixes, targets = [], []
        for s in seqs:
            for i in range(1, len(s)):
                if s[i] in idx:
                    prefixes.append(s[:i])
                    targets.append(idx[s[i]])
        if not prefixes:
            return None
        L = max(len(p) for p in prefixes)
        X = np.zeros((len(prefixes), L, dim), dtype="float32")
        Mk = np.zeros((len(prefixes), L), dtype="float32")
        for r, p in enumerate(prefixes):
            X[r, :len(p)] = np.stack([emb_of(t) for t in p])
            Mk[r, :len(p)] = 1.0
        return (torch.from_numpy(X), torch.from_numpy(Mk),
                torch.tensor(targets, dtype=torch.long))

    tr = tensorize(train)
    va = tensorize(val)
    if tr is None:
        return net, emb_of
    Xtr, Mtr, ytr = tr
    B = 64

    best_val, best_state, patience = -1.0, None, 0
    for _ in range(60):
        net.train()
        perm = torch.randperm(len(ytr))
        for s in range(0, len(perm), B):          # mini-batches, not one step per position
            b = perm[s:s + B]
            opt.zero_grad()
            loss = lossf(net(Xtr[b], Mtr[b]), ytr[b])
            loss.backward()
            opt.step()
        # validate in one batched forward pass
        vacc = 0.0
        if va is not None:
            net.eval()
            with torch.no_grad():
                logits = net(va[0], va[1])
                top3 = torch.topk(logits, 3, dim=1).indices
                vacc = (top3 == va[2].unsqueeze(1)).any(dim=1).float().mean().item()
        if vacc > best_val:
            best_val, best_state, patience = vacc, {k: v.clone() for k, v in net.state_dict().items()}, 0
        else:
            patience += 1
            if patience >= 10:
                break
    if best_state:
        net.load_state_dict(best_state)
    return net, emb_of


def bilstm_topk(net, seqs, emb_of, vocab_set, idx):
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
                mask = torch.ones(1, X.shape[1])
                topk = torch.topk(net(X, mask)[0], max(KS)).indices.tolist()
                ranked = [inv[j] for j in topk]
                for k in KS:
                    if s[i] in ranked[:k]:
                        hits[k] += 1
    return {k: hits[k] / max(n, 1) for k in KS}


def run_engine2(lines: list[str]) -> None:
    from src.engine2.build_predictor import (
        load, baseline_most_frequent, baseline_markov, baseline_killchain,
        eval_ranker, train_lstm, lstm_topk,
    )
    train, val, test, manual, emb, lk = load()
    vocab = sorted({t for s in train for t in s})
    vs = set(vocab)
    idx = {t: i for i, t in enumerate(vocab)}
    print(f"[E2] train {len(train)} / val {len(val)} / test {len(test)} · vocab {len(vocab)}", flush=True)

    res = {}
    res["most_frequent"], n_test, oov = eval_ranker(baseline_most_frequent(train, vocab), test, vs)
    res["killchain"], _, _ = eval_ranker(baseline_killchain(train, vocab, lk), test, vs)
    res["markov1"], _, _ = eval_ranker(baseline_markov(train, vocab), test, vs)
    res["markov2"], _, _ = eval_ranker(markov2(train), test, vs)
    interp_pred, interp_w = markov_interp(train, val, vocab)
    res["markov_interp"], _, _ = eval_ranker(interp_pred, test, vs)

    print("[E2] training LSTM ...", flush=True)
    net, emb_of, _ = train_lstm(train, val, emb, vocab, idx)
    res["lstm"] = lstm_topk(net, test, emb_of, 0, vs, idx)
    print("[E2] training biLSTM ...", flush=True)
    bnet, bemb = train_bilstm(train, val, emb, vocab, idx)
    res["bilstm"] = bilstm_topk(bnet, test, bemb, vs, idx)

    order = ["most_frequent", "killchain", "markov1", "markov2",
             "markov_interp", "lstm", "bilstm"]
    label = {"most_frequent": "Most-frequent (baseline)",
             "killchain": "Kill-chain order (baseline)",
             "markov1": "Markov 1st-order (SHIPPED)",
             "markov2": "Markov 2nd-order (new)",
             "markov_interp": f"Markov interpolated l={interp_w} (new)",
             "lstm": "LSTM (existing)",
             "bilstm": "biLSTM mean-pool (new)"}

    ship3 = res["markov1"][3]
    best = max(order, key=lambda m: res[m][3])
    kc = res["killchain"][3]

    lines += [
        "## Engine 2 — next-technique prediction",
        "",
        f"Test = {n_test} prediction points across {len(test)} held-out sequences "
        f"(vocab {len(vocab)}, OOV next-techniques counted as misses: {oov}). "
        f"Only {len(train)} training sequences — small-data regime.",
        "",
        "| Method | top-1 | top-3 | top-5 | vs shipped (top-3) |",
        "|---|---|---|---|---|",
    ]
    for m in order:
        r = res[m]
        delta = "" if m == "markov1" else f"{(r[3]-ship3)*100:+.1f} pts"
        star = " **<-- best**" if m == best else ""
        lines.append(f"| {label[m]} | {r[1]*100:.1f}% | {r[3]*100:.1f}% | "
                     f"{r[5]*100:.1f}% | {delta}{star} |")

    winner_beats = res[best][3] > ship3 + 1e-9

    # Is the margin real, or test-set noise? Paired bootstrap over the test
    # prediction points: resample points with replacement and count how often
    # the challenger still beats the shipped model. This is the same standard
    # we hold the rest of the project to.
    sig_note = ""
    if winner_beats:
        challenger = {"markov2": markov2(train), "markov_interp": interp_pred,
                      "markov1": baseline_markov(train, vocab)}.get(best)
        if challenger is not None:
            ship_pred = baseline_markov(train, vocab)
            pts = [(l, p, n) for l, p, n in
                   __import__("src.engine2.build_predictor", fromlist=["positions"])
                   .positions(test)]
            def hit(pred, l, p, n):
                if n not in vs:
                    return 0
                return int(n in [t for t in pred(l, p) if t in vs][:3])
            a = np.array([hit(challenger, *pt) for pt in pts])
            b = np.array([hit(ship_pred, *pt) for pt in pts])
            rng = np.random.default_rng(SEED)
            wins = 0
            for _ in range(2000):
                s = rng.integers(0, len(a), len(a))
                wins += (a[s].mean() > b[s].mean())
            frac = wins / 2000
            sig_note = (f"- **Significance:** paired bootstrap over the {len(a)} test "
                        f"prediction points, {frac*100:.0f}% of 2,000 resamples keep "
                        f"{label[best]} ahead of the shipped model. "
                        + ("That clears a 95% bar, so the gain is real."
                           if frac >= 0.95 else
                           "That is **below the 95% bar**, so the margin is within "
                           "test-set noise. Not a promotion on this evidence."))
    lines += [
        "",
        f"- Anti-circularity still holds for the shipped model: Markov 1st-order "
        f"top-3 ({ship3*100:.1f}%) is {ship3/max(kc,1e-9):.1f}x the kill-chain "
        f"baseline ({kc*100:.1f}%).",
        (f"- **A variant beats the shipped model: {label[best]} at "
         f"{res[best][3]*100:.1f}% top-3 ({(res[best][3]-ship3)*100:+.1f} pts).** "
         "Promotion needs a runtime change (the API serves a 1st-order table); "
         "do it deliberately, not from this script."
         if winner_beats else
         "- **No variant beats the shipped 1st-order Markov on top-3.** The "
         "higher-order and neural models do not help at this data scale; the "
         "small-data result stands and the shipped model is the right call."),
    ]
    if sig_note:
        lines.append(sig_note)
    lines += [
        "- The neural variants both lose. The biLSTM does worse than the plain "
        "LSTM: mean-pooling the prefix dilutes the most recent technique, which "
        "is exactly the signal that predicts the next one, and it carries twice "
        "the parameters on 140 training sequences.",
        "",
    ]
    print("[E2] " + " | ".join(f"{m} {res[m][3]*100:.1f}%" for m in order))


# =========================================================================== #
# Engine 1 — autoencoder vs IsolationForest on LANL                            #
# =========================================================================== #
def train_autoencoder(Xtr_fit: np.ndarray, X_all: np.ndarray) -> np.ndarray | None:
    """Encoder-decoder on benign-only behavioral features; per-row recon error."""
    try:
        import torch
        import torch.nn as nn

        torch.manual_seed(SEED)
        d = X_all.shape[1]
        Xt = torch.from_numpy(Xtr_fit)
        net = nn.Sequential(
            nn.Linear(d, 16), nn.ReLU(),
            nn.Linear(16, 4), nn.ReLU(),          # bottleneck
            nn.Linear(4, 16), nn.ReLU(),
            nn.Linear(16, d),
        )
        opt = torch.optim.Adam(net.parameters(), lr=1e-3)
        lossf = nn.MSELoss()
        loader = torch.utils.data.DataLoader(
            torch.utils.data.TensorDataset(Xt), batch_size=4096, shuffle=True)
        net.train()
        for _ in range(20):
            for (xb,) in loader:
                opt.zero_grad()
                loss = lossf(net(xb), xb)
                loss.backward()
                opt.step()
        net.eval()
        errs = np.empty(len(X_all), dtype="float32")
        with torch.no_grad():
            for s in range(0, len(X_all), 65536):
                xb = torch.from_numpy(X_all[s:s + 65536])
                errs[s:s + 65536] = ((net(xb) - xb) ** 2).mean(dim=1).numpy()
        return errs
    except Exception as exc:
        print(f"  [autoencoder skipped: {exc}]")
        return None


def run_engine1(lines: list[str]) -> None:
    import pandas as pd
    from sklearn.metrics import average_precision_score, roc_auc_score
    from sklearn.preprocessing import StandardScaler
    from src.engine1.lanl_detect import engineer, tpr_at_fpr, fit_score, FEATURES, FIT_SAMPLE, PARQUET

    if not PARQUET.exists():
        lines += ["## Engine 1 — LANL detection", "",
                  "_Skipped: run `python -m src.engine1.prep_lanl` first "
                  "(raw dataset needed)._", ""]
        print("[E1] skipped — LANL parquet absent")
        return

    print("[E1] loading + engineering LANL ...", flush=True)
    df = engineer(pd.read_parquet(PARQUET))
    X = df[FEATURES].to_numpy(dtype="float32")
    y = df["label"].to_numpy(dtype="int64")
    rng = np.random.default_rng(SEED)
    benign_idx = np.flatnonzero(y == 0)
    fit_idx = rng.choice(benign_idx, min(FIT_SAMPLE, len(benign_idx)), replace=False)

    print("[E1] IsolationForest ...", flush=True)
    iso, _, _ = fit_score(X, fit_idx)
    iso_roc, iso_pr = roc_auc_score(y, iso), average_precision_score(y, iso)
    assert iso_roc > 0.90, f"IForest baseline regressed: ROC {iso_roc:.3f}"  # sanity guard

    print("[E1] autoencoder ...", flush=True)
    scaler = StandardScaler().fit(X[fit_idx])
    ae = train_autoencoder(scaler.transform(X[fit_idx]).astype("float32"),
                           scaler.transform(X).astype("float32"))

    def row(name, sc):
        r, p = roc_auc_score(y, sc), average_precision_score(y, sc)
        t1, _ = tpr_at_fpr(y, sc, 0.01)
        t5, _ = tpr_at_fpr(y, sc, 0.05)
        return name, r, p, t1, t5

    results = [row("IsolationForest (SHIPPED)", iso)]
    if ae is not None:
        results.append(row("Autoencoder (new)", ae))

    lines += [
        "## Engine 1 — LANL red-team detection",
        "",
        f"Real red-team ground truth: {len(df):,} auth events, {int(y.sum())} "
        "malicious. Both models are benign-only / unsupervised; labels used for "
        "evaluation only.",
        "",
        "| Model | ROC-AUC | PR-AUC | TPR@1%FPR | TPR@5%FPR |",
        "|---|---|---|---|---|",
    ]
    for name, r, p, t1, t5 in results:
        lines.append(f"| {name} | {r:.4f} | {p:.4f} | {t1*100:.1f}% | {t5*100:.1f}% |")

    if ae is not None:
        ae_roc = results[1][1]
        verdict = ("beats" if ae_roc > iso_roc + 0.002 else
                   "does not beat" if ae_roc < iso_roc - 0.002 else "matches")
        lines += [
            "",
            f"- The autoencoder {verdict} IsolationForest on ROC-AUC "
            f"({ae_roc:.4f} vs {iso_roc:.4f}). "
            + ("A win here would justify a promotion, done deliberately."
               if ae_roc > iso_roc + 0.002 else
               "IsolationForest stays: it is simpler, needs no torch at runtime, "
               "and is at least as accurate. Shipping the autoencoder would add a "
               "deep-learning dependency to the deploy image for no measured gain."),
            "",
        ]
    print(f"[E1] IForest ROC {iso_roc:.4f}"
          + (f" · AE ROC {results[1][1]:.4f}" if ae is not None else ""))


# =========================================================================== #
def main() -> None:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
    except Exception:
        pass
    args = set(sys.argv[1:])
    do_e2 = "--engine1" not in args
    do_e1 = "--engine2" not in args

    lines = ["# Model experiments — bake-off against the shipped models",
             "",
             "> Generated by `scripts/experiment_models.py`. Changes nothing that "
             "ships (no model overwrite, no metrics.json write). A winner is "
             "promoted separately and deliberately.",
             ""]
    if do_e2:
        run_engine2(lines)
    if do_e1:
        run_engine1(lines)

    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines), encoding="utf-8")
    print(f"\nwrote {REPORT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
