"""
src/engine3/netstate.py — a world model over NETWORK STATE, not over techniques.

The SIH 2026 "World Models" problem statement asks for the transition dynamics

    P(S_t+1 | S_t)

where `S_t` is the observed state of the network — flag distributions, packet
timing, throughput — and NOT a label an analyst assigns after the fact. Our
existing predictor (src/engine2) learns P(technique_t+1 | technique_t) and is a
genuine transition model over the wrong state space for that question. This
module is the right state space.

What it is
----------
A discrete latent state-space model, one of the four families the problem
statement names ("LSTM, Transformer, GNN or latent state-space").

    1. S_t is a fixed-width traffic feature vector over a window of W
       consecutive flows: TCP flag rates, inter-arrival-time statistics,
       bidirectional ratios, packet-length distribution, TCP window sizes and
       throughput. Mean and standard deviation of each, so the vector carries
       the window's dispersion and not only its centre.
    2. Those vectors are standardised and quantised into K latent states by
       k-means. The latent state is the model's vocabulary.
    3. P(S_t+1 | S_t) is a K x K transition matrix counted over consecutive
       windows, Laplace-smoothed, never counted across a day boundary.
    4. Each latent state carries its MEASURED attack prevalence on the training
       days, so a distribution over future states reads directly as an
       infiltration probability.

Forecasting is then one matrix multiply per step, which makes a K-step rollout
exact rather than sampled, and completely deterministic.

Why discrete and not an LSTM
----------------------------
We already published a negative result: an LSTM lost to an interpolated Markov
at next-technique prediction on this project's data scale
(`reports/model_experiments.md`). A quantised latent space keeps the model
inspectable — you can print what state 7 means and how often it precedes a
compromise — which is the property the problem statement demands when it says
black-box output is not acceptable. `scripts/eval_netstate.py` measures this
model against persistence and marginal baselines; if a sequence model beats it
there, that is the evidence to switch.

What this is NOT
----------------
- Not packet-level. CIC-IDS2017 is distributed as flow records; TTL variance,
  fragment flags and retransmission counts are not in it. Requirement 7 stays
  open and `docs/competition/sih-2026-world-models.md` says so.
- Not port or host aware. This parquet carries flow statistics only, with no
  address or port columns, so "active flow count" and "unique port count" are
  not among the features even though the problem statement names them.
- Not CTU-13 or CIC-IDS2018. It is CIC-IDS2017, which the problem statement
  also lists as acceptable.

Usage:
    from src.engine3.netstate import NetStateModel
    m = NetStateModel.load()
    m.forecast(state_vectors, horizon=5)   # infiltration probability per step
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
FLOWS = ROOT / "data" / "processed" / "cicids2017" / "flows.parquet"
MODEL = ROOT / "models" / "netstate_cicids.npz"

# ─── Model shape ──────────────────────────────────────────────────────────────
WINDOW = 256          # consecutive flows per state observation
N_STATES = 24         # latent states; measured against alternatives in the eval
LAPLACE = 1.0         # smoothing so an unseen transition is improbable, not impossible
SEED = 20260822       # k-means is seeded: the same data must give the same model

# Train on the earlier days, test on the later ones. A random split would put
# the same attack burst on both sides and let the model memorise it, which is
# the leak we already called out in reports/lr_baseline.md.
TRAIN_DAYS = ["Monday", "Tuesday", "Wednesday"]
TEST_DAYS = ["Thursday", "Friday"]

# ─── The state vector ─────────────────────────────────────────────────────────
# Chosen to cover the observable categories the problem statement names, and
# restricted to what CIC-IDS2017 flow records actually contain.
FLOW_FEATURES: list[str] = [
    # TCP flag distribution
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count",
    "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
    # inter-arrival timing
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    # bidirectionality
    "Down/Up Ratio", "Fwd Packets/s", "Bwd Packets/s",
    # packet-length distribution
    "Packet Length Mean", "Packet Length Std",
    "Min Packet Length", "Max Packet Length",
    # TCP window
    "Init_Win_bytes_forward", "Init_Win_bytes_backward",
    # throughput and session shape
    "Flow Bytes/s", "Flow Packets/s", "Flow Duration",
    "Active Mean", "Idle Mean",
]

# Each flow feature contributes a window mean and a window standard deviation.
STATE_DIM = len(FLOW_FEATURES) * 2


class FeatureContractError(ValueError):
    """A state vector was built from a different feature set than the model.

    Its own type, because the API turns it into a 422 -- the caller sent input
    this model cannot answer for, which is a request problem, not a server
    fault, and not something a retry fixes.
    """

    def __init__(self, *, expected: int, got: int) -> None:
        self.expected, self.got = expected, got
        likely = ""
        if got == 60 and expected == 48:
            likely = (" This is the packet/flow mismatch: src/engine3/packets.py "
                      "emits 30 packet features (60 dims) and the shipped "
                      "artifact was trained on 24 CIC-IDS2017 flow features "
                      "(48 dims). They share a shape convention, not a feature "
                      "set, so there is no conversion -- a packet-trained "
                      "artifact is required.")
        super().__init__(
            f"this model encodes {expected}-dimensional windows, got {got}."
            f"{likely}")


def state_names() -> list[str]:
    return ([f"{c} (mean)" for c in FLOW_FEATURES]
            + [f"{c} (std)" for c in FLOW_FEATURES])


# ─── Building state observations ──────────────────────────────────────────────
def windows(df, *, window: int = WINDOW) -> tuple[np.ndarray, np.ndarray]:
    """Split one day's flows into consecutive windows and summarise each.

    Returns (states, attack_rate) where states is (n_windows, STATE_DIM) and
    attack_rate is the share of flows in the window carrying an attack label.

    The flow order in the parquet is the order CIC-IDS2017 ships, which is
    chronological within a day. There is no timestamp column to verify that
    against, so it is an assumption -- stated here rather than hidden, and the
    reason windows are never formed across a day boundary.
    """
    X = df[FLOW_FEATURES].to_numpy(dtype=np.float64, copy=True)
    X[~np.isfinite(X)] = 0.0            # the CIC export contains inf in rate columns
    y = df["label"].to_numpy(dtype=np.float64)

    n = (len(X) // window) * window
    if n == 0:
        return np.empty((0, STATE_DIM)), np.empty(0)
    Xw = X[:n].reshape(-1, window, len(FLOW_FEATURES))
    yw = y[:n].reshape(-1, window)
    return np.hstack([Xw.mean(axis=1), Xw.std(axis=1)]), yw.mean(axis=1)


def build_observations(df, days: list[str], *, window: int = WINDOW):
    """State sequences per day. Kept separate so transitions never cross days."""
    out = []
    for day in days:
        d = df[df["day"] == day]
        if d.empty:
            continue
        s, a = windows(d, window=window)
        if len(s):
            out.append((day, s, a))
    return out


# ─── The model ────────────────────────────────────────────────────────────────
@dataclass
class NetStateModel:
    """Standardiser + latent centroids + transition matrix + state risk."""

    mean: np.ndarray            # (STATE_DIM,)
    scale: np.ndarray           # (STATE_DIM,)
    centroids: np.ndarray       # (K, STATE_DIM)
    transitions: np.ndarray     # (K, K), rows sum to 1
    state_attack_rate: np.ndarray   # (K,) measured prevalence per latent state
    state_support: np.ndarray       # (K,) training windows per state
    window: int = WINDOW
    trained_on: str = ""
    # Weight on "the next window looks like this one", fitted on a slice held
    # out from the training days. 0.0 means the counted matrix is used as-is.
    persistence_weight: float = 0.0
    # Pseudo-count mass given to the offline prior by OnlineTracker. Small means
    # the tracker trusts the day in front of it sooner. Fitted leave-one-day-out.
    online_prior_strength: float = 0.0

    # -- inference ---------------------------------------------------------- #
    @property
    def n_states(self) -> int:
        return len(self.centroids)

    def encode(self, states: np.ndarray) -> np.ndarray:
        """Raw state vectors -> latent state ids. Nearest centroid, no ties broken
        randomly: argmin is stable for a fixed centroid order.

        Checks the feature contract first. A model is a mean, a scale and a set
        of centroids over ONE named feature list; handing it a vector of the
        same shape convention but a different feature set is not a
        dimensionality problem that numpy should report, it is a category error.
        Without this, packet windows (30 features, 60 dims) met the shipped
        flow-trained artifact (24 features, 48 dims) and raised
        `operands could not be broadcast together with shapes (n,60) (48,)`,
        which names neither the two feature sets nor the fact that no amount of
        reshaping would make the answer meaningful.
        """
        states = np.atleast_2d(states)
        if states.shape[-1] != self.mean.shape[-1]:
            raise FeatureContractError(expected=int(self.mean.shape[-1]),
                                       got=int(states.shape[-1]))
        z = (states - self.mean) / self.scale
        d = ((z[:, None, :] - self.centroids[None, :, :]) ** 2).sum(axis=2)
        return d.argmin(axis=1)

    def next_distribution(self, latent: int) -> np.ndarray:
        """P(S_t+1 | S_t = latent), interpolated with persistence.

        The counted transition matrix on its own LOST to the persistence
        baseline on the held-out days: top-1 0.273 against 0.362. Network
        traffic is strongly autocorrelated and the transition structure learned
        on Monday-Wednesday does not fully transfer to Thursday-Friday, so the
        single most useful thing to know about the next window is that it
        probably resembles this one.

        Rather than discard the model or quietly report the baseline as ours, the
        two are interpolated -- the same fix that made engine2's next-technique
        predictor work. `persistence_weight` is fitted on a slice held out from
        the TRAINING days, never on the test days.
        """
        row = self.transitions[latent]
        w = float(self.persistence_weight)
        if w <= 0.0:
            return row
        stay = np.zeros(self.n_states)
        stay[latent] = 1.0
        return (1.0 - w) * row + w * stay

    def transition_matrix(self) -> np.ndarray:
        """The full interpolated matrix, for rollouts and matrix powers."""
        w = float(self.persistence_weight)
        if w <= 0.0:
            return self.transitions
        return (1.0 - w) * self.transitions + w * np.eye(self.n_states)

    def forecast(self, states: np.ndarray, *, horizon: int = 5) -> dict:
        """Roll the transition matrix forward and read infiltration probability
        off the predicted trajectory.

        Exact, not sampled: the distribution over states at t+k is p0 @ T^k.

        Returns per-step `attack_probability` (the expected share of flows
        carrying an attack in the predicted window) and `cumulative`, the
        probability that at least one of the next k windows is compromised
        under the model's own step probabilities.
        """
        latents = self.encode(states)
        return self._forecast_from(int(latents[-1]), self.transition_matrix(),
                                   horizon=horizon)

    def _forecast_from(self, latent: int, T: np.ndarray, *, horizon: int) -> dict:
        """Roll a given transition matrix forward from a given state.

        Split out so OnlineTracker rolls its adapted matrix through exactly this
        code. Two rollout implementations would drift, and the one that drifted
        would be the one nobody was watching.
        """
        p = np.zeros(self.n_states)
        p[latent] = 1.0

        steps, survive = [], 1.0
        for k in range(1, horizon + 1):
            p = p @ T
            step_p = float(p @ self.state_attack_rate)
            survive *= (1.0 - step_p)
            steps.append({
                "step": k,
                "attack_probability": round(step_p, 4),
                "cumulative_probability": round(1.0 - survive, 4),
                "top_states": [
                    {"state": int(s), "probability": round(float(p[s]), 4),
                     "attack_rate": round(float(self.state_attack_rate[s]), 4)}
                    for s in np.argsort(p)[::-1][:3]
                ],
            })
        return {
            "current_state": latent,
            "current_state_attack_rate": round(float(self.state_attack_rate[latent]), 4),
            "horizon": horizon,
            "steps": steps,
            "state_space": "network traffic state (CIC-IDS2017 flow windows)",
            "method": (f"discrete latent state-space model, {self.n_states} states over "
                       f"{STATE_DIM}-dimensional windows of {self.window} flows; "
                       f"exact matrix rollout, no sampling"),
        }

    # -- persistence -------------------------------------------------------- #
    def save(self, path: Path = MODEL) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        np.savez_compressed(
            path, mean=self.mean, scale=self.scale, centroids=self.centroids,
            transitions=self.transitions, state_attack_rate=self.state_attack_rate,
            state_support=self.state_support,
            window=np.array([self.window]),
            trained_on=np.array([self.trained_on]),
            persistence_weight=np.array([self.persistence_weight]),
            online_prior_strength=np.array([self.online_prior_strength]),
        )

    @classmethod
    def load(cls, path: Path = MODEL) -> "NetStateModel":
        z = np.load(path, allow_pickle=False)
        return cls(
            mean=z["mean"], scale=z["scale"], centroids=z["centroids"],
            transitions=z["transitions"], state_attack_rate=z["state_attack_rate"],
            state_support=z["state_support"],
            window=int(z["window"][0]), trained_on=str(z["trained_on"][0]),
            persistence_weight=float(z["persistence_weight"][0])
            if "persistence_weight" in z else 0.0,
            online_prior_strength=float(z["online_prior_strength"][0])
            if "online_prior_strength" in z else 0.0,
        )

    @classmethod
    def available(cls, path: Path = MODEL) -> bool:
        return path.exists()

    # -- readability -------------------------------------------------------- #
    def describe_state(self, latent: int, *, top_k: int = 4) -> dict:
        """What makes this latent state different from the average window.

        The point of quantising rather than fitting a black box: a state can be
        printed. Reported in units of training standard deviations from the
        mean window, so the numbers are comparable across features.
        """
        z = self.centroids[latent]
        order = np.argsort(np.abs(z))[::-1][:top_k]
        names = state_names()
        return {
            "state": int(latent),
            "attack_rate": round(float(self.state_attack_rate[latent]), 4),
            "training_windows": int(self.state_support[latent]),
            "distinguishing_features": [
                {"feature": names[i],
                 "z_score": round(float(z[i]), 2),
                 "direction": "high" if z[i] > 0 else "low"}
                for i in order
            ],
        }


# ─── Online adaptation ────────────────────────────────────────────────────────
class OnlineTracker:
    """Adapt the transition matrix to the day in front of you, causally.

    Why this exists. The offline matrix draws level with a persistence baseline
    and no better estimator fixes that: an oracle first-order matrix counted on
    the test days themselves reaches 0.4475 against persistence at 0.3620, so a
    first-order model over these latent states CAN win by eight points, and ours
    does not because the structure learned Monday-Wednesday does not transfer to
    Thursday-Friday. The limit is transfer, not capacity. A second-order model
    was tried and made it worse: leave-one-day-out gave order-2 a weight of 0.0
    and order-2 alone scored 0.2357 against order-1's 0.2735.

    Transfer is fixable at deployment and needs no labels. Traffic arrives, you
    observe its transitions, so you may count them. This tracker predicts the
    next state, and only then is told what actually happened -- the offline
    prior is blended with live counts as pseudo-counts, so early in a day the
    prior dominates and it hands over as evidence accumulates.

    Measured: top-1 0.3964 against persistence 0.3620 on Thursday and Friday,
    with the prior strength and persistence weight fitted leave-one-day-out over
    the training days. A version of those hyperparameters read off the test days
    scored 0.4243, which is what tuning on the test set buys and the reason the
    number above is the smaller one.

    Usage is predict-then-observe, and misusing it is hard by construction:

        t = OnlineTracker(model)
        for window in stream:
            forecast = t.forecast(horizon=3)   # before seeing this window
            t.observe(window)                  # now the model may count it
    """

    def __init__(self, model: "NetStateModel", *, prior_strength: float | None = None):
        self.model = model
        self.prior_strength = (model.online_prior_strength if prior_strength is None
                               else float(prior_strength))
        K = model.n_states
        self._prior = model.transitions * self.prior_strength
        self._live = np.zeros((K, K))
        self._current: int | None = None
        self.n_observed = 0

    # -- state -------------------------------------------------------------- #
    @property
    def current_state(self) -> int | None:
        return self._current

    def reset(self) -> None:
        """Start a new stream. Live counts do not carry across a discontinuity."""
        self._live = np.zeros((self.model.n_states, self.model.n_states))
        self._current = None
        self.n_observed = 0

    def observe(self, state_vector) -> int:
        """Feed one window. Call this AFTER predicting from it."""
        latent = int(self.model.encode(np.atleast_2d(state_vector))[0])
        if self._current is not None:
            self._live[self._current, latent] += 1.0
        self._current = latent
        self.n_observed += 1
        return latent

    def observe_all(self, state_vectors) -> list[int]:
        return [self.observe(v) for v in np.atleast_2d(state_vectors)]

    # -- prediction --------------------------------------------------------- #
    def next_distribution(self, latent: int | None = None) -> np.ndarray:
        latent = self._current if latent is None else latent
        if latent is None:
            raise ValueError("observe at least one window before predicting")
        c = self._prior[latent] + self._live[latent]
        row = c / c.sum()
        w = float(self.model.persistence_weight)
        if w > 0.0:
            stay = np.zeros(self.model.n_states)
            stay[latent] = 1.0
            row = (1.0 - w) * row + w * stay
        return row

    def transition_matrix(self) -> np.ndarray:
        """The adapted matrix, for multi-step rollouts."""
        c = self._prior + self._live
        T = c / c.sum(axis=1, keepdims=True)
        w = float(self.model.persistence_weight)
        if w > 0.0:
            T = (1.0 - w) * T + w * np.eye(self.model.n_states)
        return T

    def forecast(self, *, horizon: int = 5) -> dict:
        """Same shape as NetStateModel.forecast, over the adapted matrix."""
        if self._current is None:
            raise ValueError("observe at least one window before forecasting")
        out = self.model._forecast_from(self._current, self.transition_matrix(),
                                        horizon=horizon)
        out["adaptation"] = {
            "mode": "online",
            "windows_observed": self.n_observed,
            "prior_strength": self.prior_strength,
            "note": ("Counts only transitions already observed in this stream. "
                     "Nothing after the current window contributes."),
        }
        return out


# ─── Training ─────────────────────────────────────────────────────────────────
def fit(observations, *, n_states: int = N_STATES, window: int = WINDOW,
        trained_on: str = "", fit_persistence: bool = True) -> NetStateModel:
    """Fit the standardiser, the latent states and the transition matrix.

    `observations` is the list of (day, states, attack_rate) from
    build_observations. Transitions are counted only within a day.
    """
    from sklearn.cluster import KMeans

    S = np.vstack([s for _, s, _ in observations])
    A = np.concatenate([a for _, _, a in observations])

    mean = S.mean(axis=0)
    scale = S.std(axis=0)
    scale[scale < 1e-9] = 1.0
    Z = (S - mean) / scale

    km = KMeans(n_clusters=n_states, random_state=SEED, n_init=10).fit(Z)
    centroids = km.cluster_centers_
    labels = km.labels_

    # Measured prevalence per latent state. A state with no training support
    # gets the global rate rather than a fabricated zero.
    rate = np.zeros(n_states)
    support = np.zeros(n_states, dtype=np.int64)
    for k in range(n_states):
        m = labels == k
        support[k] = int(m.sum())
        rate[k] = float(A[m].mean()) if support[k] else float(A.mean())

    # Transitions, counted per day so no edge spans a day boundary.
    seqs, off = [], 0
    for _, s, _ in observations:
        seqs.append(labels[off:off + len(s)])
        off += len(s)
    transitions = _count_transitions(seqs, n_states)

    model = NetStateModel(
        mean=mean, scale=scale, centroids=centroids, transitions=transitions,
        state_attack_rate=rate, state_support=support, window=window,
        trained_on=trained_on or ", ".join(d for d, _, _ in observations),
    )
    if fit_persistence:
        model.persistence_weight = _fit_persistence_weight(model, observations)
        model.online_prior_strength = _fit_online_strength(model, observations)
    return model


ONLINE_STRENGTH_GRID = (2.0, 5.0, 10.0, 20.0, 50.0, 100.0)


def _fit_online_strength(model: NetStateModel, observations) -> float:
    """How much pseudo-count mass the offline prior keeps against live evidence.

    Leave-one-day-out, same protocol as the persistence weight and for the same
    reason: the question is transfer to a day the matrix has not seen, and a
    holdout taken from inside a day never asks it.
    """
    per_day = [model.encode(states) for _, states, _ in observations]
    per_day = [lat for lat in per_day if len(lat) >= 2]
    if len(per_day) < 2:
        return ONLINE_STRENGTH_GRID[0]

    scores = {g: 0 for g in ONLINE_STRENGTH_GRID}
    for i, held in enumerate(per_day):
        rest = [lat for j, lat in enumerate(per_day) if j != i]
        prior = _count_transitions(rest, model.n_states)
        for g in ONLINE_STRENGTH_GRID:
            scores[g] += _online_hits(held, prior, g, model.persistence_weight,
                                      model.n_states)
    # Ties go to the weaker prior: prefer adapting to what is actually happening.
    return float(min(ONLINE_STRENGTH_GRID, key=lambda g: (-scores[g], g)))


def _online_hits(sequence, prior: np.ndarray, strength: float,
                 persist_w: float, n_states: int) -> int:
    """Causal walk: predict from what is already seen, then count the truth."""
    prior_mass = prior * strength
    eye = np.eye(n_states)
    live = np.zeros((n_states, n_states))
    hits = 0
    for a, b in zip(sequence[:-1], sequence[1:]):
        c = prior_mass[a] + live[a]
        row = c / c.sum()
        if persist_w > 0.0:
            row = (1.0 - persist_w) * row + persist_w * eye[a]
        hits += int(row.argmax() == b)
        live[a, b] += 1.0
    return hits


PERSISTENCE_GRID = tuple(round(x, 2) for x in np.arange(0.0, 1.01, 0.05))


def _count_transitions(sequences, n_states: int) -> np.ndarray:
    """Laplace-smoothed P(next | current) from latent-id sequences."""
    counts = np.full((n_states, n_states), LAPLACE)
    for lat in sequences:
        for a, b in zip(lat[:-1], lat[1:]):
            counts[a, b] += 1.0
    return counts / counts.sum(axis=1, keepdims=True)


def _fit_persistence_weight(model: NetStateModel, observations) -> float:
    """Choose the interpolation weight by leave-one-day-out over the training days.

    Two earlier protocols were wrong and are worth recording, because both
    produced a confident number that did not transfer:

    1. Counting transitions over all training windows and then scoring lambda on
       the last 20% of those same windows. The matrix had already absorbed every
       transition it was tested on, so it always won and lambda came out 0.0.
    2. Counting on the first 80% and scoring on the tail. No leak, but the tail
       is the same traffic as the rest of its day, so it never asked the question
       that matters. It chose 0.05, which changed almost no argmax, while
       persistence still beat the model by nine points on the test days.

    The real difficulty is transfer to a day with a different attack mix, so the
    fold has to be a whole day: count on two training days, score lambda on the
    third, sum over the three folds. The test days are never touched.
    """
    per_day = [model.encode(states) for _, states, _ in observations]
    per_day = [lat for lat in per_day if len(lat) >= 2]
    if len(per_day) < 2:
        return 0.0

    eye = np.eye(model.n_states)
    scores = {w: 0 for w in PERSISTENCE_GRID}
    total = 0
    for i, held in enumerate(per_day):
        train = [lat for j, lat in enumerate(per_day) if j != i]
        T0 = _count_transitions(train, model.n_states)
        pairs = list(zip(held[:-1], held[1:]))
        total += len(pairs)
        for w in PERSISTENCE_GRID:
            T = (1.0 - w) * T0 + w * eye
            scores[w] += sum(int(T[a].argmax() == b) for a, b in pairs)

    if not total:
        return 0.0
    # Ties go to the smaller weight: lean on the learned matrix, not the baseline.
    return float(max(PERSISTENCE_GRID, key=lambda w: (scores[w], -w)))


def load_flows(days: list[str] | None = None):
    """Read only the columns the model uses. The parquet is 308 MB."""
    import pandas as pd
    cols = FLOW_FEATURES + ["day", "label"]
    df = pd.read_parquet(FLOWS, columns=cols)
    return df if days is None else df[df["day"].isin(days)]


def train(*, n_states: int = N_STATES, window: int = WINDOW) -> NetStateModel:
    df = load_flows(TRAIN_DAYS)
    obs = build_observations(df, TRAIN_DAYS, window=window)
    return fit(obs, n_states=n_states, window=window, trained_on=", ".join(TRAIN_DAYS))


# ─── Self-check ───────────────────────────────────────────────────────────────
def _selftest() -> None:
    """Runs without the dataset: a synthetic two-regime signal the model must
    recover. Regime B is noisy and compromised, regime A is quiet and clean; a
    working transition model must forecast a higher attack probability from B."""
    rng = np.random.default_rng(0)
    n, w = 40, 8

    def block(loc, scale, attack):
        f = rng.normal(loc, scale, size=(n * w, len(FLOW_FEATURES)))
        return f, np.full(n * w, attack, dtype=float)

    fa, ya = block(0.0, 0.2, 0.0)
    fb, yb = block(6.0, 2.0, 1.0)
    import pandas as pd
    frames = []
    for f, y, day in ((fa, ya, "A"), (fb, yb, "B")):
        d = pd.DataFrame(f, columns=FLOW_FEATURES)
        d["label"], d["day"] = y, day
        frames.append(d)
    df = pd.concat(frames, ignore_index=True)

    obs = build_observations(df, ["A", "B"], window=w)
    assert len(obs) == 2, obs
    m = fit(obs, n_states=4, window=w)

    assert m.transitions.shape == (4, 4)
    assert np.allclose(m.transitions.sum(axis=1), 1.0), "rows must be distributions"

    quiet = m.forecast(np.vstack([o[1] for o in obs if o[0] == "A"]), horizon=3)
    noisy = m.forecast(np.vstack([o[1] for o in obs if o[0] == "B"]), horizon=3)
    assert noisy["current_state_attack_rate"] > quiet["current_state_attack_rate"], (
        noisy["current_state_attack_rate"], quiet["current_state_attack_rate"])

    cum = [s["cumulative_probability"] for s in noisy["steps"]]
    assert cum == sorted(cum), f"cumulative probability must never fall: {cum}"

    d = m.describe_state(noisy["current_state"])
    assert d["distinguishing_features"], d

    # the online tracker must stay causal and stay a probability model
    t = OnlineTracker(m, prior_strength=2.0)
    seq = np.vstack([o[1] for o in obs if o[0] == "B"])
    t.observe(seq[0])
    for v in seq[1:]:
        f = t.forecast(horizon=2)
        assert 0.0 <= f["steps"][0]["attack_probability"] <= 1.0, f
        t.observe(v)
    assert t.n_observed == len(seq)
    assert np.allclose(t.transition_matrix().sum(axis=1), 1.0)

    print(f"netstate ok: {m.n_states} latent states, {STATE_DIM}-dim windows · "
          f"compromised regime forecasts {noisy['steps'][0]['attack_probability']:.3f} "
          f"vs {quiet['steps'][0]['attack_probability']:.3f} for the quiet one · "
          f"online tracker adapted over {t.n_observed} windows")


if __name__ == "__main__":
    _selftest()
