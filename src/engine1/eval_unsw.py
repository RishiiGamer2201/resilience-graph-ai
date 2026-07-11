"""Milestone 2 · E1.x — benign-only UNSW-NB15 anomaly evaluation.

Uses the official split prepared by ``prep_unsw``. Labels and attack categories
are excluded from training and used only for reporting the untouched test split.

Run:
    python -m src.engine1.eval_unsw
"""
from __future__ import annotations

import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.metrics import average_precision_score, precision_recall_fscore_support, roc_auc_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from src.engine1.prep_unsw import ATTACK_CATEGORY, LABEL, LEAKAGE_OR_ID_COLUMNS, OUT_DIR

ROOT = Path(__file__).resolve().parents[2]
TRAIN = OUT_DIR / "train.parquet"
TEST = OUT_DIR / "test.parquet"
MODEL = ROOT / "models" / "iforest_unsw_nb15.joblib"
REPORT = ROOT / "reports" / "unsw_evaluation.md"
RANDOM_STATE = 42
FPR_PERCENTILE = 99.0


def load_splits() -> tuple[pd.DataFrame, pd.DataFrame, list[str]]:
    missing = [path for path in (TRAIN, TEST) if not path.exists()]
    if missing:
        names = ", ".join(str(path.relative_to(ROOT)) for path in missing)
        raise FileNotFoundError(f"Missing prepared UNSW artifact(s): {names}. Run python -m src.engine1.prep_unsw first.")
    train, test = pd.read_parquet(TRAIN), pd.read_parquet(TEST)
    features = [column for column in train.columns if column not in LEAKAGE_OR_ID_COLUMNS | {LABEL}]
    missing_features = set(features) - set(test.columns)
    if missing_features:
        raise ValueError(f"Official test split lacks training feature(s): {sorted(missing_features)}")
    return train, test, features


def make_preprocessor(frame: pd.DataFrame, features: list[str]) -> ColumnTransformer:
    numeric = [column for column in features if pd.api.types.is_numeric_dtype(frame[column])]
    categorical = [column for column in features if column not in numeric]
    return ColumnTransformer([
        ("numeric", Pipeline([("impute", SimpleImputer(strategy="median")), ("scale", StandardScaler())]), numeric),
        ("categorical", Pipeline([("impute", SimpleImputer(strategy="most_frequent")), ("onehot", OneHotEncoder(handle_unknown="ignore"))]), categorical),
    ])


def metrics(y_true: np.ndarray, scores: np.ndarray, threshold: float) -> dict:
    predicted = scores >= threshold
    precision, recall, f1, _ = precision_recall_fscore_support(y_true, predicted, average="binary", zero_division=0)
    return {"pr_auc": float(average_precision_score(y_true, scores)), "roc_auc": float(roc_auc_score(y_true, scores)), "precision": float(precision), "recall": float(recall), "f1": float(f1), "alert_rate": float(predicted.mean())}


def per_attack_recall(categories: pd.Series, labels: np.ndarray, scores: np.ndarray, threshold: float) -> pd.DataFrame:
    flagged = scores >= threshold
    rows = []
    for category in sorted(categories[labels == 1].dropna().unique()):
        mask = (categories.to_numpy() == category) & (labels == 1)
        rows.append({"attack_category": str(category), "n": int(mask.sum()), "caught": int(flagged[mask].sum()), "recall": float(flagged[mask].mean())})
    return pd.DataFrame(rows).sort_values("recall", ascending=False)


def main() -> None:
    train, test, features = load_splits()
    benign_train = train.loc[train[LABEL] == 0, features]
    if benign_train.empty or test[LABEL].nunique() < 2:
        raise ValueError("Need benign training rows and both classes in the untouched official test split.")
    preprocessor = make_preprocessor(benign_train, features)
    X_train = preprocessor.fit_transform(benign_train)
    X_test = preprocessor.transform(test[features])
    detector = IsolationForest(n_estimators=200, max_samples=4096, contamination="auto", random_state=RANDOM_STATE, n_jobs=-1).fit(X_train)
    train_scores = -detector.score_samples(X_train)
    test_scores = -detector.score_samples(X_test)
    threshold = float(np.percentile(train_scores, FPR_PERCENTILE))
    labels = test[LABEL].to_numpy(dtype="int8")
    rng = np.random.default_rng(RANDOM_STATE)
    random_scores = rng.random(len(test))
    random_threshold = float(np.percentile(random_scores, FPR_PERCENTILE))
    rule_feature = "sbytes" if "sbytes" in features else next(column for column in features if pd.api.types.is_numeric_dtype(train[column]))
    rule_train = pd.to_numeric(benign_train[rule_feature], errors="coerce").fillna(0).to_numpy()
    rule_test = pd.to_numeric(test[rule_feature], errors="coerce").fillna(0).to_numpy()
    rule_threshold = float(np.percentile(rule_train, FPR_PERCENTILE))
    results = {"Random": metrics(labels, random_scores, random_threshold), "Rule": metrics(labels, rule_test, rule_threshold), "IsolationForest": metrics(labels, test_scores, threshold)}
    recall = per_attack_recall(test.get(ATTACK_CATEGORY, pd.Series("unknown", index=test.index)), labels, test_scores, threshold)
    MODEL.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"preprocessor": preprocessor, "model": detector, "features": features, "threshold": threshold, "training": "official UNSW train benign rows only"}, MODEL)
    prevalence = float(labels.mean())
    lift_random = results["IsolationForest"]["pr_auc"] / max(results["Random"]["pr_auc"], 1e-9)
    lift_rule = results["IsolationForest"]["pr_auc"] / max(results["Rule"]["pr_auc"], 1e-9)
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# UNSW-NB15 benign-only anomaly evaluation", "", "The official train/test split is preserved. IsolationForest and preprocessing fit only on benign official-training rows; labels/categories are evaluation-only.", "", f"- Train benign rows: **{len(benign_train):,}** · test rows: **{len(test):,}** · test attack prevalence: **{prevalence:.2%}**", f"- Feature count: **{len(features)}**; identifier `id` and label-derived `attack_cat` excluded.", f"- Threshold: {FPR_PERCENTILE:.0f}th percentile of benign-training anomaly scores (no test-label selection).", "", "| Method | PR-AUC | ROC-AUC | Precision | Recall | F1 | Alert rate |", "|---|---:|---:|---:|---:|---:|---:|"]
    for name in ("Random", "Rule", "IsolationForest"):
        row = results[name]
        lines.append(f"| {name}{f' ({rule_feature})' if name == 'Rule' else ''} | {row['pr_auc']:.4f} | {row['roc_auc']:.4f} | {row['precision']:.4f} | {row['recall']:.4f} | {row['f1']:.4f} | {row['alert_rate']:.2%} |")
    lines += ["", f"- IsolationForest PR-AUC lift: **{lift_random:.2f}×** over random and **{lift_rule:.2f}×** over the `{rule_feature}` rule.", "", "## Per-attack-category recall (IsolationForest)", "", "| Category | Count | Caught | Recall |", "|---|---:|---:|---:|"]
    lines += [f"| {row.attack_category} | {row.n:,} | {row.caught:,} | {row.recall:.3f} |" for row in recall.itertuples(index=False)]
    REPORT.write_text("\n".join(lines), encoding="utf-8")
    print(f"UNSW PR-AUC={results['IsolationForest']['pr_auc']:.4f}; lift={lift_random:.2f}x random; -> {REPORT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
