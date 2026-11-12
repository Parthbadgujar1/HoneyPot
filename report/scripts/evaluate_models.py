"""Re-evaluate the project's two detection models for the project report.

Writes every number and curve used in Chapter IV to a JSON file, so each table
and graph in the report can be regenerated. The deployed .joblib files are only
read, never changed. Models trained here stay in memory and are not saved.

    python evaluate_models.py <project root> <output json>

Data-leakage measures:
* CIC-IDS2017 ships no official split and is full of duplicate flows, so exact
  duplicates are removed before a stratified 70/10/20 split.
* UNSW-NB15 uses its official training and testing files. Training rows that
  also appear in the testing file are removed from the training data.
* The validation part is used only to choose hyperparameters. The test part is
  used once, for the final numbers.
"""

from __future__ import annotations

import json
import sys
import time
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.base import clone
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, average_precision_score, confusion_matrix, f1_score,
    matthews_corrcoef, precision_recall_curve, precision_score, recall_score,
    roc_auc_score, roc_curve,
)
from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.naive_bayes import GaussianNB
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier

warnings.filterwarnings("ignore")

ROOT = Path(sys.argv[1])
OUT = Path(sys.argv[2])
SEED = 42
RESULTS: dict = {"seed": SEED}

# Features the live sensor can measure itself (sensor/ml.py: cic_row, unsw_row).
# The sensor leaves every other feature missing for the median imputer to fill.
CIC_LIVE = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Subflow Fwd Packets",
    "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes", "SYN Flag Count",
    "ACK Flag Count", "FIN Flag Count", "RST Flag Count", "PSH Flag Count", "Down/Up Ratio",
    "Average Packet Size", "Avg Fwd Segment Size", "Avg Bwd Segment Size",
    "Bwd Packet Length Mean", "Flow Bytes/s", "Flow Packets/s", "Fwd Packets/s",
    "Bwd Packets/s", "Fwd Packet Length Max", "Fwd Packet Length Min",
    "Fwd Packet Length Mean", "Fwd Packet Length Std", "Max Packet Length",
    "Min Packet Length", "Packet Length Mean",
]
UNSW_LIVE = [
    "dur", "proto", "service", "state", "spkts", "dpkts", "sbytes", "dbytes", "rate",
    "sload", "dload", "smean", "dmean", "trans_depth", "is_ftp_login", "ct_ftp_cmd",
    "is_sm_ips_ports", "ct_srv_src", "ct_src_ltm", "ct_dst_ltm", "ct_dst_src_ltm",
    "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_srv_dst", "ct_flw_http_mthd",
]


def save() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(RESULTS, indent=1, default=_plain), encoding="utf-8")


def _plain(value):
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, (np.floating,)):
        return float(value)
    if isinstance(value, np.ndarray):
        return value.tolist()
    return str(value)


def log(message: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {message}", flush=True)


def metrics(y_true, proba, threshold: float = 0.5) -> dict:
    y_true = np.asarray(y_true)
    predicted = (proba >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, predicted, labels=[0, 1]).ravel()
    out = {
        "n": int(len(y_true)), "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
        "accuracy": accuracy_score(y_true, predicted),
        "precision": precision_score(y_true, predicted, zero_division=0),
        "recall": recall_score(y_true, predicted, zero_division=0),
        "f1": f1_score(y_true, predicted, zero_division=0),
        "specificity": tn / (tn + fp) if tn + fp else None,
        "fpr": fp / (fp + tn) if fp + tn else None,
        "mcc": matthews_corrcoef(y_true, predicted),
    }
    if len(set(y_true.tolist())) == 2:
        out["roc_auc"] = roc_auc_score(y_true, proba)
        out["pr_auc"] = average_precision_score(y_true, proba)
    return out


def curves(y_true, proba, points: int = 300) -> dict:
    fpr, tpr, _ = roc_curve(y_true, proba)
    precision, recall, _ = precision_recall_curve(y_true, proba)

    def thin(x, y):
        index = np.unique(np.linspace(0, len(x) - 1, min(points, len(x))).astype(int))
        return [round(float(v), 6) for v in x[index]], [round(float(v), 6) for v in y[index]]

    fpr, tpr = thin(fpr, tpr)
    recall, precision = thin(recall, precision)
    return {"fpr": fpr, "tpr": tpr, "recall": recall, "precision": precision}


def threshold_sweep(y_true, proba) -> list[dict]:
    rows = []
    for threshold in (0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9):
        item = metrics(y_true, proba, threshold)
        rows.append({
            "threshold": threshold, "precision": item["precision"], "recall": item["recall"],
            "f1": item["f1"], "fpr": item["fpr"],
        })
    return rows


def positive(model, frame) -> np.ndarray:
    return model.predict_proba(frame)[:, list(model.classes_).index(1)]


def latency_ms(model, frame, rows: int = 200) -> dict:
    """Per-flow scoring time, one row at a time, as the live sensor does."""
    if hasattr(model, "named_steps") and "classifier" in model.named_steps:
        model.set_params(classifier__n_jobs=1)
    sample = frame.sample(min(rows, len(frame)), random_state=SEED)
    times = []
    for i in range(len(sample)):
        start = time.perf_counter()
        model.predict_proba(sample.iloc[[i]])
        times.append((time.perf_counter() - start) * 1000)
    if hasattr(model, "named_steps") and "classifier" in model.named_steps:
        model.set_params(classifier__n_jobs=-1)
    return {"mean": float(np.mean(times)), "p95": float(np.percentile(times, 95))}


def importances(pipeline, names: list[str], top: int = 15) -> list[dict]:
    values = pipeline.named_steps["classifier"].feature_importances_
    order = np.argsort(values)[::-1][:top]
    return [{"feature": str(names[i]), "importance": float(values[i])} for i in order]


def rf(**overrides) -> RandomForestClassifier:
    params = dict(n_estimators=100, class_weight="balanced", random_state=SEED, n_jobs=-1)
    params.update(overrides)
    return RandomForestClassifier(**params)


GRID = [
    {"n_estimators": 50, "max_depth": None}, {"n_estimators": 100, "max_depth": None},
    {"n_estimators": 200, "max_depth": None}, {"n_estimators": 100, "max_depth": 10},
    {"n_estimators": 100, "max_depth": 20},
    {"n_estimators": 100, "max_depth": None, "min_samples_leaf": 5},
]


def tune(make, x_train, y_train, x_val, y_val) -> list[dict]:
    rows = []
    for params in GRID:
        start = time.time()
        model = make(rf(**params)).fit(x_train, y_train)
        fit_s = time.time() - start
        item = metrics(y_val, positive(model, x_val))
        rows.append({**{k: str(v) if v is None else v for k, v in params.items()},
                     "val_f1": item["f1"], "val_precision": item["precision"],
                     "val_recall": item["recall"], "val_roc_auc": item.get("roc_auc"),
                     "fit_s": fit_s})
        log(f"  grid {params}: val F1 {item['f1']:.5f}")
    return rows


def cross_validate_rf(make, x, y, folds: int = 5) -> dict:
    scores = {name: [] for name in ("accuracy", "precision", "recall", "f1", "roc_auc")}
    splitter = StratifiedKFold(n_splits=folds, shuffle=True, random_state=SEED)
    for fit_index, test_index in splitter.split(x, y):
        model = make(rf()).fit(x.iloc[fit_index], y.iloc[fit_index])
        item = metrics(y.iloc[test_index], positive(model, x.iloc[test_index]))
        for name in scores:
            scores[name].append(item[name])
    return {name: {"mean": float(np.mean(v)), "std": float(np.std(v))} for name, v in scores.items()}


# ---------------------------------------------------------------------------
# CIC-IDS2017: BENIGN vs PortScan
# ---------------------------------------------------------------------------

def load_cic(path: Path, features: list[str]) -> pd.DataFrame:
    frame = pd.read_csv(path, low_memory=False, encoding="latin-1")
    frame.columns = [c.strip() for c in frame.columns]
    frame[features] = frame[features].apply(pd.to_numeric, errors="coerce")
    frame["Label"] = frame["Label"].astype(str).str.strip()
    return frame


def evaluate_cic() -> None:
    schema = json.loads((ROOT / "cicids2017_feature_schema.json").read_text(encoding="utf-8"))
    features = schema["features"]
    deployed = joblib.load(ROOT / "cicids2017_portscan_model.joblib")
    deployed.set_params(classifier__n_jobs=-1)

    folder = ROOT / "MachineLearningCVE"
    friday = load_cic(folder / "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv", features)
    y_all = (friday["Label"] == "PortScan").astype(int)
    numeric = friday[features].to_numpy(dtype=float)

    report: dict = {
        "file_rows": int(len(friday)),
        "class_counts": friday["Label"].value_counts().to_dict(),
        "feature_count": len(features),
        "missing_values": int(np.isnan(numeric).sum()),
        "infinite_values": int(np.isinf(numeric).sum()),
        "duplicate_rows": int(friday[features + ["Label"]].duplicated().sum()),
        "rows_per_file": {},
    }
    RESULTS["cic"] = report

    clean = friday[features + ["Label"]].replace([np.inf, -np.inf], np.nan)
    log("CIC: deployed model on the whole Friday file")
    proba = positive(deployed, clean[features])
    report["deployed_full_file"] = metrics(y_all, proba)

    deduped = clean.drop_duplicates().reset_index(drop=True)
    y = (deduped["Label"] == "PortScan").astype(int)
    x = deduped[features]
    conflicting = deduped[features].duplicated(keep=False).sum()
    report["after_dedup_rows"] = int(len(deduped))
    report["after_dedup_counts"] = deduped["Label"].value_counts().to_dict()
    report["conflicting_label_rows"] = int(conflicting)

    x_rest, x_test, y_rest, y_test = train_test_split(
        x, y, test_size=0.20, stratify=y, random_state=SEED)
    x_train, x_val, y_train, y_val = train_test_split(
        x_rest, y_rest, test_size=0.125, stratify=y_rest, random_state=SEED)
    report["split"] = {
        "train": int(len(x_train)), "validation": int(len(x_val)), "test": int(len(x_test)),
        "train_positive": int(y_train.sum()), "validation_positive": int(y_val.sum()),
        "test_positive": int(y_test.sum()),
    }
    report["deployed_on_test_split_not_held_out"] = metrics(y_test, positive(deployed, x_test))
    save()

    def make(classifier):
        return Pipeline([("imputer", SimpleImputer(strategy="median")), ("classifier", classifier)])

    log("CIC: hyperparameter grid")
    report["grid"] = tune(make, x_train, y_train, x_val, y_val)
    save()

    candidates = {
        "Gaussian Naive Bayes": Pipeline([
            ("imputer", SimpleImputer(strategy="median")), ("scaler", StandardScaler()),
            ("classifier", GaussianNB())]),
        "Logistic Regression": Pipeline([
            ("imputer", SimpleImputer(strategy="median")), ("scaler", StandardScaler()),
            ("classifier", LogisticRegression(max_iter=2000, class_weight="balanced"))]),
        "Decision Tree": make(DecisionTreeClassifier(class_weight="balanced", random_state=SEED)),
        "Random Forest (project)": make(rf()),
        "Hist. Gradient Boosting": make(HistGradientBoostingClassifier(random_state=SEED)),
    }
    report["held_out"] = {}
    fitted = {}
    for name, model in candidates.items():
        log(f"CIC: fitting {name}")
        start = time.time()
        model.fit(x_train, y_train)
        fit_s = time.time() - start
        proba = positive(model, x_test)
        report["held_out"][name] = {**metrics(y_test, proba), "fit_s": fit_s}
        fitted[name] = (model, proba)
        save()

    best, proba = fitted["Random Forest (project)"]
    report["curves"] = curves(y_test, proba)
    report["baseline_curves"] = {
        name: curves(y_test, value[1], 150) for name, value in fitted.items()
        if name != "Random Forest (project)"
    }
    report["threshold_sweep"] = threshold_sweep(y_test, proba)
    report["importances"] = importances(best, features)
    report["latency_ms_deployed"] = latency_ms(deployed, x_test)

    log("CIC: 5-fold cross-validation on the training part")
    report["cv"] = cross_validate_rf(make, x_rest, y_rest)
    save()

    # What the live sensor can see: only CIC_LIVE is measured, the rest is missing.
    masked = x_test.copy()
    unmeasured = [c for c in features if c not in CIC_LIVE]
    masked[unmeasured] = np.nan
    report["live_measured_features"] = len(CIC_LIVE)
    report["live_feature_coverage"] = len(CIC_LIVE) / len(features)
    report["held_out_live_features_only"] = metrics(y_test, positive(best, masked))
    report["deployed_live_features_only"] = metrics(y_test, positive(deployed, masked))

    # Other days: the held-out model has never seen these benign flows or attacks.
    report["other_days"] = []
    for path in sorted(folder.glob("*.csv")):
        report["rows_per_file"][path.name] = None
        day = load_cic(path, features)
        report["rows_per_file"][path.name] = int(len(day))
        if path.name.startswith("Friday-WorkingHours-Afternoon-PortScan"):
            continue
        log(f"CIC: scoring {path.name}")
        frame = day[features].replace([np.inf, -np.inf], np.nan)
        flagged = positive(best, frame) >= 0.5
        by_label = pd.DataFrame({"label": day["Label"], "flagged": flagged})
        grouped = by_label.groupby("label")["flagged"].agg(["count", "sum"]).reset_index()
        report["other_days"].append({
            "file": path.name,
            "labels": [
                {"label": str(row["label"]).encode("ascii", "ignore").decode(),
                 "rows": int(row["count"]), "flagged_portscan": int(row["sum"])}
                for _, row in grouped.iterrows()
            ],
        })
        save()

    report["samples"] = {
        label: friday[friday["Label"] == label].head(4)[
            ["Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
             "Flow Bytes/s", "Flow Packets/s", "SYN Flag Count", "Label"]
        ].replace([np.inf, -np.inf], np.nan).to_dict("records")
        for label in ("BENIGN", "PortScan")
    }
    save()


# ---------------------------------------------------------------------------
# UNSW-NB15: Normal vs Reconnaissance
# ---------------------------------------------------------------------------

def evaluate_unsw() -> None:
    schema = json.loads((ROOT / "feature_schema (1).json").read_text(encoding="utf-8"))
    features = schema["features"]
    deployed = joblib.load(ROOT / "reconnaissance_model (1).joblib")
    deployed.set_params(classifier__n_jobs=-1)

    train = pd.read_csv(ROOT / "UNSW_NB15_training-set.csv", encoding="utf-8-sig")
    test = pd.read_csv(ROOT / "UNSW_NB15_testing-set.csv", encoding="utf-8-sig")
    for frame in (train, test):
        frame["attack_cat"] = frame["attack_cat"].astype(str).str.strip()

    keep = ["Normal", "Reconnaissance"]
    train_two = train[train["attack_cat"].isin(keep)].copy()
    test_two = test[test["attack_cat"].isin(keep)].copy()
    y_train_all = (train_two["attack_cat"] == "Reconnaissance").astype(int)
    y_test = (test_two["attack_cat"] == "Reconnaissance").astype(int)

    report: dict = {
        "train_rows": int(len(train)), "test_rows": int(len(test)),
        "feature_count": len(features),
        "train_categories": train["attack_cat"].value_counts().to_dict(),
        "test_categories": test["attack_cat"].value_counts().to_dict(),
        "train_two_class": train_two["attack_cat"].value_counts().to_dict(),
        "test_two_class": test_two["attack_cat"].value_counts().to_dict(),
        "missing_values_train": int(train[features].isna().sum().sum()),
        "duplicate_rows_train_two_class": int(train_two[features + ["attack_cat"]].duplicated().sum()),
    }
    RESULTS["unsw"] = report

    log("UNSW: deployed model")
    proba_test = positive(deployed, test_two[features])
    report["deployed_test"] = metrics(y_test, proba_test)
    report["deployed_train"] = metrics(y_train_all, positive(deployed, train_two[features]))
    report["deployed_latency_ms"] = latency_ms(deployed, test_two[features])

    # The label the README's "all attacks" figures were measured against.
    y_any = (test["label"] == 1).astype(int)
    report["deployed_test_all_attacks_as_positive"] = metrics(y_any, positive(deployed, test[features]))
    per_category = positive(deployed, test[features]) >= 0.5
    report["deployed_flag_rate_by_category"] = (
        pd.DataFrame({"cat": test["attack_cat"], "flagged": per_category})
        .groupby("cat")["flagged"].agg(["count", "sum"]).reset_index().to_dict("records")
    )
    save()

    # Remove training rows that also occur in the testing file, then de-duplicate.
    test_keys = set(map(tuple, test[features].astype(str).to_numpy()))
    in_test = np.fromiter(
        (tuple(row) in test_keys for row in train_two[features].astype(str).to_numpy()),
        dtype=bool, count=len(train_two),
    )
    report["train_rows_also_in_test"] = int(in_test.sum())
    clean = train_two[~in_test][features + ["attack_cat"]].drop_duplicates()
    y_clean = (clean["attack_cat"] == "Reconnaissance").astype(int)
    x_clean = clean[features]
    report["train_after_cleaning"] = clean["attack_cat"].value_counts().to_dict()

    x_fit, x_val, y_fit, y_val = train_test_split(
        x_clean, y_clean, test_size=0.125, stratify=y_clean, random_state=SEED)
    report["split"] = {
        "train": int(len(x_fit)), "validation": int(len(x_val)), "test": int(len(test_two)),
        "train_positive": int(y_fit.sum()), "validation_positive": int(y_val.sum()),
        "test_positive": int(y_test.sum()),
    }
    save()

    numeric = [c for c in features if c not in ("proto", "service", "state")]
    source = deployed.named_steps["preprocessor"]

    def make(classifier):
        return Pipeline([("preprocessor", clone(source)), ("classifier", classifier)])

    def make_scaled(classifier):
        return Pipeline([
            ("preprocessor", clone(source)),
            ("scaler", StandardScaler(with_mean=False)),
            ("classifier", classifier),
        ])

    class Dense:
        """Gaussian NB and gradient boosting need dense input."""

        def fit(self, x, y=None):
            return self

        def transform(self, x):
            return x.toarray() if hasattr(x, "toarray") else x

        def get_params(self, deep=True):
            return {}

        def set_params(self, **params):
            return self

    log("UNSW: hyperparameter grid")
    report["grid"] = tune(make, x_fit, y_fit, x_val, y_val)
    save()

    candidates = {
        "Gaussian Naive Bayes": Pipeline([
            ("preprocessor", clone(source)), ("dense", Dense()), ("classifier", GaussianNB())]),
        "Logistic Regression": make_scaled(
            LogisticRegression(max_iter=2000, class_weight="balanced")),
        "Decision Tree": make(DecisionTreeClassifier(class_weight="balanced", random_state=SEED)),
        "Random Forest (project)": make(rf()),
        "Hist. Gradient Boosting": Pipeline([
            ("preprocessor", clone(source)), ("dense", Dense()),
            ("classifier", HistGradientBoostingClassifier(random_state=SEED))]),
    }
    report["held_out"] = {}
    fitted = {}
    for name, model in candidates.items():
        log(f"UNSW: fitting {name}")
        start = time.time()
        model.fit(x_fit, y_fit)
        fit_s = time.time() - start
        proba = positive(model, test_two[features])
        report["held_out"][name] = {**metrics(y_test, proba), "fit_s": fit_s}
        fitted[name] = (model, proba)
        save()

    best, proba = fitted["Random Forest (project)"]
    report["curves"] = curves(y_test, proba)
    report["baseline_curves"] = {
        name: curves(y_test, value[1], 150) for name, value in fitted.items()
        if name != "Random Forest (project)"
    }
    report["threshold_sweep"] = threshold_sweep(y_test, proba)
    report["deployed_curves"] = curves(y_test, proba_test)
    report["deployed_threshold_sweep"] = threshold_sweep(y_test, proba_test)
    names = best.named_steps["preprocessor"].get_feature_names_out()
    report["importances"] = importances(best, [n.split("__", 1)[-1] for n in names])

    log("UNSW: 5-fold cross-validation on the training file")
    report["cv"] = cross_validate_rf(make, x_clean, y_clean)
    save()

    masked = test_two[features].copy()
    unmeasured = [c for c in features if c not in UNSW_LIVE]
    masked[unmeasured] = np.nan
    report["live_measured_features"] = len(UNSW_LIVE)
    report["live_feature_coverage"] = len(UNSW_LIVE) / len(features)
    report["held_out_live_features_only"] = metrics(y_test, positive(best, masked))
    report["deployed_live_features_only"] = metrics(y_test, positive(deployed, masked))

    report["samples"] = {
        label: test_two[test_two["attack_cat"] == label].head(4)[
            ["dur", "proto", "service", "state", "spkts", "dpkts", "sbytes", "rate", "attack_cat"]
        ].to_dict("records")
        for label in keep
    }
    save()


if __name__ == "__main__":
    log("Starting evaluation")
    evaluate_cic()
    log("CIC-IDS2017 done")
    evaluate_unsw()
    log("UNSW-NB15 done")
    save()
    log("Finished")
