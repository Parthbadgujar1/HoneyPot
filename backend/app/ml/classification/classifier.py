"""Supervised behaviour classifiers.

Implements a common classifier interface backed by scikit-learn and XGBoost.
Each classifier records version, features, metrics, and persistence.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

from app.ml.base import BaseModelWrapper
from app.telemetry.features import FEATURE_NAMES, CATEGORICAL_STAGES


class BaseClassifier(BaseModelWrapper):
    model_type = "classifier"

    def __init__(self, version: str = "v0", classes: Optional[List[str]] = None, **kwargs):
        super().__init__(version=version)
        self.classes = classes or CATEGORICAL_STAGES
        self.feature_version = "v1"

    def fit(self, X, y=None) -> "BaseClassifier":
        self.model.fit(X, y)
        self.trained_at = datetime.utcnow()
        return self

    def predict(self, X) -> Any:
        return self.model.predict(X)

    def predict_proba(self, X) -> Any:
        if hasattr(self.model, "predict_proba"):
            return self.model.predict_proba(X)
        return None

    def evaluate(self, X_test, y_test, class_names: Optional[List[str]] = None) -> Dict[str, Any]:
        preds = self.predict(X_test)
        acc = accuracy_score(y_test, preds)
        f1 = f1_score(y_test, preds, average="weighted", zero_division=0)
        prec = precision_score(y_test, preds, average="weighted", zero_division=0)
        rec = recall_score(y_test, preds, average="weighted", zero_division=0)
        self.metrics = {
            "accuracy": acc,
            "f1_weighted": f1,
            "precision_weighted": prec,
            "recall_weighted": rec,
            "n_train": int(getattr(self, "_n_train", 0)),
            "n_test": len(y_test),
        }
        return self.metrics


class LogisticRegressionClassifier(BaseClassifier):
    name = "logistic_regression"

    def __init__(self, version: str = "v0", classes=None, **kwargs):
        super().__init__(version=version, classes=classes)
        from sklearn.linear_model import LogisticRegression

        self.model = LogisticRegression(max_iter=1000, multi_class="multinomial")


class RandomForestClassifier(BaseClassifier):
    name = "random_forest"

    def __init__(self, version: str = "v0", classes=None, **kwargs):
        super().__init__(version=version, classes=classes)
        from sklearn.ensemble import RandomForestClassifier as _RFC

        self.model = _RFC(n_estimators=150, max_depth=12, random_state=42, n_jobs=-1)


class XGBoostClassifier(BaseClassifier):
    name = "xgboost"

    def __init__(self, version: str = "v0", classes=None, **kwargs):
        super().__init__(version=version, classes=classes)
        from xgboost import XGBClassifier

        self.model = XGBClassifier(
            n_estimators=200,
            max_depth=6,
            learning_rate=0.1,
            use_label_encoder=False,
            eval_metric="mlogloss",
            verbosity=0,
        )


CLASSIFIER_REGISTRY = {
    "logistic_regression": LogisticRegressionClassifier,
    "random_forest": RandomForestClassifier,
    "xgboost": XGBoostClassifier,
}


def create_classifier(name: str, version: str = "v0") -> BaseClassifier:
    name = name.lower()
    if name not in CLASSIFIER_REGISTRY:
        raise ValueError(f"Unknown classifier: {name}")
    return CLASSIFIER_REGISTRY[name](version=version)
