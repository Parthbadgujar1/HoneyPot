"""Common ML model interface and persistence helpers."""

import json
import os
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, Optional

import joblib

from app.core.config import get_settings

settings = get_settings()


class BaseModelWrapper(ABC):
    """Common interface for all ML models used by the platform."""

    name: str = "base"
    model_type: str = "unknown"

    def __init__(self, version: str = "v0", **kwargs):
        self.version = version
        self.metrics: Dict[str, Any] = {}
        self.artifact_path: Optional[str] = None
        self.trained_at: Optional[datetime] = None
        self.feature_version: Optional[str] = None

    @abstractmethod
    def fit(self, X, y=None) -> "BaseModelWrapper":
        ...

    @abstractmethod
    def predict(self, X) -> Any:
        ...

    def save(self, directory: Optional[str] = None) -> str:
        directory = directory or settings.ML_MODELS_DIR
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, f"{self.name}-{self.version}.joblib")
        joblib.dump(self, path)
        self.artifact_path = path
        self._save_meta(directory)
        return path

    def _save_meta(self, directory: str) -> None:
        meta_path = os.path.join(directory, f"{self.name}-{self.version}.json")
        meta = {
            "name": self.name,
            "model_type": self.model_type,
            "version": self.version,
            "trained_at": self.trained_at.isoformat() if self.trained_at else None,
            "metrics": self.metrics,
            "feature_version": self.feature_version,
            "artifact_path": self.artifact_path,
        }
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2, default=str)

    @classmethod
    def load(cls, path: str) -> "BaseModelWrapper":
        return joblib.load(path)


def load_model(path: str):
    return joblib.load(path)
