"""Load the trained models and score live connections with them.

Two trained pipelines from the HoneyPot project root are used:

* ``cicids2017_portscan_model.joblib`` - BENIGN vs PortScan, trained on
  78 CICFlowMeter flow features (CIC-IDS2017).
* ``reconnaissance_model (1).joblib`` - Normal vs Reconnaissance, trained
  on 42 UNSW-NB15 features.

A live sensor cannot reproduce CICFlowMeter's full flow statistics (IAT,
TCP flag sequences, window sizes, TTLs). Features the sensor measures are
filled in from the connection; the rest are left missing and the model's
own median imputer fills them. ``feature_coverage`` reports how much of
each model's input was actually measured, so analysts can weigh the
scores accordingly. The ML score is a secondary signal next to the
behavioural rules, not a standalone verdict.
"""

from __future__ import annotations

import json
import logging
import math
from collections import deque
from typing import Iterable

import joblib
import numpy as np
import pandas as pd

from .config import model_path

log = logging.getLogger("sensor.ml")

NAN = float("nan")

# Map the decoy's services onto UNSW-NB15 service categories.
UNSW_SERVICES = {
    "http": "http", "ftp": "ftp", "ssh": "ssh", "smtp": "smtp",
    "pop3": "pop3", "dns": "dns", "ssl": "ssl", "irc": "irc",
}


def _div(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else NAN


def cic_row(flow: dict, feature_names: list[str]) -> dict:
    """Build one CIC-IDS2017 feature row from a measured connection."""
    row = {name: NAN for name in feature_names}

    duration = float(flow.get("duration_s") or 0.0)
    fwd_packets = int(flow.get("packets_in") or 1)
    bwd_packets = int(flow.get("packets_out") or 1)
    fwd_bytes = int(flow.get("bytes_in") or 0)
    bwd_bytes = int(flow.get("bytes_out") or 0)
    total_packets = fwd_packets + bwd_packets
    total_bytes = fwd_bytes + bwd_bytes
    sizes = [int(s) for s in (flow.get("chunk_sizes") or [])]

    values = {
        "Destination Port": flow.get("dst_port"),
        "Flow Duration": duration * 1_000_000,  # CICFlowMeter uses microseconds
        "Total Fwd Packets": fwd_packets,
        "Total Backward Packets": bwd_packets,
        "Total Length of Fwd Packets": fwd_bytes,
        "Total Length of Bwd Packets": bwd_bytes,
        "Subflow Fwd Packets": fwd_packets,
        "Subflow Fwd Bytes": fwd_bytes,
        "Subflow Bwd Packets": bwd_packets,
        "Subflow Bwd Bytes": bwd_bytes,
        "SYN Flag Count": 1,
        "ACK Flag Count": 1,
        "FIN Flag Count": int(bool(flow.get("graceful"))),
        "RST Flag Count": int(bool(flow.get("reset"))),
        "PSH Flag Count": int(bool(flow.get("had_payload"))),
        "Down/Up Ratio": _div(bwd_packets, fwd_packets),
        "Average Packet Size": _div(total_bytes, total_packets),
        "Avg Fwd Segment Size": _div(fwd_bytes, fwd_packets),
        "Avg Bwd Segment Size": _div(bwd_bytes, bwd_packets),
        "Bwd Packet Length Mean": _div(bwd_bytes, bwd_packets),
        "Flow Bytes/s": _div(total_bytes, duration),
        "Flow Packets/s": _div(total_packets, duration),
        "Fwd Packets/s": _div(fwd_packets, duration),
        "Bwd Packets/s": _div(bwd_packets, duration),
    }
    if sizes:
        values.update({
            "Fwd Packet Length Max": max(sizes),
            "Fwd Packet Length Min": min(sizes),
            "Fwd Packet Length Mean": float(np.mean(sizes)),
            "Fwd Packet Length Std": float(np.std(sizes)),
            "Max Packet Length": max(sizes),
            "Min Packet Length": min(sizes),
            "Packet Length Mean": float(np.mean(sizes)),
        })

    for name, value in values.items():
        if name in row and value is not None:
            row[name] = float(value)
    return row


def flow_context(flow: dict, recent: Iterable[dict]) -> dict:
    """Connection-count features (UNSW ct_*) over the most recent flows."""
    flows = list(recent) + [flow]
    src = flow["src_ip"]
    port = flow.get("dst_port")
    service = flow.get("service", "-")
    same_src = [f for f in flows if f["src_ip"] == src]
    return {
        "ct_srv_src": sum(1 for f in same_src if f.get("service") == service),
        "ct_src_ltm": len(same_src),
        "ct_dst_ltm": len(same_src),
        "ct_dst_src_ltm": len(same_src),
        "ct_src_dport_ltm": sum(1 for f in same_src if f.get("dst_port") == port),
        "ct_dst_sport_ltm": sum(1 for f in flows if f.get("dst_port") == port),
        "ct_srv_dst": sum(1 for f in flows if f.get("service") == service),
        "ct_flw_http_mthd": sum(int(f.get("http_requests") or 0) for f in same_src),
    }


def unsw_row(flow: dict, ctx: dict, feature_names: list[str]) -> dict:
    """Build one UNSW-NB15 feature row from a measured connection."""
    row = {name: NAN for name in feature_names}

    duration = float(flow.get("duration_s") or 0.0)
    spkts = int(flow.get("packets_in") or 1)
    dpkts = int(flow.get("packets_out") or 1)
    sbytes = int(flow.get("bytes_in") or 0)
    dbytes = int(flow.get("bytes_out") or 0)
    service = UNSW_SERVICES.get(str(flow.get("service", "-")), "-")

    if flow.get("graceful"):
        state = "FIN"
    elif flow.get("reset"):
        state = "RST"
    else:
        state = "CON"

    values = {
        "dur": duration,
        "proto": "tcp",
        "service": service,
        "state": state,
        "spkts": spkts,
        "dpkts": dpkts,
        "sbytes": sbytes,
        "dbytes": dbytes,
        "rate": _div(spkts + dpkts, duration),
        "sload": _div(sbytes * 8, duration),
        "dload": _div(dbytes * 8, duration),
        "smean": _div(sbytes, spkts),
        "dmean": _div(dbytes, dpkts),
        "trans_depth": int(flow.get("http_requests") or 0),
        "is_ftp_login": 0,
        "ct_ftp_cmd": 0,
        "is_sm_ips_ports": 0,
    }
    values.update(ctx)

    for name, value in values.items():
        if name in row:
            row[name] = value
    return row


class ModelBundle:
    """Holds both pipelines. Safe to call ``predict`` from several threads."""

    def __init__(self, config: dict):
        ml = config["ml"]
        self.enabled: bool = ml["enabled"]
        self.cic_weight: float = ml["cic_weight"]
        self.unsw_weight: float = ml["unsw_weight"]
        self.errors: dict[str, str] = {}

        self.cic = None
        self.unsw = None
        self.cic_features: list[str] = []
        self.unsw_features: list[str] = []

        if not self.enabled:
            return

        self.cic, self.cic_features = self._load(
            "cic", ml["cic_model"], ml["cic_schema"]
        )
        self.unsw, self.unsw_features = self._load(
            "unsw", ml["unsw_model"], ml["unsw_schema"]
        )

    def _load(self, label: str, model_file: str, schema_file: str):
        try:
            model = joblib.load(model_path(model_file))
            schema = json.loads(model_path(schema_file).read_text(encoding="utf-8"))
            features = list(schema["features"])

            names = getattr(model, "feature_names_in_", None)
            if names is not None and list(names) != features:
                raise ValueError("model feature names do not match the schema")

            # Score one flow at a time: keep predictions on this thread.
            if hasattr(model, "named_steps") and "classifier" in model.named_steps:
                model.set_params(classifier__n_jobs=1)

            log.info("Loaded %s model (%d features)", label, len(features))
            return model, features
        except Exception as exc:  # the sensor still runs without the model
            self.errors[label] = f"{type(exc).__name__}: {exc}"
            log.error("Could not load %s model: %s", label, self.errors[label])
            return None, []

    def status(self) -> dict:
        return {
            "enabled": self.enabled,
            "cic_loaded": self.cic is not None,
            "unsw_loaded": self.unsw is not None,
            "cic_features": len(self.cic_features),
            "unsw_features": len(self.unsw_features),
            "errors": dict(self.errors),
        }

    def predict(self, flow: dict, recent: Iterable[dict] = ()) -> dict:
        """Return per-model attack probabilities for one measured flow."""
        result = {
            "cic_portscan": None,
            "unsw_recon": None,
            "cic_feature_coverage": None,
            "unsw_feature_coverage": None,
        }
        recent = list(recent)

        if self.cic is not None:
            row = cic_row(flow, self.cic_features)
            frame = pd.DataFrame([row], columns=self.cic_features)
            result["cic_portscan"] = self._positive_probability(self.cic, frame)
            result["cic_feature_coverage"] = _coverage(row)

        if self.unsw is not None:
            ctx = flow_context(flow, recent)
            row = unsw_row(flow, ctx, self.unsw_features)
            frame = pd.DataFrame([row], columns=self.unsw_features)
            result["unsw_recon"] = self._positive_probability(self.unsw, frame)
            result["unsw_feature_coverage"] = _coverage(row)

        return result

    @staticmethod
    def _positive_probability(model, frame: pd.DataFrame) -> float:
        probabilities = model.predict_proba(frame)[0]
        classes = list(model.classes_)
        return float(probabilities[classes.index(1)])

    def combined_points(self, prediction: dict) -> int:
        """Convert model probabilities into score points (0 to weights)."""
        points = 0.0
        if prediction.get("cic_portscan") is not None:
            points += self.cic_weight * prediction["cic_portscan"]
        if prediction.get("unsw_recon") is not None:
            points += self.unsw_weight * prediction["unsw_recon"]
        if math.isnan(points):
            return 0
        return int(round(points))


def _coverage(row: dict) -> float:
    if not row:
        return 0.0
    measured = sum(1 for value in row.values() if not _is_missing(value))
    return round(measured / len(row), 3)


def _is_missing(value) -> bool:
    return value is None or (isinstance(value, float) and math.isnan(value))


def recent_flow_buffer(maxlen: int = 100) -> deque:
    """Buffer of recent flows used for the UNSW connection-count features."""
    return deque(maxlen=maxlen)
