from __future__ import annotations

from collections import OrderedDict, deque
from collections.abc import Iterable
import math
import json
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest
from threadpoolctl import threadpool_limits

from app.models import EventType, Finding, NetworkEvent


class IsolationForestDetector:
    """Calibrated Isolation Forest using the same features for baseline and inference."""

    feature_names = ("connection_rate", "fan_out", "distinct_ports", "new_edge",
                     "failed_ratio", "time_of_window", "connection_count", "bytes_per_connection")

    def __init__(self, window_seconds: float = 10.0, false_positive_target: float = 0.01,
                 seed: int = 7, max_window_events: int = 20000, max_sources: int = 1024) -> None:
        if not math.isfinite(window_seconds) or window_seconds <= 0:
            raise ValueError("window_seconds must be positive and finite")
        if not 0 < false_positive_target < 1:
            raise ValueError("false_positive_target must be between zero and one")
        if max_window_events < 1 or max_sources < 1:
            raise ValueError("window/source capacities must be positive")
        self.window_seconds = window_seconds
        self.false_positive_target = false_positive_target
        self.seed = seed
        self.max_window_events, self.max_sources = max_window_events, max_sources
        self._windows: OrderedDict[str, deque[NetworkEvent]] = OrderedDict()
        self._known_edges: set[tuple[str, str, int, str]] = set()
        self._started_at: dict[str, float] = {}
        self._model: IsolationForest | None = None
        self.threshold = 0.0
        self.last_score: dict | None = None
        self.window_overflows = 0
        self.out_of_order = 0
        self._overflow_at: dict[str, float] = {}
        self._training: list[list[float]] = []
        self.metadata: dict = {}

    @staticmethod
    def eligible(event: NetworkEvent) -> bool:
        return (event.counts_as_connection and event.event_type in (EventType.CONNECT, EventType.ACCEPT)
                and event.attribution != "unknown")

    def reset_windows(self) -> None:
        self._windows.clear()
        self._started_at.clear()
        self._overflow_at.clear()

    @staticmethod
    def edge(event: NetworkEvent) -> tuple[str, str, int, str]:
        return event.src_service, event.dst_service, event.dst_port, event.protocol

    def features(self, event: NetworkEvent) -> dict[str, float]:
        key = event.source_key()
        if key not in self._windows:
            if len(self._windows) >= self.max_sources:
                removed, _ = self._windows.popitem(last=False)
                self._started_at.pop(removed, None)
                self._overflow_at.pop(removed, None)
            self._windows[key] = deque()
        self._windows.move_to_end(key)
        window = self._windows[key]
        self._started_at.setdefault(key, event.timestamp_mono)
        if window and event.timestamp_mono < window[-1].timestamp_mono:
            raise ValueError("events must be ordered by monotonic timestamp per source")
        window.append(event)
        while window and event.timestamp_mono - window[0].timestamp_mono >= self.window_seconds:
            window.popleft()
        if len(window) > self.max_window_events:
            window.popleft()
            self.window_overflows += 1
            self._overflow_at[key] = event.timestamp_mono
        edge_events = [item for item in window if item.destination_key() == event.destination_key()
                       and item.dst_port == event.dst_port and item.protocol == event.protocol]
        byte_counts = [item.bytes_count for item in edge_events if item.bytes_count is not None]
        outcomes = [item.failed if item.source == "simulator" else item.outcome == "failed"
                    for item in edge_events if item.source == "simulator" or item.outcome in ("succeeded", "failed")]
        return {
            "connection_rate": len(edge_events) / self.window_seconds,
            "fan_out": float(len({item.destination_key() for item in window})),
            "distinct_ports": float(len({item.dst_port for item in window})),
            "new_edge": float(self.edge(event) not in self._known_edges),
            "failed_ratio": sum(outcomes) / len(outcomes) if outcomes else 0.0,
            "time_of_window": (event.timestamp_mono % self.window_seconds) / self.window_seconds,
            "connection_count": float(len(edge_events)),
            "bytes_per_connection": sum(byte_counts) / len(byte_counts) if byte_counts else 0.0,
        }

    def fit_baseline(self, samples: list[list[float]]) -> None:
        matrix = np.asarray(samples, dtype=float)
        if matrix.ndim != 2 or matrix.shape[0] < 2 or matrix.shape[1] != len(self.feature_names):
            raise ValueError(f"baseline needs at least two rows of {len(self.feature_names)} features")
        if not np.isfinite(matrix).all():
            raise ValueError("baseline features must be finite")
        self._training = matrix.tolist()
        self._model = IsolationForest(random_state=self.seed, contamination="auto", n_estimators=100, n_jobs=1)
        with threadpool_limits(limits=1):
            self._model.fit(matrix)
            scores = -self._model.score_samples(matrix)
        self.threshold = float(np.quantile(scores, 1 - self.false_positive_target))
        self.reset_windows()

    def calibrate(self, samples: list[list[float]]) -> None:
        matrix = np.asarray(samples, dtype=float)
        if self._model is None or matrix.ndim != 2 or matrix.shape[0] < 2 or matrix.shape[1] != len(self.feature_names):
            raise ValueError("calibration requires a fitted model and independent feature rows")
        if not np.isfinite(matrix).all():
            raise ValueError("calibration features must be finite")
        with threadpool_limits(limits=1):
            scores = -self._model.score_samples(matrix)
        self.threshold = float(np.quantile(scores, 1 - self.false_positive_target, method="higher"))
        self.metadata["calibration_rows"] = len(samples)
        self.metadata["calibration_fpr"] = float(np.mean(scores > self.threshold))
        self.reset_windows()

    def save(self, path: str | Path) -> None:
        """JSON model recipe, avoiding executable pickle deserialization."""
        if self._model is None:
            raise ValueError("model is not fitted")
        import sklearn
        value = {"version": 1, "sklearn": sklearn.__version__, "feature_names": self.feature_names,
            "window_seconds": self.window_seconds, "false_positive_target": self.false_positive_target,
            "seed": self.seed, "threshold": self.threshold, "known_edges": sorted(self._known_edges),
            "training": self._training, "metadata": self.metadata,
            "max_window_events": self.max_window_events, "max_sources": self.max_sources}
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(value, allow_nan=False), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path):
        import sklearn
        value = json.loads(Path(path).read_text(encoding="utf-8"))
        if (value["version"] != 1 or value["sklearn"] != sklearn.__version__
                or tuple(value["feature_names"]) != cls.feature_names):
            raise ValueError("model schema/library mismatch; retrain with current environment")
        model = cls(value["window_seconds"], value["false_positive_target"], value["seed"],
                    value["max_window_events"], value["max_sources"])
        model.fit_baseline(value["training"])
        model.threshold = float(value["threshold"])
        if not math.isfinite(model.threshold):
            raise ValueError("invalid threshold")
        model._known_edges = {tuple(edge) for edge in value["known_edges"]}
        model.metadata = value["metadata"]
        return model

    def fit_events(self, events: Iterable[NetworkEvent]) -> None:
        baseline = [event for event in events if self.eligible(event)]
        self._known_edges = {self.edge(event) for event in baseline}
        self.reset_windows()
        try:
            samples = []
            for event in baseline:
                features = self.features(event)
                samples.append([features[name] for name in self.feature_names])
            self.fit_baseline(samples)
        finally:
            self.reset_windows()

    def observe(self, event: NetworkEvent) -> Finding | None:
        self.last_score = None
        if self._model is None or not self.eligible(event):
            return None
        key = event.source_key()
        if key in self._windows and self._windows[key] and event.timestamp_mono < self._windows[key][-1].timestamp_mono:
            self.out_of_order += 1
            self.last_score = {"event_id": event.stable_id(), "status": "out_of_order", "score": None}
            return None
        features = self.features(event)
        # A partial first window is an observability warm-up, not an attack.
        status = "warmup" if event.timestamp_mono - self._started_at[key] < self.window_seconds else "scored"
        if key in self._overflow_at and event.timestamp_mono - self._overflow_at[key] < self.window_seconds:
            status = "window_overflow"
        self.last_score = {"event_id": event.stable_id(), "timestamp_mono": event.timestamp_mono,
            "status": status, "score": None, "threshold": self.threshold, "features": features,
            "bytes_available": event.bytes_count is not None,
            "outcome_available": event.source == "simulator" or event.outcome in ("succeeded", "failed")}
        if status != "scored":
            return None
        vector = np.asarray([[features[name] for name in self.feature_names]])
        with threadpool_limits(limits=1):
            score = float(-self._model.score_samples(vector)[0])
        self.last_score["score"] = score
        self.last_score["anomalous"] = score > self.threshold
        if score <= self.threshold:
            return None
        return Finding(source=event.src_service, destination=event.dst_service,
                       score=score, features=features,
                       src_container=event.src_container, dst_container=event.dst_container,
                       dst_port=event.dst_port, protocol=event.protocol,
                       event_id=event.stable_id(), timestamp_mono=event.timestamp_mono,
                       attribution=event.attribution,
                       src_container_id=event.src_container_id, dst_container_id=event.dst_container_id,
                       explanation="Isolation Forest score exceeded the calibrated baseline threshold")
