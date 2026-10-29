from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterable
import math

import numpy as np
from sklearn.ensemble import IsolationForest
from threadpoolctl import threadpool_limits

from app.models import EventType, Finding, NetworkEvent


class IsolationForestDetector:
    """Calibrated Isolation Forest using the same features for baseline and inference."""

    feature_names = ("connection_rate", "fan_out", "distinct_ports", "new_edge",
                     "failed_ratio", "time_of_window", "connection_count", "bytes_per_connection")

    def __init__(self, window_seconds: float = 10.0, false_positive_target: float = 0.01) -> None:
        if not math.isfinite(window_seconds) or window_seconds <= 0:
            raise ValueError("window_seconds must be positive and finite")
        if not 0 < false_positive_target < 1:
            raise ValueError("false_positive_target must be between zero and one")
        self.window_seconds = window_seconds
        self.false_positive_target = false_positive_target
        self._windows: dict[str, deque[NetworkEvent]] = defaultdict(deque)
        self._known_edges: set[tuple[str, str, int, str]] = set()
        self._started_at: dict[str, float] = {}
        self._model: IsolationForest | None = None
        self.threshold = 0.0

    @staticmethod
    def edge(event: NetworkEvent) -> tuple[str, str, int, str]:
        return event.src_service, event.dst_service, event.dst_port, event.protocol

    def features(self, event: NetworkEvent) -> dict[str, float]:
        window = self._windows[event.src_service]
        self._started_at.setdefault(event.src_service, event.timestamp_mono)
        if window and event.timestamp_mono < window[-1].timestamp_mono:
            raise ValueError("events must be ordered by monotonic timestamp per source")
        window.append(event)
        while window and event.timestamp_mono - window[0].timestamp_mono >= self.window_seconds:
            window.popleft()
        edge_events = [item for item in window if item.dst_service == event.dst_service]
        byte_counts = [item.bytes_count for item in edge_events if item.bytes_count is not None]
        return {
            "connection_rate": len(edge_events) / self.window_seconds,
            "fan_out": float(len({item.dst_service for item in window})),
            "distinct_ports": float(len({item.dst_port for item in window})),
            "new_edge": float(self.edge(event) not in self._known_edges),
            "failed_ratio": sum(item.failed for item in edge_events) / len(edge_events),
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
        self._model = IsolationForest(random_state=7, contamination="auto", n_estimators=100, n_jobs=1)
        with threadpool_limits(limits=1):
            self._model.fit(matrix)
            scores = -self._model.score_samples(matrix)
        self.threshold = float(np.quantile(scores, 1 - self.false_positive_target))
        self._windows.clear()
        self._started_at.clear()

    def fit_events(self, events: Iterable[NetworkEvent]) -> None:
        baseline = [event for event in events if event.event_type == EventType.CONNECT]
        self._known_edges = {self.edge(event) for event in baseline}
        self._windows.clear()
        try:
            samples = []
            for event in baseline:
                features = self.features(event)
                samples.append([features[name] for name in self.feature_names])
            self.fit_baseline(samples)
        finally:
            self._windows.clear()
            self._started_at.clear()

    def observe(self, event: NetworkEvent) -> Finding | None:
        if self._model is None or event.event_type != EventType.CONNECT:
            return None
        features = self.features(event)
        # A partial first window is an observability warm-up, not an attack.
        if event.timestamp_mono - self._started_at[event.src_service] < self.window_seconds:
            return None
        vector = np.asarray([[features[name] for name in self.feature_names]])
        with threadpool_limits(limits=1):
            score = float(-self._model.score_samples(vector)[0])
        if score <= self.threshold:
            return None
        return Finding(source=event.src_service, destination=event.dst_service,
                       score=score, features=features,
                       src_container=event.src_container, dst_container=event.dst_container,
                       dst_port=event.dst_port, protocol=event.protocol,
                       explanation="Isolation Forest score exceeded the calibrated baseline threshold")
