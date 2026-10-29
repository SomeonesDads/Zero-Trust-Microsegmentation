from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timezone
import asyncio

import numpy as np
from sklearn.ensemble import IsolationForest

from app.models import Finding, NetworkEvent


class IsolationForestDetector:
    """Windowed edge detector. Scores are calibrated against a baseline percentile."""

    def __init__(self, window_seconds: float = 10.0, false_positive_target: float = 0.01) -> None:
        self.window_seconds = window_seconds
        self.false_positive_target = false_positive_target
        self._windows: dict[str, deque[NetworkEvent]] = defaultdict(deque)
        self._model: IsolationForest | None = None
        self.threshold = 0.0
        self._fallback_threshold = 0.0

    @staticmethod
    def features(events: list[NetworkEvent]) -> dict[str, float]:
        destinations = {e.dst_service for e in events}
        ports = {e.dst_port for e in events}
        return {"connection_rate": float(len(events)), "fan_out": float(len(destinations)),
                "distinct_ports": float(len(ports)), "new_edge": 1.0 if len(destinations) > 1 else 0.0,
                "failed_ratio": sum(e.failed for e in events) / max(1, len(events)),
                "time_of_window": float(events[-1].timestamp_mono if events else 0.0)}

    def fit_baseline(self, samples: list[list[float]]) -> None:
        if len(samples) < 2:
            raise ValueError("at least two baseline samples are required")
        self._model = IsolationForest(random_state=7, contamination="auto", n_estimators=100)
        self._model.fit(np.asarray(samples, dtype=float))
        raw = -self._model.score_samples(np.asarray(samples, dtype=float))
        self.threshold = float(np.quantile(raw, 1.0 - self.false_positive_target))
        # A small deterministic score keeps the async simulator portable on
        # Windows builds where native OpenMP calls can block the event loop.
        baseline = np.asarray(samples, dtype=float)
        simple = baseline[:, 0] + baseline[:, 1] + baseline[:, 2] + 3 * baseline[:, 3] + baseline[:, 4]
        self._fallback_threshold = float(np.quantile(simple, 1.0 - self.false_positive_target))

    def observe(self, event: NetworkEvent) -> Finding | None:
        window = self._windows[event.src_service]
        window.append(event)
        while window and event.timestamp_mono - window[0].timestamp_mono > self.window_seconds:
            window.popleft()
        features = self.features(list(window))
        vector = np.asarray([[features[k] for k in ("connection_rate", "fan_out", "distinct_ports", "new_edge", "failed_ratio", "time_of_window")]])
        in_async_loop = True
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            in_async_loop = False
        fallback_score = float(features["connection_rate"] + features["fan_out"] + features["distinct_ports"] +
                               3 * features["new_edge"] + features["failed_ratio"])
        fallback_anomaly = fallback_score > self._fallback_threshold
        if self._model and not in_async_loop:
            score = float(-self._model.score_samples(vector)[0])
            is_anomaly = score > self.threshold or fallback_anomaly
        else:
            score = fallback_score
            is_anomaly = score > self._fallback_threshold
        if self._model and is_anomaly:
            return Finding(timestamp=datetime.now(timezone.utc), source=event.src_service,
                           destination=event.dst_service, score=score, features=features,
                           explanation="windowed connection behavior exceeded calibrated baseline threshold")
        return None

