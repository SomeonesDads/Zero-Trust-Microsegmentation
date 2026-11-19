from __future__ import annotations

import asyncio
from collections import deque
from contextlib import suppress, aclosing
import time

from app.agents.graph_observer import GraphObserver
from app.detection.base import Detector
from app.detection.isolation_forest import IsolationForestDetector
from app.models import Finding, NetworkEvent
from app.policies.enforcement import DryRunEnforcer
from app.telemetry.base import TelemetrySource
from app.storage import store_call


class Orchestrator:
    def __init__(self, source: TelemetrySource, observer: GraphObserver | None = None,
                 detector: Detector | None = None, enforcer: DryRunEnforcer | None = None,
                 queue_size: int = 4096, retention: int = 10000, store=None) -> None:
        self.source = source
        self.observer = observer or GraphObserver(retention)
        self.detector = detector or IsolationForestDetector()
        self.enforcer = enforcer or DryRunEnforcer()
        self.events = deque(maxlen=retention)
        self.alerts = deque(maxlen=retention)
        self.scores = deque(maxlen=retention)
        self.queue_size, self.retention, self.store = queue_size, retention, store
        self.metrics = {"events_total": 0, "alerts_total": 0, "queue_high_water": 0,
                        "analysis_queue_dropped": 0, "unresolved_policy_skipped": 0,
                        "last_queue_wait_seconds": 0.0, "last_inference_seconds": 0.0}
        self.status = "idle"
        self.error: str | None = None

    async def run(self) -> None:
        if self.status == "running":
            raise RuntimeError("orchestrator is already running")
        queue = asyncio.Queue(maxsize=self.queue_size)
        self.status, self.error = "running", None

        async def ingest() -> None:
            async with aclosing(self.source.events()) as stream:
                async for event in stream:
                    if self.observer.observe(event):
                        self.events.append(event)
                        self.metrics["events_total"] += 1
                        if self.store:
                            await store_call(self.store.append, "events", event)
                        if event.counts_as_connection:
                            try:
                                queue.put_nowait((event, time.monotonic()))
                                self.metrics["queue_high_water"] = max(self.metrics["queue_high_water"], queue.qsize())
                            except asyncio.QueueFull:
                                self.metrics["analysis_queue_dropped"] += 1
                    await asyncio.sleep(0)
            await queue.put(None)

        async def analyze() -> None:
            while (item := await queue.get()) is not None:
                event, queued = item
                started = time.monotonic()
                self.metrics["last_queue_wait_seconds"] = started - queued
                # Keep sklearn/native inference off the event loop, without
                # concurrent access to the detector's rolling windows.
                finding = await asyncio.to_thread(self.detector.observe, event)
                self.metrics["last_inference_seconds"] = time.monotonic() - started
                score = getattr(self.detector, "last_score", None)
                if score:
                    score = {**score, "queue_wait_seconds": self.metrics["last_queue_wait_seconds"],
                             "inference_seconds": self.metrics["last_inference_seconds"]}
                    self.scores.append(score)
                    if self.store:
                        await store_call(self.store.append, "scores", score)
                if finding:
                    self.alerts.append(finding)
                    self.metrics["alerts_total"] += 1
                    if self.store:
                        await store_call(self.store.append, "findings", finding)
                    if finding.attribution != "resolved":
                        self.metrics["unresolved_policy_skipped"] += 1
                        continue
                    previous = len(self.enforcer.audit)
                    policy = self.enforcer.propose(finding)
                    if self.store:
                        if len(self.enforcer.audit) > previous:
                            await store_call(self.store.append, "policies", policy)
                        for entry in self.enforcer.audit[previous:]:
                            await store_call(self.store.append, "audit", entry)
                    if len(self.enforcer.policies) > self.retention and self.enforcer.mode == "dry-run":
                        del self.enforcer.policies[next(iter(self.enforcer.policies))]
                    del self.enforcer.audit[:-self.retention]

        tasks = [asyncio.create_task(ingest()), asyncio.create_task(analyze())]
        try:
            await asyncio.gather(*tasks)
            self.status = "completed"
        except asyncio.CancelledError:
            self.status = "stopped"
            raise
        except Exception as error:
            self.status, self.error = "failed", str(error)
            raise
        finally:
            for task in tasks:
                task.cancel()
            for task in tasks:
                with suppress(asyncio.CancelledError, Exception):
                    await task
            if self.store:
                await store_call(self.store.summary, "summary", {
                    "status": self.status, "error": self.error, "metrics": self.metrics,
                    "rotations": self.store.rotations, "mode": self.enforcer.mode,
                    "queue_unconsumed": queue.qsize(), "duplicates": self.observer.duplicates})
                self.store.close()
