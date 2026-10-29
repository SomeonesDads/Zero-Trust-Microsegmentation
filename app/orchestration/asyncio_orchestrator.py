from __future__ import annotations

import asyncio

from app.agents.graph_observer import GraphObserver
from app.detection.isolation_forest import IsolationForestDetector
from app.models import Finding, NetworkEvent
from app.policies.enforcement import DryRunEnforcer
from app.telemetry.base import TelemetrySource


class Orchestrator:
    def __init__(self, source: TelemetrySource, observer: GraphObserver | None = None,
                 detector: IsolationForestDetector | None = None,
                 enforcer: DryRunEnforcer | None = None) -> None:
        self.source = source
        self.observer = observer or GraphObserver()
        self.detector = detector or IsolationForestDetector()
        self.enforcer = enforcer or DryRunEnforcer()
        self.events: list[NetworkEvent] = []
        self.alerts: list[Finding] = []

    async def run(self) -> None:
        queue: asyncio.Queue[NetworkEvent | None] = asyncio.Queue()

        async def inference_worker() -> None:
            while True:
                event = await queue.get()
                try:
                    if event is None:
                        return
                    finding = self.detector.observe(event)
                    if finding:
                        self.alerts.append(finding)
                        self.enforcer.propose(finding)
                finally:
                    queue.task_done()

        worker = asyncio.create_task(inference_worker())
        async for event in self.source.events():
            if not self.observer.observe(event):
                continue
            self.events.append(event)
            # Ingestion remains responsive while the worker performs inference.
            queue.put_nowait(event)
        await queue.join()
        queue.put_nowait(None)
        await worker

