from __future__ import annotations

import asyncio
from contextlib import suppress

from app.agents.graph_observer import GraphObserver
from app.detection.base import Detector
from app.detection.isolation_forest import IsolationForestDetector
from app.models import Finding, NetworkEvent
from app.policies.enforcement import DryRunEnforcer
from app.telemetry.base import TelemetrySource


class Orchestrator:
    def __init__(self, source: TelemetrySource, observer: GraphObserver | None = None,
                 detector: Detector | None = None, enforcer: DryRunEnforcer | None = None) -> None:
        self.source = source
        self.observer = observer or GraphObserver()
        self.detector = detector or IsolationForestDetector()
        self.enforcer = enforcer or DryRunEnforcer()
        self.events: list[NetworkEvent] = []
        self.alerts: list[Finding] = []
        self.status = "idle"
        self.error: str | None = None

    async def run(self) -> None:
        if self.status == "running":
            raise RuntimeError("orchestrator is already running")
        queue: asyncio.Queue[NetworkEvent | None] = asyncio.Queue()
        self.status, self.error = "running", None

        async def ingest() -> None:
            async for event in self.source.events():
                if self.observer.observe(event):
                    self.events.append(event)
                    queue.put_nowait(event)
                await asyncio.sleep(0)
            queue.put_nowait(None)

        async def analyze() -> None:
            while (event := await queue.get()) is not None:
                # Keep sklearn/native inference off the event loop, without
                # concurrent access to the detector's rolling windows.
                finding = await asyncio.to_thread(self.detector.observe, event)
                if finding:
                    self.alerts.append(finding)
                    self.enforcer.propose(finding)

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
