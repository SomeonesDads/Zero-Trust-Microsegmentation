from __future__ import annotations

import asyncio

from fastapi import FastAPI

from app.agents.graph_observer import GraphObserver
from app.api.routes import router
from app.detection.isolation_forest import IsolationForestDetector
from app.orchestration.asyncio_orchestrator import Orchestrator
from app.policies.enforcement import DryRunEnforcer
from app.telemetry.simulator import SimulatorSource, synthetic_events


def build_app() -> FastAPI:
    source = SimulatorSource(synthetic_events())
    detector = IsolationForestDetector()
    # A small deterministic baseline is enough for the development simulation;
    # production runs must calibrate from their recorded baseline window.
    detector.fit_baseline([[1, 1, 1, 0, 0, float(i)] for i in range(20)])
    orchestrator = Orchestrator(source, GraphObserver(), detector, DryRunEnforcer())
    app = FastAPI(title="Zero-Trust Microsegmentation M1", version="0.1.0")
    app.state.orchestrator = orchestrator
    app.include_router(router)
    return app


app = build_app()


def run() -> None:
    asyncio.run(app.state.orchestrator.run())


if __name__ == "__main__":
    run()

