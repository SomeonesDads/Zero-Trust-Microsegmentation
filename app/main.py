from __future__ import annotations

import argparse
import asyncio
from contextlib import asynccontextmanager, suppress
import json
import os
from pathlib import Path

from fastapi import FastAPI

from app.api.routes import router
from app.config import SimulationConfig
from app.detection.isolation_forest import IsolationForestDetector
from app.orchestration.asyncio_orchestrator import Orchestrator
from app.policies.enforcement import DryRunEnforcer
from app.telemetry.simulator import SimulatorSource, baseline_events, synthetic_events

DEFAULT_CONFIG = Path(__file__).resolve().parents[1] / "configs" / "simulation.json"


def build_app(config_path: str | Path | None = None) -> FastAPI:
    config = SimulationConfig.load(config_path or os.environ.get("ZTM_CONFIG", DEFAULT_CONFIG))
    detector = IsolationForestDetector(config.window_seconds, config.false_positive_target)
    source = SimulatorSource(synthetic_events(config.seed, config.simulation_events - 10, 10))
    orchestrator = Orchestrator(source, detector=detector, enforcer=DryRunEnforcer())

    async def prepare() -> None:
        await asyncio.to_thread(detector.fit_events, baseline_events(config.seed, config.baseline_events))

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        await prepare()
        task = asyncio.create_task(orchestrator.run())
        application.state.simulation_task = task
        try:
            yield
        finally:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task

    application = FastAPI(title="Zero-Trust Microsegmentation", version="0.2.0", lifespan=lifespan)
    application.state.orchestrator = orchestrator
    application.state.config = config
    application.state.prepare = prepare
    application.include_router(router)
    return application


app = build_app()


def run() -> None:
    parser = argparse.ArgumentParser(description="Run the no-root, dry-run M1 simulation.")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    args = parser.parse_args()

    async def simulate() -> None:
        application = build_app(args.config)
        await application.state.prepare()
        state = application.state.orchestrator
        await state.run()
        print(json.dumps({"mode": state.enforcer.mode, "status": state.status,
                          "events": len(state.events), "alerts": len(state.alerts),
                          "policies": len(state.enforcer.policies)}))

    asyncio.run(simulate())


if __name__ == "__main__":
    run()
