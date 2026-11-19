from __future__ import annotations

import argparse
import asyncio
from contextlib import asynccontextmanager, suppress
import json
import os
from pathlib import Path

from fastapi import FastAPI

from app.api.routes import router
from app.config import RuntimeConfig
from app.detection.isolation_forest import IsolationForestDetector
from app.orchestration.asyncio_orchestrator import Orchestrator
from app.policies.enforcement import DryRunEnforcer
from app.telemetry.simulator import SimulatorSource, baseline_events, synthetic_events
from app.telemetry.replay import ReplaySource
from app.telemetry.live import LiveSource
from app.storage import RunStore
from datetime import datetime, timezone
from hashlib import sha256
import platform

DEFAULT_CONFIG = Path(__file__).resolve().parents[1] / "configs" / "simulation.json"


def build_app(config_path: str | Path | None = None) -> FastAPI:
    config = RuntimeConfig.load(config_path or os.environ.get("ZTM_CONFIG", DEFAULT_CONFIG))
    detector = (IsolationForestDetector.load(config.model_path) if config.model_path else
                IsolationForestDetector(config.window_seconds, config.false_positive_target, config.seed))
    if config.model_path and (detector.window_seconds != config.window_seconds or
                             detector.false_positive_target != config.false_positive_target):
        raise ValueError("runtime window/FPR must match model; update config or retrain")
    if config.source == "live" and ("ebpf" not in detector.metadata.get("sources", []) or
                                    "simulator" in detector.metadata.get("sources", [])):
        raise ValueError("live mode requires a real benign capture, not a simulator-trained model")
    store = None
    if config.output_dir:
        path = Path(config.output_dir)
        if path.exists() and any(path.iterdir()):
            raise ValueError("output_dir must be new or empty; choose a unique directory for each run")
        store = RunStore(path, config.max_file_bytes, config.max_file_parts)
    if config.source == "simulator":
        source = SimulatorSource(synthetic_events(config.seed, config.simulation_events - 10, 10))
    elif config.source == "replay":
        source = ReplaySource(config.replay_path)
    else:
        source = LiveSource(config.lab_config, config.collector_python, config.conntrack,
            config.queue_size, config.identity_refresh_seconds, config.duration_seconds, store)
    orchestrator = Orchestrator(source, detector=detector, enforcer=DryRunEnforcer(),
                               queue_size=config.queue_size, retention=config.retention, store=store)

    async def prepare() -> None:
        if not config.model_path:
            await asyncio.to_thread(detector.fit_events, baseline_events(config.seed, config.baseline_events))
        if store:
            store.summary("manifest", {"started": datetime.now(timezone.utc).isoformat(),
                "config": config.model_dump(), "config_sha256": sha256(config.model_dump_json().encode()).hexdigest(),
                "source": config.source, "mode": "dry-run", "python": platform.python_version(),
                "platform": platform.platform(), "threshold": detector.threshold,
                "model_sha256": sha256(Path(config.model_path).read_bytes()).hexdigest() if config.model_path else None,
                "training": detector.metadata})

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        await prepare()
        task = asyncio.create_task(orchestrator.run())
        application.state.simulation_task = task
        try:
            yield
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    application = FastAPI(title="Zero-Trust Microsegmentation", version="0.4.0", lifespan=lifespan)
    application.state.orchestrator = orchestrator
    application.state.config = config
    application.state.prepare = prepare
    application.include_router(router)
    return application


app = build_app()


def run() -> None:
    parser = argparse.ArgumentParser(description="Run simulator/replay/live telemetry with dry-run policies.")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    args = parser.parse_args()

    async def simulate() -> None:
        application = build_app(args.config)
        await application.state.prepare()
        state = application.state.orchestrator
        await state.run()
        print(json.dumps({"mode": state.enforcer.mode, "status": state.status,
                          "events": len(state.events), "alerts": len(state.alerts),
                          "policies": len(state.enforcer.policies), "metrics": state.metrics}))

    asyncio.run(simulate())


if __name__ == "__main__":
    run()
