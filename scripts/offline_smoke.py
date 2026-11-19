"""Reproducible no-root capture/train/replay smoke; outputs are explicitly synthetic."""
from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path

from app.main import build_app
from app.telemetry.simulator import baseline_events, synthetic_events
from app.training import train


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("data/verification") /
                        datetime.now(timezone.utc).strftime("offline-%Y%m%d-%H%M%S"))
    args = parser.parse_args()
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    baseline, evaluation, model = root / "baseline.jsonl", root / "evaluation.jsonl", root / "model.json"
    baseline.write_text("".join(e.model_dump_json() + "\n" for e in baseline_events(count=1000)), encoding="utf-8")
    evaluation.write_text("".join(e.model_dump_json() + "\n" for e in synthetic_events(normal_count=80, anomalous_count=20)), encoding="utf-8")
    training = train(str(baseline), str(model))
    config = root / "replay.json"
    config.write_text(json.dumps({"source": "replay", "model_path": str(model),
        "replay_path": str(evaluation), "output_dir": str(root / "run")}), encoding="utf-8")
    application = build_app(config)
    async def run():
        await application.state.prepare()
        await application.state.orchestrator.run()
    asyncio.run(run())
    state = application.state.orchestrator
    assert state.status == "completed" and state.metrics["events_total"] == 100
    assert state.scores and state.alerts and state.enforcer.policies
    assert all(p.state == "proposed" and p.mode == "dry-run" for p in state.enforcer.policies.values())
    result = {"passed": True, "data_kind": "synthetic; not a real lab measurement", "output": str(root),
              "events": state.metrics["events_total"], "alerts": len(state.alerts),
              "policies": len(state.enforcer.policies), "training": training}
    (root / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
