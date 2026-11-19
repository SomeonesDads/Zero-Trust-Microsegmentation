from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class SimulationConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    window_seconds: float = Field(default=10.0, gt=0, allow_inf_nan=False)
    false_positive_target: float = Field(default=0.01, gt=0, lt=1)
    enforcement_mode: Literal["dry-run"] = "dry-run"
    seed: int = 7
    simulation_events: int = Field(default=40, ge=10)
    baseline_events: int = Field(default=500, ge=20)

    @classmethod
    def load(cls, path: str | Path) -> "SimulationConfig":
        return cls.model_validate(json.loads(Path(path).read_text(encoding="utf-8")))


class RuntimeConfig(SimulationConfig):
    """M2-M4 always propose policies; real packet enforcement belongs to M5."""

    source: Literal["simulator", "replay", "live"] = "simulator"
    replay_path: str | None = None
    model_path: str | None = None
    lab_config: str = "configs/lab.json"
    output_dir: str | None = None
    collector_python: str = "/usr/bin/python3"
    conntrack: bool = True
    queue_size: int = Field(default=4096, ge=1)
    retention: int = Field(default=10000, ge=1)
    max_file_bytes: int = Field(default=32 * 1024 * 1024, ge=1024)
    max_file_parts: int = Field(default=8, ge=1)
    identity_refresh_seconds: float = Field(default=5, gt=0)
    duration_seconds: float | None = Field(default=None, gt=0)

    @model_validator(mode="after")
    def check_source(self):
        if self.source == "replay" and not self.replay_path:
            raise ValueError("replay source requires replay_path")
        if self.source != "simulator" and not self.model_path:
            raise ValueError("live/replay require a model trained with app.training")
        if self.source != "simulator" and not self.output_dir:
            raise ValueError("live/replay require output_dir for audit and telemetry")
        return self
