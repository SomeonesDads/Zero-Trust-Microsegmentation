from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


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
