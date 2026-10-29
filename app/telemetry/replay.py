from __future__ import annotations

import json
from pathlib import Path
from collections.abc import AsyncIterator

from app.models import NetworkEvent


class ReplaySource:
    """Replay newline-delimited normalized events without changing consumers."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    async def events(self) -> AsyncIterator[NetworkEvent]:
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                yield NetworkEvent.model_validate(json.loads(line))

