from __future__ import annotations

import asyncio
from pathlib import Path
from collections.abc import AsyncIterator

from app.models import NetworkEvent
from app.storage import read_events


class ReplaySource:
    """Replay newline-delimited normalized events without changing consumers."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    async def events(self) -> AsyncIterator[NetworkEvent]:
        for event in read_events(self.path):
            yield event
            await asyncio.sleep(0)

