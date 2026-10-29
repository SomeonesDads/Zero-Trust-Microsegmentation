from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Protocol

from app.models import NetworkEvent


class TelemetrySource(Protocol):
    async def events(self) -> AsyncIterator[NetworkEvent]: ...

