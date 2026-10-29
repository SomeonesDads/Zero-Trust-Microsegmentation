from __future__ import annotations

from typing import Protocol

from app.models import Finding, NetworkEvent


class Detector(Protocol):
    def observe(self, event: NetworkEvent) -> Finding | None: ...

