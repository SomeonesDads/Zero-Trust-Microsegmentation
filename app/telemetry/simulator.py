from __future__ import annotations

import asyncio
import random
from collections.abc import AsyncIterator, Iterable

from app.models import NetworkEvent


class SimulatorSource:
    """Deterministic local source; it never opens sockets or needs privileges."""

    def __init__(self, events: Iterable[NetworkEvent], delay: float = 0.0) -> None:
        self._events = list(events)
        self.delay = delay

    async def events(self) -> AsyncIterator[NetworkEvent]:
        for event in self._events:
            if self.delay:
                await asyncio.sleep(self.delay)
            yield event


def synthetic_events(seed: int = 7, normal_count: int = 30, anomalous_count: int = 10) -> list[NetworkEvent]:
    rng = random.Random(seed)
    result: list[NetworkEvent] = []
    for i in range(normal_count):
        result.append(NetworkEvent(timestamp_mono=float(i), src_container="web-1", src_service="web",
                                   dst_container="api-1", dst_service="api", dst_port=8080,
                                   event_id=f"normal-{i}"))
    for i in range(anomalous_count):
        result.append(NetworkEvent(timestamp_mono=float(normal_count + i), src_container="web-1",
                                   src_service="web", dst_container=f"db-{i}", dst_service="postgres",
                                   dst_port=rng.randint(1, 65535), event_id=f"anomaly-{i}"))
    return result

