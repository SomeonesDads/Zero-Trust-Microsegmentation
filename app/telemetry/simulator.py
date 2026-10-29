from __future__ import annotations

import asyncio
import random
from collections.abc import AsyncIterator, Iterable

from app.models import NetworkEvent


class SimulatorSource:
    """Deterministic source that never opens sockets or needs privileges."""

    def __init__(self, events: Iterable[NetworkEvent], delay: float = 0.0) -> None:
        self._events = list(events)
        self.delay = delay

    async def events(self) -> AsyncIterator[NetworkEvent]:
        for event in self._events:
            if self.delay:
                await asyncio.sleep(self.delay)
            yield event


def baseline_events(seed: int = 7, count: int = 500) -> list[NetworkEvent]:
    """A development-only shopping graph with varying inter-arrival times."""
    rng = random.Random(seed)
    edges = [("web", "api", 8080), ("web", "auth", 3000),
             ("api", "redis", 6379), ("api", "postgres", 5432)]
    events = []
    timestamp = 0.0
    for i in range(count):
        timestamp += rng.uniform(0.1, 0.8)
        src, dst, port = edges[i % len(edges)]
        events.append(NetworkEvent(timestamp_mono=timestamp,
                                   src_container=f"{src}-1", src_service=src,
                                   dst_container=f"{dst}-1", dst_service=dst, dst_port=port,
                                   bytes_count=rng.randint(100, 1000), event_id=f"baseline-{i}"))
    return events


def synthetic_events(seed: int = 7, normal_count: int = 30, anomalous_count: int = 10) -> list[NetworkEvent]:
    result = baseline_events(seed, normal_count)
    result = [event.model_copy(update={"event_id": f"normal-{i}"}) for i, event in enumerate(result)]
    start = result[-1].timestamp_mono + 1 if result else 0.0
    for i in range(anomalous_count):
        result.append(NetworkEvent(timestamp_mono=start + i * 0.01,
                                   src_container="web-1", src_service="web",
                                   dst_container="postgres-1", dst_service="postgres",
                                   dst_port=10000 + i, failed=True, bytes_count=0,
                                   event_id=f"anomaly-{i}"))
    return result
