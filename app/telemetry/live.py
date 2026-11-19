"""Linux live telemetry assembled from a scoped BCC reader and netns conntrack."""
from __future__ import annotations

import asyncio
from collections import Counter
from datetime import datetime, timezone
import json
import heapq
from pathlib import Path
import platform
import time

from app.telemetry.conntrack import ConntrackReader
from app.telemetry.ebpf import EBPFReader
from app.telemetry.identity import IdentityRegistry
from app.telemetry.normalize import Normalizer
from app.storage import store_call
from lab.topology import load_config


class LiveSource:
    def __init__(self, lab_config: str = "configs/lab.json", collector_python: str = "/usr/bin/python3",
                 conntrack: bool = True, queue_size: int = 4096, refresh_seconds: float = 5,
                 duration_seconds: float | None = None, store=None) -> None:
        self.config = load_config(Path(lab_config))
        self.python, self.conntrack = collector_python, conntrack
        self.queue_size, self.refresh_seconds = queue_size, refresh_seconds
        self.duration_seconds, self.store = duration_seconds, store
        self.registry = IdentityRegistry(self.config["name"])
        self.stats = Counter(raw_received=0, queue_dropped=0, invalid=0, unknown=0, filtered=0)
        self.ebpf = None
        self.readers = {}
        self.retired_conntrack_records = 0
        self.retired_conntrack_overruns = 0
        self.status = "idle"
        self.error = None

    def health(self) -> dict:
        return {"status": self.status, "error": self.error, **self.stats,
            "ebpf_ready": bool(self.ebpf and self.ebpf.ready),
            "ebpf": self.ebpf.metrics if self.ebpf else {}, "containers": len(self.registry.containers),
            "conntrack_enabled": self.conntrack,
            "conntrack_records": self.retired_conntrack_records + sum(r.records_seen for r in self.readers.values()),
            "conntrack_overruns": self.retired_conntrack_overruns + sum(r.overruns for r in self.readers.values())}

    async def events(self):
        if platform.system() != "Linux":
            self.status, self.error = "failed", "live telemetry requires Linux"
            raise RuntimeError("live telemetry requires Linux; use simulator/replay on this host")
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        normalizer = Normalizer(self.registry, [self.config[f"{tier}_subnet"] for tier in
            ("frontend", "application", "data")], platform.node(), boot)
        queue = asyncio.Queue(maxsize=self.queue_size)
        pending = []
        sequence = 0
        tasks = {}
        start = time.monotonic()

        async def pump(reader):
            async for raw in reader.records():
                self.stats["raw_received"] += 1
                try:
                    queue.put_nowait(raw)
                except asyncio.QueueFull:
                    self.stats["queue_dropped"] += 1

        async def refresh():
            fresh = IdentityRegistry(self.config["name"])
            await asyncio.to_thread(fresh.refresh)
            self.registry.replace(list(fresh.containers.values()))
            if self.ebpf:
                await self.ebpf.update(list(self.registry.by_netns))
            desired = {key: value for key, value in self.registry.containers.items() if value.ips}
            for key in list(self.readers):
                if key not in desired:
                    task = tasks.pop(key)
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                    self.retired_conntrack_records += self.readers[key].records_seen
                    self.retired_conntrack_overruns += self.readers[key].overruns
                    del self.readers[key]
            if self.conntrack:
                for key, item in desired.items():
                    if key not in self.readers:
                        reader = ConntrackReader(item.pid, item.netns_id)
                        self.readers[key] = reader
                        tasks[key] = asyncio.create_task(pump(reader))
            if self.store:
                await store_call(self.store.summary, "identities", self.registry.snapshot())

        self.status = "starting"
        try:
            await refresh()
            self.ebpf = EBPFReader(self.python, list(self.registry.by_netns))
            tasks["ebpf"] = asyncio.create_task(pump(self.ebpf))
            refreshed = reported = time.monotonic()
            while self.duration_seconds is None or time.monotonic() - start < self.duration_seconds:
                now = time.monotonic()
                if now - refreshed >= self.refresh_seconds or any(t.done() for t in tasks.values()):
                    await refresh()
                    refreshed = now
                for task in tasks.values():
                    if task.done():
                        await task
                        raise RuntimeError("telemetry reader stopped unexpectedly")
                self.status = "running" if self.ebpf.ready else "starting"
                if now - reported >= 1:
                    if self.store:
                        await store_call(self.store.summary, "telemetry", self.health())
                    reported = now
                try:
                    raw = await asyncio.wait_for(queue.get(), 0.25)
                except asyncio.TimeoutError:
                    raw = None
                if raw:
                    sequence += 1
                    if len(pending) < self.queue_size:
                        heapq.heappush(pending, (raw["timestamp_mono"], sequence, raw))
                    else:
                        self.stats["queue_dropped"] += 1
                # Perf buffers are per CPU. Reorder within 50 ms before feature windows.
                while pending and pending[0][0] <= time.monotonic() - 0.05:
                    _, _, item = heapq.heappop(pending)
                    try:
                        event = normalizer.normalize(item)
                    except (ValueError, KeyError):
                        self.stats["invalid"] += 1
                        continue
                    self.stats["unknown"], self.stats["filtered"] = normalizer.unknown, normalizer.filtered
                    if event:
                        yield event
            self.status = "completed"
        except asyncio.CancelledError:
            self.status = "stopped"
            raise
        except GeneratorExit:
            self.status = "stopped"
            raise
        except Exception as error:
            self.status, self.error = "failed", str(error)
            raise
        finally:
            for task in tasks.values():
                task.cancel()
            await asyncio.gather(*tasks.values(), return_exceptions=True)
            self.stats["shutdown_unconsumed"] = queue.qsize() + len(pending)
            if self.store:
                await store_call(self.store.summary, "telemetry", self.health())


def main():
    """Capture a benign baseline without training or proposing policies."""
    import argparse
    from app.storage import RunStore
    parser = argparse.ArgumentParser(description="Capture attributed lab TCP telemetry (Linux/BCC)")
    parser.add_argument("--lab-config", default="configs/lab.json")
    parser.add_argument("--collector-python", default="/usr/bin/python3")
    parser.add_argument("--duration", type=float, default=1800)
    parser.add_argument("--output", required=True)
    parser.add_argument("--no-conntrack", action="store_true")
    parser.add_argument("--max-file-mib", type=int, default=32)
    parser.add_argument("--max-file-parts", type=int, default=8)
    args = parser.parse_args()
    if args.duration <= 0 or args.max_file_mib < 1 or args.max_file_parts < 1:
        parser.error("duration and file capacities must be positive")
    path = Path(args.output)
    if path.exists() and any(path.iterdir()):
        parser.error("output directory must be new or empty")
    store = RunStore(path, args.max_file_mib * 1024 * 1024, args.max_file_parts)
    source = LiveSource(args.lab_config, args.collector_python, not args.no_conntrack,
                        duration_seconds=args.duration, store=store)
    async def capture():
        store.summary("manifest", {"mode": "capture", "source": "live", "started": datetime.now(timezone.utc).isoformat(),
            "duration_seconds": args.duration, "lab_config": source.config, "conntrack": source.conntrack})
        try:
            async for event in source.events():
                await store_call(store.append, "events", event)
        finally:
            store.summary("capture", {**source.health(), "rotations": store.rotations})
            store.close()
    asyncio.run(capture())


if __name__ == "__main__":
    main()
