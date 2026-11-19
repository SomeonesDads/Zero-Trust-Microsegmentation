"""Bounded rotating JSONL with visible retention and atomically written summaries."""
from __future__ import annotations

import json
import asyncio
from pathlib import Path
import threading
from typing import Any


async def store_call(function, *args):
    """Finish an in-flight disk write before cancellation can close the store."""
    task = asyncio.create_task(asyncio.to_thread(function, *args))
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        await task
        raise


class RunStore:
    def __init__(self, path: str | Path, max_bytes: int = 32 * 1024 * 1024, parts: int = 8) -> None:
        if max_bytes < 1 or parts < 1:
            raise ValueError("storage capacities must be positive")
        self.path = Path(path)
        self.path.mkdir(parents=True, exist_ok=True)
        self.max_bytes, self.parts = max_bytes, parts
        self.handles: dict[str, Any] = {}
        self.sizes: dict[str, int] = {}
        self.rotations: dict[str, int] = {}
        self._lock = threading.RLock()
        self._closed = False

    def append(self, stream: str, value: Any) -> None:
        with self._lock:
            if self._closed:
                raise RuntimeError("run store is closed")
            self._append(stream, value)

    def _append(self, stream: str, value: Any) -> None:
        if hasattr(value, "model_dump"):
            value = value.model_dump(mode="json")
        data = (json.dumps(value, allow_nan=False) + "\n").encode("utf-8")
        path = self.path / f"{stream}.jsonl"
        if stream not in self.handles:
            self.handles[stream] = path.open("ab", buffering=0)
            self.sizes[stream] = path.stat().st_size
        if self.sizes[stream] and self.sizes[stream] + len(data) > self.max_bytes:
            self.handles[stream].close()
            oldest = self.path / f"{stream}.{self.parts}.jsonl"
            oldest.unlink(missing_ok=True)
            for index in range(self.parts - 1, 0, -1):
                source = self.path / f"{stream}.{index}.jsonl"
                if source.exists():
                    source.replace(self.path / f"{stream}.{index + 1}.jsonl")
            path.replace(self.path / f"{stream}.1.jsonl")
            self.handles[stream] = path.open("ab", buffering=0)
            self.sizes[stream] = 0
            self.rotations[stream] = self.rotations.get(stream, 0) + 1
        self.handles[stream].write(data)
        self.sizes[stream] += len(data)

    def summary(self, name: str, value: dict | list) -> None:
        path = self.path / f"{name}.json"
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(value, indent=2, allow_nan=False), encoding="utf-8")
        temporary.replace(path)

    def close(self) -> None:
        with self._lock:
            for handle in self.handles.values():
                handle.close()
            self.handles.clear()
            self._closed = True


def read_events(path: str | Path):
    """Read a single capture or a directory of rotated capture parts chronologically."""
    from app.models import NetworkEvent
    path = Path(path)
    if path.is_dir():
        parts = sorted(path.glob("events.*.jsonl"), key=lambda p: int(p.name.split(".")[1]), reverse=True)
        paths = parts + [path / "events.jsonl"]
    else:
        paths = [path]
    for file in paths:
        with file.open(encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    yield NetworkEvent.model_validate_json(line)
