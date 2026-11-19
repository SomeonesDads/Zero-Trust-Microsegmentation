"""Async transport for the BCC child process; never silently falls back to simulation."""
from __future__ import annotations

import asyncio
from collections import deque
import json
from pathlib import Path


class EBPFReader:
    def __init__(self, python: str, netns: list[int]) -> None:
        self.python, self.netns = python, netns
        self.process = None
        self.metrics: dict = {}
        self.stderr = deque(maxlen=20)
        self.ready = False

    async def update(self, namespaces: list[int]) -> None:
        self.netns = namespaces
        if self.process and self.process.returncode is None:
            self.process.stdin.write((json.dumps({"netns": namespaces}) + "\n").encode())
            await self.process.stdin.drain()

    async def records(self):
        reader = Path(__file__).with_name("collector") / "bcc_reader.py"
        self.process = await asyncio.create_subprocess_exec(self.python, "-u", str(reader),
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        async def errors():
            async for line in self.process.stderr:
                self.stderr.append(line.decode(errors="replace").rstrip())
        task = asyncio.create_task(errors())
        try:
            await self.update(self.netns)
            while True:
                line = await asyncio.wait_for(self.process.stdout.readline(), timeout=60 if not self.ready else 15)
                if not line:
                    await self.process.wait()
                    await task
                    raise RuntimeError("eBPF collector exited: " + "\n".join(self.stderr))
                record = json.loads(line)
                if record["type"] == "ready":
                    self.ready = True
                elif record["type"] == "metrics":
                    self.metrics = record
                elif record["type"] == "event":
                    yield record
        finally:
            self.ready = False
            if self.process.returncode is None:
                self.process.terminate()
                try:
                    await asyncio.wait_for(self.process.wait(), 5)
                except asyncio.TimeoutError:
                    self.process.kill()
                    await self.process.wait()
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

