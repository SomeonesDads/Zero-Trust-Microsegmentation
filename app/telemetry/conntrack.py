"""Conntrack NEW/UPDATE/DESTROY plus initial snapshot, in each lab netns.

Records corroborate socket telemetry and never increment connection counts.
An overrun or process failure is surfaced instead of interpreting missing data
as an attack. Restarting the pipeline takes a fresh snapshot.
"""
from __future__ import annotations

import asyncio
from collections import deque
import re
import time


def parse_conntrack(line: str, netns_id: int, stamp: float | None = None) -> dict | None:
    if not re.search(r"\btcp\s+6\b", line):
        return None
    fields = {}
    # Original direction comes before reply direction; keep the FIRST tuple.
    for key, value in re.findall(r"\b(src|dst|sport|dport)=([^\s]+)", line):
        fields.setdefault(key, value)
    if set(fields) != {"src", "dst", "sport", "dport"} or ":" in fields["src"]:
        return None
    return {"source": "conntrack", "event_type": "close" if "[DESTROY]" in line else "state",
        "timestamp_mono": time.monotonic() if stamp is None else stamp,
        "src_ip": fields["src"], "dst_ip": fields["dst"],
        "src_port": int(fields["sport"]), "dst_port": int(fields["dport"]),
        "outcome": "succeeded" if "ESTABLISHED" in line else "pending" if "SYN_SENT" in line else "unknown",
        "netns_id": netns_id}


class ConntrackReader:
    def __init__(self, pid: int, netns_id: int) -> None:
        self.pid, self.netns_id = pid, netns_id
        self.records_seen = 0
        self.overruns = 0
        self.stderr = deque(maxlen=20)

    async def records(self):
        prefix = ["nsenter", "-t", str(self.pid), "-n", "conntrack"]
        # Start the event listener BEFORE taking the snapshot to close the gap.
        process = await asyncio.create_subprocess_exec(*prefix, "-E", "-p", "tcp", "-f", "ipv4",
            "-o", "timestamp", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        async def errors():
            async for line in process.stderr:
                text = line.decode(errors="replace").strip()
                self.stderr.append(text)
                if "buffer" in text.lower() or "enobufs" in text.lower():
                    self.overruns += 1
        task = asyncio.create_task(errors())
        try:
            snapshot = await asyncio.create_subprocess_exec(*prefix, "-L", "-p", "tcp", "-f", "ipv4",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            try:
                out, err = await asyncio.wait_for(snapshot.communicate(), 15)
            finally:
                if snapshot.returncode is None:
                    snapshot.kill()
                    await snapshot.wait()
            if snapshot.returncode:
                raise RuntimeError("conntrack snapshot failed: " + err.decode(errors="replace"))
            for line in out.decode().splitlines():
                record = parse_conntrack(line, self.netns_id)
                if record:
                    yield record
            async for line in process.stdout:
                if self.overruns:
                    raise RuntimeError("conntrack event loss (ENOBUFS); restart capture to resync")
                record = parse_conntrack(line.decode(), self.netns_id)
                if record:
                    self.records_seen += 1
                    yield record
            await process.wait()
            await task
            raise RuntimeError("conntrack stream exited: " + "\n".join(self.stderr))
        finally:
            if process.returncode is None:
                process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), 3)
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

