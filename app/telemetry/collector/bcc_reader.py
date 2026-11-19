"""Standalone system-Python/BCC child; stdout is a versioned JSONL protocol.

stdin receives complete netns allow-list snapshots. No project/PyPI imports
are needed by this process; install python3-bpfcc via the Linux distribution.
"""
from __future__ import annotations

import ctypes
from datetime import datetime, timezone
import json
from pathlib import Path
import queue
import signal
import socket
import struct
import sys
import threading
import time


def main() -> None:
    from bcc import BPF
    initial = json.loads(sys.stdin.readline())
    program = BPF(text=Path(__file__).with_name("tcp.c").read_text())
    updates = queue.Queue(maxsize=1)
    stopped = threading.Event()
    lost = 0
    emitted = 0

    def output(value):
        print(json.dumps(value), flush=True)

    def update(namespaces):
        table = program["allowed_netns"]
        desired = {int(value) for value in namespaces}
        for key in list(table.keys()):
            if key.value not in desired:
                del table[key]
        for value in desired:
            table[ctypes.c_uint(value)] = ctypes.c_ubyte(1)

    def control():
        for line in sys.stdin:
            try:
                value = json.loads(line)["netns"]
                if updates.full():
                    updates.get_nowait()
                updates.put_nowait(value)
            except (ValueError, KeyError):
                stopped.set()
        stopped.set()

    def event(cpu, data, size):
        nonlocal emitted
        item = program["events"].event(data)
        src = socket.inet_ntop(socket.AF_INET, struct.pack("=I", item.src_ip))
        dst = socket.inet_ntop(socket.AF_INET, struct.pack("=I", item.dst_ip))
        sport, dport = int(item.src_port), int(item.dst_port)
        kind = {1: "connect", 2: "accept", 3: "close", 4: "close"}[item.kind]
        if item.kind in (2, 4):
            src, dst, sport, dport = dst, src, dport, sport
        emitted += 1
        output({"type": "event", "source": "ebpf", "timestamp_mono": item.timestamp_ns / 1e9,
            "timestamp_wall": datetime.fromtimestamp(time.time() - (time.monotonic() - item.timestamp_ns / 1e9), timezone.utc).isoformat(),
            "event_type": kind, "src_ip": src, "dst_ip": dst, "src_port": sport,
            "dst_port": dport, "netns_id": int(item.netns_id), "cgroup_id": int(item.cgroup_id),
            "pid": int(item.pid), "comm": item.comm.decode(errors="replace"),
            "local_endpoint": "destination" if item.kind in (2, 4) else "source",
            "outcome": "failed" if kind == "connect" and item.result != 0 else
                       "pending" if kind == "connect" else "succeeded" if kind == "accept" else "unknown"})

    def loss(cpu, count):
        nonlocal lost
        lost += count

    update(initial["netns"])
    try:
        program.attach_kprobe(event="tcp_v4_connect", fn_name="connect_entry")
        program.attach_kretprobe(event="tcp_v4_connect", fn_name="connect_return", maxactive=1024)
        program.attach_kretprobe(event="inet_csk_accept", fn_name="accept_return", maxactive=1024)
        program.attach_kprobe(event="tcp_close", fn_name="close_entry")
        program["events"].open_perf_buffer(event, page_cnt=64, lost_cb=loss)
        signal.signal(signal.SIGTERM, lambda *_: stopped.set())
        signal.signal(signal.SIGINT, lambda *_: stopped.set())
        threading.Thread(target=control, daemon=True).start()
        output({"type": "ready", "schema_version": 2, "hooks": ["tcp_v4_connect", "inet_csk_accept", "tcp_close"]})
        last = time.monotonic()
        while not stopped.is_set():
            try:
                update(updates.get_nowait())
            except queue.Empty:
                pass
            program.perf_buffer_poll(timeout=100)
            if time.monotonic() - last >= 1:
                counts = [int(program["counters"][ctypes.c_int(i)].value) for i in range(3)]
                output({"type": "metrics", "attempted": counts[0], "submit_failed": counts[1],
                    "entry_map_failed": counts[2], "perf_lost": lost, "received": emitted,
                    "submit_loss_rate": counts[1] / counts[0] if counts[0] else 0})
                last = time.monotonic()
    finally:
        program.cleanup()


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"BCC collector failed: {error}", file=sys.stderr, flush=True)
        raise SystemExit(1)
