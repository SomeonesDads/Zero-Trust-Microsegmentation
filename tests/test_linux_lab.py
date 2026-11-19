"""Opt-in acceptance test on the user's ALREADY deployed, isolated Linux lab."""
import asyncio
import os
import platform

import pytest

from app.models import EventType
from app.storage import RunStore
from app.telemetry.live import LiveSource
from lab.topology import load_config
from lab.validation import connection_probe

pytestmark = [pytest.mark.linux_lab, pytest.mark.skipif(
    platform.system() != "Linux" or os.environ.get("ZTM_LINUX_LAB") != "1",
    reason="set ZTM_LINUX_LAB=1 on the deployed Linux lab to run real eBPF/conntrack probes")]


@pytest.mark.asyncio
async def test_real_attributed_probe_and_conntrack(tmp_path):
    assert os.geteuid() == 0, "run with sudo and the project venv Python"
    store = RunStore(tmp_path / "capture")
    source = LiveSource(duration_seconds=30, store=store)
    observed = []
    async def collect():
        async for event in source.events():
            observed.append(event)
            store.append("events", event)
    task = asyncio.create_task(collect())
    try:
        for _ in range(120):
            if task.done():
                await task
            if source.ebpf and source.ebpf.ready:
                break
            await asyncio.sleep(0.25)
        assert source.ebpf and source.ebpf.ready, "collector did not become ready"
        result = await asyncio.to_thread(connection_probe, load_config(), 20)
        await asyncio.sleep(3)
        ports = {x["src_port"] for x in result["connections"]}
        connections = [e for e in observed if e.event_type == EventType.CONNECT and
                       e.dst_ip == result["target"] and e.src_port in ports and e.source == "ebpf"]
        assert len(connections) == 20
        assert all(e.attribution == "resolved" and e.src_container.endswith("api-1") for e in connections)
        assert any(e.source == "conntrack" and e.dst_ip == result["target"] for e in observed)
        assert source.stats["queue_dropped"] == 0
        assert source.ebpf.metrics.get("attempted", 0) >= 20
        assert source.ebpf.metrics.get("perf_lost", -1) == 0
        assert source.ebpf.metrics.get("submit_failed", -1) == 0
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        store.close()
