from __future__ import annotations

import asyncio
import json
from pathlib import Path
import time

import pytest

from app.agents.graph_observer import GraphObserver
from app.models import EventType
from app.telemetry.conntrack import parse_conntrack
from app.telemetry.identity import ContainerIdentity, IdentityRegistry
from app.telemetry.normalize import Normalizer
from lab.validation import parse_clock


def identity(name, service, address, ns, generation="old"):
    return ContainerIdentity(f"{name}@{generation}", name, service, ns, ns, ns + 1000, (address,))


@pytest.fixture
def registry():
    registry = IdentityRegistry()
    registry.replace([identity("web-1", "web", "10.77.20.11", 11),
                      identity("api-1", "api", "10.77.20.31", 31)])
    return registry


def raw(kind="connect", source="ebpf", **changes):
    return {"event_type": kind, "source": source, "timestamp_mono": 1,
        "src_ip": "10.77.20.11", "dst_ip": "10.77.20.31", "src_port": 40000,
        "dst_port": 8080, "netns_id": 31 if kind == "accept" else 11, **changes}


def normalizer(registry):
    return Normalizer(registry, ["10.77.20.0/24"], "host", "boot")


def test_connect_accept_conntrack_count_once_and_share_flow(registry):
    source = normalizer(registry)
    events = [source.normalize(raw()), source.normalize(raw("accept", timestamp_mono=1.01)),
              source.normalize(raw("state", "conntrack", netns_id=31, timestamp_mono=1.02))]
    assert {e.connection_id for e in events} == {events[0].connection_id}
    assert [e.counts_as_connection for e in events] == [True, False, False]
    assert all(e.attribution == "resolved" for e in events)
    observer = GraphObserver()
    for event in events:
        observer.observe(event)
    assert observer.graph["web"]["api"]["count"] == 1
    assert observer.instances["web-1@old"]["api-1@old"]["count"] == 1
    assert not observer.observe(events[0])


def test_accept_arriving_before_connect_does_not_double_count(registry):
    source = normalizer(registry)
    accepted = source.normalize(raw("accept"))
    connected = source.normalize(raw(timestamp_mono=1.01))
    assert accepted.connection_id == connected.connection_id
    assert not accepted.counts_as_connection and connected.counts_as_connection


def test_external_accept_is_visible_but_not_resolved_container(registry):
    event = normalizer(registry).normalize(raw("accept", src_ip="10.77.0.2"))
    assert event.src_container == "external:10.77.0.2"
    assert event.attribution == "external" and event.counts_as_connection
    assert event.dst_port == 8080 and event.src_port == 40000


def test_restart_replaces_generation_and_rejects_stale_namespace(registry):
    source = normalizer(registry)
    first = source.normalize(raw())
    registry.replace([identity("web-1", "web", "10.77.20.11", 12, "new"),
                      identity("api-1", "api", "10.77.20.31", 31)])
    stale = source.normalize(raw(timestamp_mono=2))
    current = source.normalize(raw(timestamp_mono=3, netns_id=12))
    assert stale.attribution == "unknown"
    assert current.source_key() == "web-1@new"
    assert current.connection_id != first.connection_id
    assert 11 not in registry.by_netns


def test_failed_connect_unspecified_address_uses_socket_namespace(registry):
    event = normalizer(registry).normalize(raw(src_ip="0.0.0.0", outcome="failed"))
    assert event.source_key() == "web-1@old"
    assert event.attribution == "resolved" and event.failed


def test_server_close_keeps_original_direction(registry):
    event = normalizer(registry).normalize(raw("close", netns_id=31, local_endpoint="destination"))
    assert event.attribution == "resolved"
    assert event.src_service == "web" and event.dst_service == "api"
    assert not event.counts_as_connection


def test_registry_rejects_ambiguous_ip_without_destroying_previous_snapshot(registry):
    with pytest.raises(ValueError, match="ambiguous container IP"):
        registry.replace([identity("x", "api", "10.0.0.1", 1), identity("y", "api", "10.0.0.1", 2)])
    assert "10.77.20.11" in registry.by_ip


def test_filter_unknown_and_stable_ids_include_source_port(registry):
    source = normalizer(registry)
    assert source.normalize(raw(src_ip="192.0.2.1", dst_ip="192.0.2.2")) is None
    unknown = source.normalize(raw(dst_ip="10.77.20.99"))
    assert unknown.attribution == "unknown"
    first = source.normalize(raw())
    second = source.normalize(raw(src_port=40001))
    assert first.stable_id() != second.stable_id()


def test_conntrack_parser_uses_original_tuple_and_honest_outcome():
    line = "[UPDATE] tcp 6 120 ESTABLISHED src=10.77.20.11 dst=10.77.20.31 sport=40000 dport=8080 src=10.77.20.31 dst=10.77.20.11 sport=8080 dport=40000 [ASSURED]"
    record = parse_conntrack(line, 31, 5)
    assert record["src_port"] == 40000 and record["dst_port"] == 8080
    assert record["outcome"] == "succeeded" and record["timestamp_mono"] == 5
    destroyed = parse_conntrack(line.replace("[UPDATE]", "[DESTROY]").replace("ESTABLISHED", "TIME_WAIT"), 31)
    assert destroyed["event_type"] == "close" and destroyed["outcome"] == "unknown"
    assert parse_conntrack("udp 17 30 src=1.2.3.4", 31) is None


def test_graph_retention_and_service_replica_identity(registry):
    source = normalizer(registry)
    observer = GraphObserver(retention=3)
    for i in range(10):
        event = source.normalize(raw(timestamp_mono=i, src_port=40000 + i))
        event.dst_service = f"service-{i}"
        event.dst_container_id = f"instance-{i}"
        observer.observe(event)
    assert len(observer._ids) == 3
    assert observer.graph.number_of_edges() == 3
    assert observer.instances.number_of_edges() == 3


def test_clock_bound_and_unsynchronized_state():
    good = "System time : 0.002 seconds slow of NTP time\nStratum : 2\nLeap status : Normal"
    assert parse_clock(good)["latency_valid"]
    assert not parse_clock(good.replace("0.002", "0.020"))["latency_valid"]
    assert not parse_clock(good.replace("Normal", "Not synchronised"))["latency_valid"]


@pytest.mark.asyncio
async def test_live_source_transports_attributed_events_and_closes_readers(monkeypatch, registry):
    from app.telemetry.live import LiveSource
    monkeypatch.setattr("app.telemetry.live.platform.system", lambda: "Linux")
    original_read = Path.read_text
    monkeypatch.setattr(Path, "read_text", lambda self, *a, **kw: "boot" if str(self).replace('\\', '/') == "/proc/sys/kernel/random/boot_id" else original_read(self, *a, **kw))
    monkeypatch.setattr(IdentityRegistry, "refresh", lambda self: self.replace(list(registry.containers.values())))
    closed = asyncio.Event()
    class Reader:
        def __init__(self, *args):
            self.ready, self.metrics = True, {"perf_lost": 0}
        async def update(self, namespaces):
            pass
        async def records(self):
            try:
                yield raw(timestamp_mono=time.monotonic())
                await asyncio.Event().wait()
            finally:
                closed.set()
    monkeypatch.setattr("app.telemetry.live.EBPFReader", Reader)
    source = LiveSource(conntrack=False, duration_seconds=0.4)
    events = [event async for event in source.events()]
    assert len(events) == 1 and events[0].attribution == "resolved"
    assert closed.is_set() and source.status == "completed"


@pytest.mark.asyncio
async def test_live_non_linux_fails_without_simulation_fallback(monkeypatch):
    from app.telemetry.live import LiveSource
    monkeypatch.setattr("app.telemetry.live.platform.system", lambda: "Windows")
    with pytest.raises(RuntimeError, match="requires Linux"):
        await anext(LiveSource(conntrack=False).events())
