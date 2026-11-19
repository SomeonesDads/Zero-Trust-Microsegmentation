"""Canonical client-to-server events and bounded cross-sensor flow correlation."""
from __future__ import annotations

from collections import OrderedDict
from datetime import datetime, timezone
from hashlib import sha256
import ipaddress
import time

from app.models import EventType, NetworkEvent
from app.telemetry.identity import IdentityRegistry


class Normalizer:
    def __init__(self, registry: IdentityRegistry, subnets: list[str], host_id: str,
                 boot_id: str, retention: int = 10000) -> None:
        self.registry = registry
        self.networks = [ipaddress.ip_network(net) for net in subnets]
        self.host_id, self.boot_id = host_id, boot_id
        self.retention = retention
        self.flows: OrderedDict[tuple, tuple[str, float]] = OrderedDict()
        self.unknown = 0
        self.filtered = 0
        self.sequence = 0

    def normalize(self, raw: dict) -> NetworkEvent | None:
        src, dst = str(ipaddress.ip_address(raw["src_ip"])), str(ipaddress.ip_address(raw["dst_ip"]))
        if not any(ipaddress.ip_address(ip) in net for ip in (src, dst) for net in self.networks):
            self.filtered += 1
            return None
        left, right = self.registry.by_ip.get(src), self.registry.by_ip.get(dst)
        kind = EventType(raw["event_type"])
        # Probe's socket netns must agree with the attributed local endpoint.
        destination_local = kind == EventType.ACCEPT or raw.get("local_endpoint") == "destination"
        local = right if destination_local else left
        if raw.get("source", "ebpf") == "ebpf" and local is None:
            namespace = self.registry.by_netns.get(raw.get("netns_id"))
            local_ip = dst if destination_local else src
            # A failed connect can have an unspecified local address. Its socket
            # namespace is still authoritative; do not infer a remote endpoint.
            if namespace and (local_ip == "0.0.0.0" or local_ip in namespace.ips):
                if destination_local:
                    right = namespace
                else:
                    left = namespace
                local = namespace
        if raw.get("source", "ebpf") == "ebpf" and raw.get("netns_id") and local and local.netns_id != raw["netns_id"]:
            if destination_local:
                right = None
            else:
                left = None
        def unresolved(ip, identity):
            return identity is None and any(ipaddress.ip_address(ip) in net for net in self.networks)
        attribution = "unknown" if unresolved(src, left) or unresolved(dst, right) else (
            "resolved" if left and right else "external")
        self.unknown += int(attribution == "unknown")
        stamp = float(raw["timestamp_mono"])
        key = (src, int(raw.get("src_port", 0)), dst, int(raw["dst_port"]),
               left.container_id if left else "", right.container_id if right else "")
        previous = self.flows.get(key)
        # Connect is authoritative for container-originated traffic. Accept is
        # authoritative only for an external client. Conntrack is corroboration.
        source = raw.get("source", "ebpf")
        count = source == "ebpf" and (kind == EventType.CONNECT or
                (kind == EventType.ACCEPT and left is None and attribution == "external"))
        if previous is None or stamp - previous[1] > 120:
            self.sequence += 1
            connection_id = sha256(f"{self.boot_id}|{key}|{stamp}|{self.sequence}".encode()).hexdigest()[:24]
        else:
            connection_id = previous[0]
        self.flows[key] = (connection_id, stamp)
        self.flows.move_to_end(key)
        if len(self.flows) > self.retention:
            self.flows.popitem(last=False)
        if kind == EventType.CLOSE:
            self.flows.pop(key, None)
        outcome = raw.get("outcome", "unknown")
        return NetworkEvent(timestamp_mono=stamp,
            timestamp_wall=raw.get("timestamp_wall", datetime.now(timezone.utc)),
            timestamp_ingest=time.monotonic(), event_type=kind,
            src_container=left.name if left else f"unknown:{src}" if unresolved(src, left) else f"external:{src}",
            dst_container=right.name if right else f"unknown:{dst}" if unresolved(dst, right) else f"external:{dst}",
            src_service=left.service if left else "unknown" if unresolved(src, left) else "external",
            dst_service=right.service if right else "unknown" if unresolved(dst, right) else "external",
            src_container_id=left.container_id if left else None,
            dst_container_id=right.container_id if right else None,
            src_ip=src, dst_ip=dst, src_port=key[1], dst_port=key[3], source=source,
            netns_id=raw.get("netns_id"), cgroup_id=raw.get("cgroup_id"),
            pid=raw.get("pid"), comm=raw.get("comm"), attribution=attribution,
            counts_as_connection=count, outcome=outcome, failed=outcome == "failed",
            connection_id=connection_id, host_id=self.host_id, boot_id=self.boot_id)
