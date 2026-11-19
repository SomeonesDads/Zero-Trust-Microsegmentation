"""Normalized event and result models shared by all agents and sources."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal
from uuid import uuid5, NAMESPACE_URL

from pydantic import BaseModel, Field, ConfigDict


class EventType(str, Enum):
    CONNECT = "connect"
    ACCEPT = "accept"
    CLOSE = "close"
    STATE = "state"


class NetworkEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamp_mono: float = Field(ge=0, allow_inf_nan=False)
    timestamp_wall: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event_type: EventType = EventType.CONNECT
    src_container: str
    src_service: str
    dst_container: str
    dst_service: str
    src_ip: str = "127.0.0.1"
    dst_ip: str = "127.0.0.1"
    src_port: int = Field(default=0, ge=0, le=65535)
    dst_port: int = Field(ge=1, le=65535)
    protocol: str = "tcp"
    netns_id: int | None = None
    cgroup_id: int | None = None
    pid: int | None = None
    comm: str | None = None
    source: str = "simulator"
    bytes_count: int | None = Field(default=None, ge=0)
    failed: bool = False
    event_id: str | None = None
    schema_version: int = 2
    host_id: str = "simulation"
    boot_id: str = "simulation"
    connection_id: str | None = None
    src_container_id: str | None = None
    dst_container_id: str | None = None
    attribution: Literal["resolved", "external", "unknown"] = "resolved"
    outcome: Literal["unknown", "pending", "succeeded", "failed"] = "unknown"
    counts_as_connection: bool = True
    timestamp_ingest: float | None = None

    def source_key(self) -> str:
        return self.src_container_id or self.src_container

    def destination_key(self) -> str:
        return self.dst_container_id or self.dst_container

    def stable_id(self) -> str:
        """Return an id stable across replay and duplicate delivery."""
        if self.event_id:
            return self.event_id
        identity = "|".join(str(v) for v in (self.host_id, self.boot_id, self.source,
            self.timestamp_mono, self.event_type, self.source_key(), self.destination_key(),
            self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.protocol))
        return str(uuid5(NAMESPACE_URL, identity))


class Finding(BaseModel):
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: str
    destination: str
    score: float
    features: dict[str, float]
    explanation: str
    recommended_mitigation: str = "scoped_quarantine"
    src_container: str | None = None
    dst_container: str | None = None
    dst_port: int | None = Field(default=None, ge=1, le=65535)
    protocol: str = "tcp"
    event_id: str | None = None
    timestamp_mono: float | None = None
    attribution: str = "resolved"
    src_container_id: str | None = None
    dst_container_id: str | None = None


class Policy(BaseModel):
    policy_id: str
    source: str
    destination: str
    port: int | None = None
    protocol: str = "tcp"
    action: str = "drop"
    mode: str = "dry-run"
    state: str = "proposed"
    reason: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    src_container_id: str | None = None
    dst_container_id: str | None = None


def jsonable(value: Any) -> Any:
    return value.model_dump(mode="json") if isinstance(value, BaseModel) else value

