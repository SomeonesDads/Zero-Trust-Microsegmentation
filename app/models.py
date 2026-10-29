"""Normalized event and result models shared by all agents and sources."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid5, NAMESPACE_URL

from pydantic import BaseModel, Field, ConfigDict


class EventType(str, Enum):
    CONNECT = "connect"
    ACCEPT = "accept"
    CLOSE = "close"


class NetworkEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamp_mono: float
    timestamp_wall: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event_type: EventType = EventType.CONNECT
    src_container: str
    src_service: str
    dst_container: str
    dst_service: str
    src_ip: str = "127.0.0.1"
    dst_ip: str = "127.0.0.1"
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

    def stable_id(self) -> str:
        """Return an id stable across replay and duplicate delivery."""
        if self.event_id:
            return self.event_id
        identity = "|".join(str(v) for v in (self.timestamp_mono, self.event_type, self.src_container,
                                                self.dst_container, self.dst_port, self.protocol))
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


def jsonable(value: Any) -> Any:
    return value.model_dump(mode="json") if isinstance(value, BaseModel) else value

