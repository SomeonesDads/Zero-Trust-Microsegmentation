from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from app.agents.graph_observer import GraphObserver
from app.detection.isolation_forest import IsolationForestDetector
from app.main import build_app
from app.models import Finding, NetworkEvent
from app.orchestration.asyncio_orchestrator import Orchestrator
from app.policies.enforcement import DryRunEnforcer
from app.telemetry.simulator import SimulatorSource, synthetic_events


def event(i: int, dst: str = "api", port: int = 8080, event_id: str | None = None) -> NetworkEvent:
    return NetworkEvent(timestamp_mono=float(i), src_container="web-1", src_service="web",
                        dst_container=f"{dst}-1", dst_service=dst, dst_port=port,
                        event_id=event_id or f"e-{i}-{dst}-{port}")


def test_graph_updates_and_deduplicates() -> None:
    observer = GraphObserver()
    assert observer.observe(event(1)) is True
    assert observer.observe(event(1)) is False
    assert observer.graph["web"]["api"]["count"] == 1


def test_anomalous_synthetic_traffic_is_detected() -> None:
    detector = IsolationForestDetector()
    detector.fit_baseline([[1, 1, 1, 0, 0, float(i)] for i in range(20)])
    findings = [detector.observe(e) for e in synthetic_events(normal_count=0, anomalous_count=10)]
    assert any(findings)


def test_policy_is_scoped_idempotent_and_rollback_works() -> None:
    enforcer = DryRunEnforcer()
    finding = Finding(source="web", destination="redis", score=2, features={}, explanation="test")
    first = enforcer.propose(finding)
    second = enforcer.propose(finding)
    assert first.policy_id == second.policy_id
    assert len(enforcer.audit) == 1
    assert enforcer.rollback(first.policy_id).state == "rolled_back"


@pytest.mark.asyncio
async def test_end_to_end_and_benign_flow() -> None:
    detector = IsolationForestDetector()
    detector.fit_baseline([[1, 1, 1, 0, 0, float(i)] for i in range(20)])
    orchestrator = Orchestrator(SimulatorSource(synthetic_events()), detector=detector)
    await orchestrator.run()
    assert len(orchestrator.events) == 40
    assert orchestrator.observer.graph.has_edge("web", "api")


@pytest.mark.asyncio
async def test_api_endpoints_return_valid_data() -> None:
    app = build_app()
    await app.state.orchestrator.run()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        assert (await client.get("/health")).json()["status"] == "ok"
        assert "nodes" in (await client.get("/graph")).json()
        assert isinstance((await client.get("/events")).json(), list)
        assert isinstance((await client.get("/alerts")).json(), list)
        assert isinstance((await client.get("/policies")).json(), list)

