from __future__ import annotations

import asyncio
import threading
from unittest.mock import patch

from fastapi.testclient import TestClient
import pytest

from app.agents.graph_observer import GraphObserver
from app.config import SimulationConfig
from app.detection.isolation_forest import IsolationForestDetector
from app.main import build_app
from app.models import EventType, Finding, NetworkEvent
from app.orchestration.asyncio_orchestrator import Orchestrator
from app.policies.enforcement import DryRunEnforcer
from app.telemetry.replay import ReplaySource
from app.telemetry.simulator import SimulatorSource, baseline_events, synthetic_events


def event(i: float, dst: str = "api", port: int = 8080, **kwargs) -> NetworkEvent:
    return NetworkEvent(timestamp_mono=i, src_container="web-1", src_service="web",
                        dst_container=f"{dst}-1", dst_service=dst, dst_port=port, **kwargs)


def detector() -> IsolationForestDetector:
    result = IsolationForestDetector()
    result.fit_events(baseline_events())
    return result


def test_graph_updates_and_deduplicates() -> None:
    observer = GraphObserver()
    assert observer.observe(event(1)) is True
    assert observer.observe(event(1)) is False
    assert observer.graph["web"]["api"]["count"] == 1


def test_isolation_forest_detects_synthetic_attacks_without_flagging_benign_segment() -> None:
    model = detector()
    findings = [(item, model.observe(item)) for item in synthetic_events()]
    assert any(finding for item, finding in findings if item.event_id.startswith("anomaly"))
    assert not any(finding for item, finding in findings if item.event_id.startswith("normal"))


def test_features_use_configured_window_and_baseline_edges() -> None:
    model = IsolationForestDetector(window_seconds=2)
    model.fit_events([event(i) for i in range(20)])
    assert model.features(event(0))["new_edge"] == 0
    features = model.features(event(1, "redis", 6379, failed=True, bytes_count=120))
    assert features["fan_out"] == 2
    assert features["new_edge"] == 1
    assert features["connection_rate"] == 0.5
    assert features["bytes_per_connection"] == 120
    assert model.features(event(3))["connection_count"] == 1


def test_threshold_calibration_and_invalid_configuration() -> None:
    model = detector()
    with pytest.raises(ValueError):
        IsolationForestDetector(window_seconds=0)
    with pytest.raises(ValueError):
        IsolationForestDetector(false_positive_target=1)
    with pytest.raises(ValueError):
        model.fit_baseline([[float("nan")] * 8] * 2)
    with pytest.raises(ValueError):
        SimulationConfig(enforcement_mode="auto-approve")
    assert model._model is not None and model.threshold > 0
    assert not model._windows
    assert model.observe(event(0, event_type=EventType.CLOSE)) is None


def test_policy_is_scoped_idempotent_audited_and_reversible() -> None:
    enforcer = DryRunEnforcer("auto-approve")
    finding = Finding(source="web", destination="redis", src_container="web-1",
                      dst_container="redis-1", dst_port=6379, score=2, features={}, explanation="test")
    first = enforcer.propose(finding)
    assert first == enforcer.propose(finding)
    assert first.state == "verified"
    assert not enforcer.backend.permits(event(1, "redis", 6379))
    assert enforcer.backend.permits(event(2))
    assert enforcer.backend.permits(event(3, "redis", 6380))
    assert enforcer.backend.permits(event(3, "redis", 6379).model_copy(update={"protocol": "udp"}))
    assert enforcer.backend.permits(event(4, "redis", 6379).model_copy(update={"src_container": "web-2"}))
    assert enforcer.rollback(first.policy_id).state == "rolled_back"
    assert enforcer.backend.permits(event(5, "redis", 6379))
    enforcer.rollback(first.policy_id)
    assert [entry["transition"] for entry in enforcer.audit] == [
        "proposed", "validated", "approved", "applied", "verified", "rolled_back"]
    assert all(entry["timestamp"] for entry in enforcer.audit)


def test_default_dry_run_and_manual_approval() -> None:
    finding = Finding(source="web", destination="redis", score=2, features={}, explanation="test")
    dry = DryRunEnforcer()
    policy = dry.propose(finding)
    assert policy.state == "proposed" and not dry.backend.active
    with pytest.raises(ValueError):
        dry.approve(policy.policy_id)
    manual = DryRunEnforcer("manual-approve")
    proposed = manual.propose(finding)
    assert not manual.backend.active
    assert manual.approve(proposed.policy_id).state == "verified"


@pytest.mark.asyncio
async def test_end_to_end_real_model_deduplication_and_benign_flow() -> None:
    model = detector()
    events = synthetic_events()
    enforcer = DryRunEnforcer()
    state = Orchestrator(SimulatorSource(events + events[-5:]), detector=model, enforcer=enforcer)
    with patch.object(model._model, "score_samples", wraps=model._model.score_samples) as score:
        await asyncio.wait_for(state.run(), 10)
    assert score.call_count > 0
    assert state.status == "completed"
    assert len(state.events) == 40
    assert state.alerts and enforcer.policies
    assert len(enforcer.audit) == len(enforcer.policies)
    assert all(policy.mode == "dry-run" and policy.state == "proposed" for policy in enforcer.policies.values())
    assert all(policy.destination == "postgres-1" for policy in enforcer.policies.values())
    assert enforcer.backend.permits(event(100))
    assert state.observer.graph.has_edge("web", "api")


@pytest.mark.asyncio
async def test_slow_inference_does_not_block_ingestion_or_event_loop() -> None:
    started, release = threading.Event(), threading.Event()

    class SlowDetector:
        def observe(self, item):
            started.set()
            assert release.wait(3)
            return None

    state = Orchestrator(SimulatorSource([event(i) for i in range(20)]), detector=SlowDetector())
    task = asyncio.create_task(state.run())
    try:
        for _ in range(200):
            if started.is_set() and len(state.events) == 20:
                break
            await asyncio.sleep(0.005)
        assert started.is_set() and len(state.events) == 20
    finally:
        release.set()
        await asyncio.wait_for(task, 5)


@pytest.mark.asyncio
async def test_worker_errors_propagate_without_hanging() -> None:
    class Broken:
        def observe(self, item):
            raise RuntimeError("inference failed")

    state = Orchestrator(SimulatorSource([event(1)]), detector=Broken())
    with pytest.raises(RuntimeError, match="inference failed"):
        await asyncio.wait_for(state.run(), 3)
    assert state.status == "failed" and state.error == "inference failed"


@pytest.mark.asyncio
async def test_replay_uses_the_same_model_and_deduplicates(tmp_path) -> None:
    events = synthetic_events()
    path = tmp_path / "events.jsonl"
    path.write_text("\n".join(item.model_dump_json() for item in events + events[-2:]))
    state = Orchestrator(ReplaySource(path), detector=detector())
    await state.run()
    assert len(state.events) == 40 and state.alerts


def test_api_lifespan_starts_simulation_and_returns_data() -> None:
    application = build_app()
    with TestClient(application) as client:
        # Tests the actual ASGI lifespan rather than manually calling run().
        client.portal.call(lambda: application.state.simulation_task)
        assert client.get("/health").json()["pipeline"] == "completed"
        assert client.get("/health").json()["mode"] == "dry-run"
        assert len(client.get("/events").json()) == 40
        assert client.get("/graph").json()["edges"]
        assert client.get("/alerts").json()
        assert client.get("/policies").json()
        assert client.get("/agent-status").json()["threat_analysis"] == "completed"
