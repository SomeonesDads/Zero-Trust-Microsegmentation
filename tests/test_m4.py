from __future__ import annotations

import asyncio
import json

from fastapi.testclient import TestClient
import numpy as np
import pytest

from app.config import RuntimeConfig
from app.detection.isolation_forest import IsolationForestDetector
from app.main import build_app
from app.models import Finding, NetworkEvent
from app.orchestration.asyncio_orchestrator import Orchestrator
from app.storage import RunStore, read_events
from app.telemetry.simulator import SimulatorSource, baseline_events, synthetic_events
from app.training import train


def write_capture(path, events):
    path.write_text("".join(e.model_dump_json() + "\n" for e in events), encoding="utf-8")


def test_training_heldout_threshold_and_json_roundtrip(tmp_path):
    capture, model_file = tmp_path / "capture.jsonl", tmp_path / "model.json"
    write_capture(capture, baseline_events(count=1000))
    report = train(str(capture), str(model_file))
    first = IsolationForestDetector.load(model_file)
    second = IsolationForestDetector.load(model_file)
    assert report["training_rows"] > 0 and report["calibration_rows"] > 0
    assert report["capture_sha256"] and report["calibration_fpr"] <= 0.02
    first.observe(synthetic_events()[0])
    scores_a, scores_b = [], []
    first.reset_windows()
    for event in synthetic_events():
        first.observe(event)
        second.observe(event)
        scores_a.append(first.last_score)
        scores_b.append(second.last_score)
    assert scores_a == scores_b
    document = json.loads(model_file.read_text())
    document["sklearn"] = "incompatible"
    model_file.write_text(json.dumps(document))
    with pytest.raises(ValueError, match="mismatch"):
        IsolationForestDetector.load(model_file)


def test_calibration_edges_do_not_leak_into_training(tmp_path):
    events = baseline_events(count=1000)
    for event in events[-100:]:
        event.dst_service, event.dst_container, event.dst_port = "new-service", "new-1", 9999
    capture, target = tmp_path / "capture.jsonl", tmp_path / "model.json"
    write_capture(capture, events)
    train(str(capture), str(target))
    model = IsolationForestDetector.load(target)
    assert not any(edge[1] == "new-service" for edge in model._known_edges)


def test_training_rejects_mixed_clocks(tmp_path):
    events = baseline_events(count=100)
    events[-1].boot_id = "another-boot"
    capture = tmp_path / "capture.jsonl"
    write_capture(capture, events)
    with pytest.raises(ValueError, match="one host/boot"):
        train(str(capture), str(tmp_path / "model.json"))


def test_feature_windows_do_not_merge_replicas_and_ignore_pending_outcomes():
    model = IsolationForestDetector(window_seconds=10)
    event = baseline_events(count=1)[0]
    event.source, event.failed, event.outcome = "ebpf", False, "pending"
    model.features(event)
    other = event.model_copy(update={"src_container_id": "web-2@new", "timestamp_mono": 1})
    features = model.features(other)
    assert features["connection_count"] == 1 and features["failed_ratio"] == 0
    assert len(model._windows) == 2


def test_window_overflow_and_out_of_order_do_not_create_alerts():
    model = IsolationForestDetector(window_seconds=2, max_window_events=2)
    model.fit_baseline([[1.0] * 8, [2.0] * 8])
    template = baseline_events(count=1)[0]
    for stamp in (0, 0.1, 0.2, 0.3):
        assert model.observe(template.model_copy(update={"timestamp_mono": stamp})) is None
    assert model.last_score["status"] == "window_overflow"
    assert model.observe(template.model_copy(update={"timestamp_mono": 0.1})) is None
    assert model.out_of_order == 1


def test_store_rotation_and_streaming_replay_order(tmp_path):
    store = RunStore(tmp_path, max_bytes=1024, parts=20)
    events = baseline_events(count=10)
    for event in events:
        store.append("events", event)
    store.close()
    assert store.rotations["events"] > 0
    assert [e.stable_id() for e in read_events(tmp_path)] == [e.stable_id() for e in events]


@pytest.mark.asyncio
async def test_queue_and_history_are_bounded_and_loss_is_visible(tmp_path):
    class Slow:
        def observe(self, event):
            import time
            time.sleep(0.01)
    state = Orchestrator(SimulatorSource(baseline_events(count=100)), detector=Slow(),
                         queue_size=2, retention=5)
    await state.run()
    assert state.metrics["events_total"] == 100
    assert state.metrics["analysis_queue_dropped"] > 0
    assert state.metrics["queue_high_water"] <= 2
    assert len(state.events) == 5 and len(state.observer._ids) == 5


@pytest.mark.asyncio
async def test_unresolved_findings_never_become_policies():
    class Detector:
        def observe(self, event):
            return Finding(source="external", destination="api", score=1, features={},
                           explanation="test", attribution="external")
    state = Orchestrator(SimulatorSource(baseline_events(count=1)), detector=Detector())
    await state.run()
    assert len(state.alerts) == 1 and not state.enforcer.policies
    assert state.metrics["unresolved_policy_skipped"] == 1


def test_replay_api_and_persisted_audit(tmp_path):
    capture, model_file = tmp_path / "baseline.jsonl", tmp_path / "model.json"
    write_capture(capture, baseline_events(count=1000))
    train(str(capture), str(model_file))
    evaluation = tmp_path / "eval.jsonl"
    write_capture(evaluation, synthetic_events())
    output = tmp_path / "run"
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"source": "replay", "model_path": str(model_file),
        "replay_path": str(evaluation), "output_dir": str(output)}))
    application = build_app(config)
    with TestClient(application) as client:
        client.portal.call(lambda: application.state.simulation_task)
        assert client.get("/health").json()["source"] == "replay"
        assert len(client.get("/events?limit=3&offset=2").json()) == 3
        assert client.get("/graph?view=instances").json()["nodes"]
        assert client.get("/scores").json()
        assert client.get("/telemetry-health").json()["pipeline"]["events_total"] == 40
        assert all(policy["state"] == "proposed" for policy in client.get("/policies").json())
    assert json.loads((output / "summary.json").read_text())["status"] == "completed"
    assert (output / "scores.jsonl").exists()
    with pytest.raises(ValueError, match="new or empty"):
        build_app(config)


def test_live_requires_real_training_and_explicit_config(tmp_path):
    with pytest.raises(ValueError, match="model trained"):
        RuntimeConfig(source="live")
    with pytest.raises(ValueError):
        RuntimeConfig(enforcement_mode="auto-approve")
    capture, model_file = tmp_path / "baseline.jsonl", tmp_path / "model.json"
    write_capture(capture, baseline_events(count=1000))
    train(str(capture), str(model_file))
    config = tmp_path / "live.json"
    config.write_text(json.dumps({"source": "live", "model_path": str(model_file),
                                 "output_dir": str(tmp_path / "run")}))
    with pytest.raises(ValueError, match="real benign capture"):
        build_app(config)


def test_policy_ids_distinguish_container_restart():
    from app.policies.enforcement import DryRunEnforcer
    enforcer = DryRunEnforcer()
    finding = Finding(source="web", destination="api", src_container="web-1", dst_container="api-1",
        src_container_id="web-1@old", dst_container_id="api-1@old", score=1, features={}, explanation="test")
    old = enforcer.propose(finding)
    new = enforcer.propose(finding.model_copy(update={"src_container_id": "web-1@new"}))
    assert old.policy_id != new.policy_id
    with pytest.raises(ValueError, match="resolved"):
        enforcer.propose(finding.model_copy(update={"attribution": "unknown"}))


@pytest.mark.asyncio
async def test_failed_source_stops_worker_and_persists_error(tmp_path):
    class BrokenSource:
        async def events(self):
            yield baseline_events(count=1)[0]
            raise RuntimeError("collector disconnected")
    class Detector:
        def observe(self, event):
            return None
    state = Orchestrator(BrokenSource(), detector=Detector(), store=RunStore(tmp_path))
    with pytest.raises(RuntimeError, match="disconnected"):
        await asyncio.wait_for(state.run(), 2)
    result = json.loads((tmp_path / "summary.json").read_text())
    assert result["status"] == "failed" and result["error"] == "collector disconnected"


@pytest.mark.asyncio
async def test_cancellation_closes_source_and_records_stopped(tmp_path):
    closed = asyncio.Event()
    class Infinite:
        async def events(self):
            try:
                yield baseline_events(count=1)[0]
                await asyncio.Event().wait()
            finally:
                closed.set()
    class Detector:
        def observe(self, event):
            return None
    state = Orchestrator(Infinite(), detector=Detector(), store=RunStore(tmp_path))
    task = asyncio.create_task(state.run())
    for _ in range(50):
        if state.events:
            break
        await asyncio.sleep(0.01)
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    assert closed.is_set()
    assert json.loads((tmp_path / "summary.json").read_text())["status"] == "stopped"
