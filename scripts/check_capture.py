"""Compare a lab connection-probe manifest against a captured TCP event stream."""
import argparse
import json
from pathlib import Path

from app.models import EventType
from app.storage import read_events


def check(capture: str, probe_path: str) -> dict:
    probe = json.loads(Path(probe_path).read_text(encoding="utf-8"))
    expected = {(x["src_ip"], x["src_port"]) for x in probe["connections"]}
    connects, accepts, conntrack = set(), set(), set()
    attribution_errors = 0
    for event in read_events(capture):
        if not (probe["started_mono"] <= event.timestamp_mono <= probe["ended_mono"] + 5):
            continue
        key = (event.src_ip, event.src_port)
        if key not in expected or event.dst_ip != probe["target"] or event.dst_port != probe["port"]:
            continue
        attribution_errors += int(event.attribution != "resolved")
        if event.source == "ebpf" and event.event_type == EventType.CONNECT:
            connects.add(key)
        if event.source == "ebpf" and event.event_type == EventType.ACCEPT:
            accepts.add(key)
        if event.source == "conntrack":
            conntrack.add(key)
    root = Path(capture) if Path(capture).is_dir() else Path(capture).parent
    health_file = root / "telemetry.json"
    health = json.loads(health_file.read_text()) if health_file.exists() else {}
    metrics = health.get("ebpf", {})
    loss_known = "perf_lost" in metrics and "submit_failed" in metrics
    no_loss = loss_known and all(metrics.get(key, 0) == 0 for key in ("perf_lost", "submit_failed", "entry_map_failed")) and health.get("queue_dropped", 0) == 0
    return {"passed": connects == expected and accepts == expected and attribution_errors == 0 and no_loss,
        "expected": len(expected), "connect_observed": len(connects), "accept_observed": len(accepts),
        "conntrack_observed": len(conntrack), "attribution_errors": attribution_errors,
        "loss_counters_available": loss_known, "no_loss_observed": no_loss,
        "note": "conntrack coverage is corroborating; socket completeness applies only to this controlled probe"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", required=True)
    parser.add_argument("--probe", required=True)
    args = parser.parse_args()
    result = check(args.capture, args.probe)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
