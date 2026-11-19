"""Train on a benign capture with a chronological held-out calibration segment."""
from __future__ import annotations

import argparse
from hashlib import sha256
from pathlib import Path
import random

from app.detection.isolation_forest import IsolationForestDetector
from app.storage import read_events


def train(capture: str, output: str, window: float = 10, fpr: float = 0.01,
          seed: int = 7, max_samples: int = 20000) -> dict:
    if max_samples < 2:
        raise ValueError("max_samples must be >= 2")
    detector = IsolationForestDetector(window, fpr, seed)
    first, last, count = None, None, 0
    clocks = set()
    sources = set()
    digest = sha256()
    for event in read_events(capture):
        digest.update(event.model_dump_json().encode())
        sources.add(event.source)
        clocks.add((event.host_id, event.boot_id))
        if detector.eligible(event):
            first = event.timestamp_mono if first is None else min(first, event.timestamp_mono)
            last = event.timestamp_mono if last is None else max(last, event.timestamp_mono)
            count += 1
    if len(clocks) != 1 or ("simulator" in sources and len(sources) > 1):
        raise ValueError("capture must use one host/boot and must not mix synthetic and real data")
    if count < 20 or last - first < window * 4:
        raise ValueError("baseline needs >=20 eligible events and >=4 windows of coverage")
    split = first + (last - first) * 0.7
    # Known edges are derived ONLY from the training interval.
    detector._known_edges = {detector.edge(e) for e in read_events(capture)
                            if detector.eligible(e) and e.timestamp_mono < split}
    samples = []
    for training in (True, False):
        rows, seen = [], 0
        rng = random.Random(seed)
        detector.reset_windows()
        for event in read_events(capture):
            if not detector.eligible(event) or (event.timestamp_mono < split) != training:
                continue
            features = detector.features(event)
            key = event.source_key()
            if event.timestamp_mono - detector._started_at[key] < window:
                continue
            if key in detector._overflow_at and event.timestamp_mono - detector._overflow_at[key] < window:
                raise ValueError("baseline window overflow; increase capacity or reduce load")
            row = [features[name] for name in detector.feature_names]
            seen += 1
            if len(rows) < max_samples:
                rows.append(row)
            else:
                index = rng.randrange(seen)
                if index < max_samples:
                    rows[index] = row
        if len(rows) < 2:
            raise ValueError("not enough post-warmup samples in each temporal partition")
        samples.append(rows)
    detector.fit_baseline(samples[0])
    detector.calibrate(samples[1])
    detector.metadata.update({"capture_sha256": digest.hexdigest(), "eligible_events": count,
        "training_rows": len(samples[0]), "split_mono": split, "duration_seconds": last - first,
        "sources": sorted(sources), "clock": list(next(iter(clocks))),
        "calibration": "last 30% of capture time; independent from training",
        "known_edges_scope": "service/port/protocol; windows remain per runtime instance"})
    detector.save(output)
    return {"model": str(output), "threshold": detector.threshold, **detector.metadata}


def main():
    import json
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--window", type=float, default=10)
    parser.add_argument("--fpr", type=float, default=0.01)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--max-samples", type=int, default=20000)
    args = parser.parse_args()
    print(json.dumps(train(args.capture, args.output, args.window, args.fpr, args.seed, args.max_samples), indent=2))


if __name__ == "__main__":
    main()
