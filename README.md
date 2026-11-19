# Zero-Trust Microsegmentation — M2–M4

This repository contains the no-root simulation core, the 15-container Containerlab testbed, and Linux live telemetry through BCC/eBPF and conntrack. The M4 agents generate dry-run policies; real tc/eBPF enforcement belongs to M5.

- [Implemented files and features (Indonesian)](docs/IMPLEMENTASI_M2_M3_M4.md)
- [Setup and testing tutorial (Indonesian)](docs/TESTING_M2_M3_M4.md)
- [Implementation roadmap and effort estimates](docs/RANCANGAN_IMPLEMENTASI.md)

## Run

```powershell
py -3.10 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
python -m pytest -q
python -m app.main
```

The simulation API can be served with `uvicorn app.main:app`. Endpoints include `/health`, `/events`, `/graph`, `/alerts`, `/policies`, `/agent-status`, `/telemetry-health`, `/scores`, and `/policy-audit`. Use `python -m scripts.offline_smoke` to test capture generation, held-out calibration, model persistence, and replay without Linux privileges.

Simulator, replay, and live sources share one async telemetry interface. NetworkX maintains service and instance graphs. Isolation Forest uses bounded windows and independent baseline calibration. JSONL artifacts preserve scores and proposed-policy audits. The enforcement backend remains simulated; Kubernetes NetworkPolicy output remains an artifact requiring further baseline implementation.

## Environment verification

The M2–M4 development session ran offline tests on Windows with Python 3.10.5. Ubuntu WSL exposes kernel 6.18.33.2 and BTF, but BCC, Containerlab, conntrack, and chrony were missing; Docker Engine was not available. Run the documented Linux acceptance tests on the Mini PC and laptop before claiming real deployment or telemetry success.

## Safety and limitations

Simulation remains the default. The lab CLI can deploy containers, configure owned bridges/firewall tables with explicit apply commands, and open allow-listed lab test connections. Live telemetry requires Linux, BCC, kernel support, and privileges; see the tutorial. It never applies packet-blocking policies. All outputs distinguish simulator/replay/live sources. Linux kernel attachment and two-host deployment need acceptance testing on the target hardware; offline tests alone do not establish those results.

