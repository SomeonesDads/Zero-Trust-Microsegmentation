# Zero-Trust Microsegmentation — M1 simulation core

This repository contains the no-root, dry-run simulation milestone for the Topic 04 testbed. It is deliberately independent of Docker, Containerlab, eBPF, kernel privileges, and external hosts.

## Run

```powershell
py -3.10 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
python -m pytest -q
python -m app.main
```

The API can be served with `uvicorn app.main:app --reload`. Endpoints are `/health`, `/events`, `/graph`, `/alerts`, `/policies`, and `/agent-status`.

The simulator and replay source implement the same async telemetry interface. The normalized event model already includes attribution, loss-related source metadata, and fields needed by future eBPF/conntrack readers. The graph observer is NetworkX-based. The detector uses a replaceable Isolation Forest with window features and baseline threshold calibration. The primary enforcement backend is represented by a tc/eBPF-shaped backend stub; the default is dry-run and policies are scoped, deterministic, idempotent, audited, and reversible. Kubernetes NetworkPolicy output is an artifact-only static baseline.

## M0 environment status

Verified in the development session: Windows host; Python 3.10.11; Docker CLI 28.4.0. Docker daemon access was denied. Containerlab, clang, bpftool, libbpf/pkg-config, WSL kernel/BTF, and chrony were unavailable or not verifiable from this session. M2 must re-check these on the Linux Mini PC and laptop.

## Safety and limitations

No code enables real enforcement, flushes firewall rules, opens sockets, or targets external hosts. This is a development simulation; it must not be mixed with real-testbed experiment results. Real eBPF telemetry will require a Linux host with kernel >= 5.15, BTF, CAP_BPF/CAP_PERFMON/CAP_NET_ADMIN (or root), container attribution, ring-buffer loss counters, and an explicit configured enforcement mode. M2 is the next milestone: host preparation, Containerlab topology, isolated services, replicas/decoys, and Locust traffic.

