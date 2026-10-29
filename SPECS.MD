# SPECS.MD — Topic 04: Zero-Trust Microsegmentation

Autonomous Multi-Agent Zero-Trust Microsegmentation and Anomaly Mitigation in Containerized Cloud-Native Fabrics.

This file is the source of truth for the coding agent. Items marked **[SPEC]** come from the original project PDF. Items marked **[DESIGN]** are design decisions made to make the project buildable and reproducible; change them if needed, but document the change.

---

## 1. Problem and goal [SPEC]

- Static microsegmentation (Kubernetes NetworkPolicies, iptables) cannot adapt when an attacker moves laterally between microservices.
- Centralized SIEM systems need more than 60 s from detection to mitigation.
- Goal: an autonomous multi-agent system that detects anomalous lateral connections and quarantines the compromised container with least-privilege tc/eBPF drop filters, while other traffic keeps flowing.
- Reaction speed vs. the SIEM baseline is an **experimental hypothesis**, not a result. Never report numbers that were not measured.

## 2. System components [SPEC]

| Agent | Responsibility |
|---|---|
| Graph observer | Builds a live service-dependency graph from eBPF and conntrack connection events |
| Threat analysis | Flags unusual lateral connections using Isolation Forests or GNN embeddings |
| Enforcement | Writes least-privilege tc/eBPF filters that quarantine the compromised container and keep other traffic flowing |

- Agent stack: 3-tier Python agent system with local ML models, orchestrated with LangGraph/asyncio.
- Data flow: eBPF connect events go up to the observer, tc/eBPF drop rules go down to the workloads.
- Detectors must be pluggable (Isolation Forest first, GNN embeddings via PyTorch Geometric later).

## 3. Testbed [SPEC]

**Host 1 — Mini PC** (16 vCPU / 32 GB)
- Runs 15–20 containers: the agents and control plane, plus the Containerlab microservice app.
- App: Nginx web, Node auth, Python API, Redis cache, Postgres DB, on isolated bridge networks.
- eBPF hooks, agent controller.

**Host 2 — Laptop** (8–12 vCPU / 16–24 GB)
- Locust generates benign shopping-style traffic.
- Kali/Metasploit generates attacks.

**Link:** 1 GbE between hosts.

**Software:** Containerlab/Docker, BCC/eBPF, bpftool, clang, libbpf (libbpf-dev), scikit-learn, PyTorch Geometric.

**Host tuning:** kernel >= 5.15 with BPF enabled; `net.core.bpf_jit_enable=1`, `net.core.bpf_jit_harden=2`.

### Testbed design decisions [DESIGN]

- Containerlab is the primary topology. Docker Compose is allowed as a development fallback only, and must be labeled as such.
- Reach to Host 2: expose the Nginx entry point (and any attack-target interfaces) to Host 2 over the 1 GbE link via a dedicated lab VLAN/subnet or routed port. Internal tiers (API, Redis, Postgres) stay on isolated bridges not reachable from Host 2.
- Lateral movement: after an initial foothold on a service container (for example the web or API tier), attack steps toward Redis/Postgres originate from inside the lab network, so the graph observer sees service-to-service edges.
- Reach the 15–20 container target with the 5 base services plus replicas (for example 2x web, 2x API), decoy services, agent containers, and a collector. Document the final count.
- All attacks stay inside the isolated lab. No external targets, no public exposure.
- Clock sync: run chrony (or NTP) between both hosts. Record the offset at the start and end of every run. Flag runs where the offset exceeds 5 ms; do not use them for latency claims.

## 4. Telemetry [SPEC + DESIGN]

- Sources: eBPF connection events and conntrack events [SPEC].
- Hooks [DESIGN]: kprobe on `tcp_v4_connect` and kretprobe on `inet_csk_accept` (`tcp_accept` is not a kernel function; `inet_csk_accept` is the usual accept hook). Optional `tcp_v6_connect` if IPv6 is enabled. Optionally `inet_sock_set_state` tracepoint for close events.
- Attribution [DESIGN]: attribute each event to a container via network namespace inode or cgroup ID, mapped to container name and service via the container runtime or Containerlab metadata.
- Streaming: perf or ring buffer to a userspace reader, then to the observer.
- Normalized event fields: timestamp (monotonic and wall), event type (connect/accept/close), src container/service, dst container/service, src/dst IP, dst port, protocol, netns/cgroup ID, PID/comm, source (ebpf/conntrack/simulator).
- Completeness [SPEC smoke test: "telemetry captures every socket event"]: track ring-buffer drops (lost-event counters) and report an event-loss rate. Cross-check against conntrack counts.
- Missing telemetry is an observability failure, never evidence of an attack.
- A simulator source and a replay source must implement the same interface as the eBPF source.

## 5. Enforcement [SPEC + DESIGN]

- Primary backend: tc/eBPF drop filters.
- Attachment [DESIGN]: `clsact` qdisc with tc-bpf in direct-action mode on the host-side veth of the compromised container (ingress and egress). Document how same-bridge container-to-container traffic is covered (for example per-container veth filtering, since bridge-internal traffic crosses veths).
- Least privilege: block only the offending flow or quarantine the offending container's non-essential paths; leave unrelated legitimate flows alone.
- Policy lifecycle: proposed, validated, approved, applied, verified, rolled back. Each transition is audit-logged with timestamps.
- Modes [DESIGN]: `dry-run` (default), `manual-approve`, `auto-approve` (used for latency experiments). Real enforcement requires explicit configuration.
- Safety: never flush unrelated rules; policies are idempotent, scoped and reversible; fail safe if the container cannot be identified confidently.
- Kubernetes NetworkPolicy: generated as an artifact and used as the **static-policy comparison baseline**, not as the primary backend. Do not claim it enforces anything in a cluster that does not exist.

## 6. Threat analysis [SPEC + DESIGN]

- Isolation Forest first; GNN embeddings (PyTorch Geometric) as a later optional detector.
- Features per edge and window [DESIGN]: connection rate, fan-out (distinct destinations), distinct destination ports, new-edge flag, bytes/connection count if available, failed-connection ratio, time-of-window. Window size is configurable and recorded.
- Calibrate the score threshold on baseline data to a target false-positive rate (default 1%).
- Findings contain: timestamp, source, destination, score, features/explanation, recommended mitigation.
- Application-layer indicators (for example suspicious HTTP payloads) are kept separate from connection-level anomalies. A suspicious payload alone is not proof of lateral movement.
- Inference must not block event processing.

## 7. Experiments [SPEC + DESIGN]

Effort budget [SPEC]: about 6–8 days setup, 10–12 days experiments.

1. **Baseline**: 30 minutes of Locust shopping traffic to learn the normal graph. Shorter runs allowed for development.
2. **Attacks**: port scans, SSH brute force, and SQL injection leading to lateral Redis access.
3. **Trace mitigation**: detection, policy-generation and enforcement latency, plus false positives.
4. **Sweeps**: 20 attack vectors at 100–2000 req/s of background load (suggested levels: 100, 500, 1000, 2000).
5. **Analysis**: ROC curves for detection; CDFs of reaction latency.

### Attack catalog [DESIGN] (A01–A20)

Labels are ground truth. Each run records attacker host, source container, target, start time and end time. The three scenario families from the spec are marked.

| ID | Vector | Family |
|---|---|---|
| A01 | TCP connect scan of the web tier | port scan |
| A02 | TCP SYN scan of the web tier | port scan |
| A03 | Slow, low-rate scan (rate-evasion) | port scan |
| A04 | Internal sweep from compromised web container across internal subnet | port scan / lateral |
| A05 | Full-range port scan of the API tier | port scan |
| A06 | SSH brute force against an exposed SSH service | brute force |
| A07 | SSH brute force, slow and low | brute force |
| A08 | Credential spraying across several services | brute force |
| A09 | Brute force against the auth service login | brute force |
| A10 | SQL injection against the API (HTTP-layer indicator) | SQLi |
| A11 | SQLi followed by lateral Redis access | SQLi to Redis |
| A12 | SQLi followed by lateral Postgres access from unexpected source | SQLi to lateral |
| A13 | Unexpected web to Redis direct connection | lateral movement |
| A14 | Unexpected web to Postgres direct connection | lateral movement |
| A15 | Auth service to Redis unexpected access | lateral movement |
| A16 | Multi-hop pivot (web, API, Redis) | lateral movement |
| A17 | Connection to a decoy service | lateral movement |
| A18 | Burst of new edges from one container | lateral movement |
| A19 | Low-and-slow lateral movement spread over a long window | evasion |
| A20 | Lateral movement timed during a load spike | evasion |

Negative controls (benign, must not be flagged): N01 flash-sale load surge, N02 service restart with reconnect storm, N03 legitimate new deployment/replica.

### Trials, statistics, reproducibility [DESIGN]

- At least 10 trials per (attack vector, load level) condition; fixed seeds; report mean and 95% confidence intervals (bootstrap is fine).
- Write a run manifest per experiment: git commit, config hash, seeds, kernel version, tool versions, clock offset, host load, container count, detector threshold.
- Distinguish configured load (req/s) from measured achieved throughput. Report both. Distinguish HTTP requests/s from connection events/s.
- Dev-mode simulation results must never be mixed with real-testbed results.

## 8. Metrics [SPEC + DESIGN]

- **Mean time to containment (MTTC)**: end-to-end from attack start to verified containment; also report detection-to-containment.
- Stage latencies: first indicator to detection, detection to policy generation, policy generation to enforcement, enforcement to verified block.
- **Legitimate requests dropped** during mitigation (Locust failure and error counts).
- **eBPF agent CPU and memory** (per agent and total).
- **Attack-graph precision and recall** at the edge level: predicted malicious edges vs ground-truth malicious edges.
- Detection ROC (with AUC), precision, recall, F1; false-positive rate.
- Telemetry event-loss rate.
- CDFs of reaction and containment latency.

## 9. Comparison baselines [SPEC + DESIGN]

- **Static NetworkPolicy**: generate a static allow-list policy from the baseline graph, applied as a fixed policy (generated artifact plus an equivalent static enforcement for measurement). Does not adapt.
- **Snort/Suricata**: run Suricata in a container with a signature ruleset covering the attack vectors it can reasonably see. Document which vectors it cannot detect.
- **Centralized SIEM playbook**: emulate as a pipeline with log shipping, central correlation, and playbook execution, with a configurable log-shipping delay of at least 60 s. Label as an emulation. Do not call it a commercial SIEM measurement.
- Any baseline not implemented must be labeled "proposed", not given invented results.

## 10. Milestones and acceptance criteria [DESIGN]

| # | Milestone | Acceptance |
|---|---|---|
| M0 | Environment inspection and plan | Report of OS, Python, Docker, Containerlab, clang, bpftool, libbpf, kernel/BTF, chrony; missing prerequisites listed |
| M1 | Simulation core (no root, no eBPF) | Event model, simulator source, graph observer, Isolation Forest, dry-run enforcement, asyncio orchestrator, minimal API, unit tests and e2e simulation all pass |
| M2 | Host prep and Containerlab app | Host tuning applied; 5-service app up on isolated bridges; replicas/decoys reach 15–20 containers; Locust from Host 2 works |
| M3 | eBPF telemetry | kprobes on `tcp_v4_connect` / `inet_csk_accept` stream attributed events; smoke test shows benign traffic flows and event loss is measured |
| M4 | Live agents | Observer, analysis, enforcement run on live telemetry; conntrack source integrated; detector trained on short baseline |
| M5 | tc/eBPF enforcement | Quarantine via clsact/tc-bpf on veth; rollback verified; benign flows continue; dry-run default preserved |
| M6 | Attack harness | Scripted attack catalog A01–A20 and negatives N01–N03; ground-truth labels; clock sync check |
| M7 | Experiments | 30 min baseline; trials, sweeps at 100–2000 req/s; baselines implemented; run manifests |
| M8 | Analysis and LangGraph | ROC, CDFs, MTTC, CPU/memory, precision/recall, comparison tables; LangGraph adapter over the same agents; final report |

LangGraph is required as an adapter before M8. asyncio is the reference orchestrator. Do not fork agent logic between the two.

## 11. Safety and reliability constraints

- Default to simulation and dry-run. Require explicit configuration for real enforcement.
- Attacks only against the isolated lab. Never target external hosts.
- Never flush existing firewall rules or overwrite unrelated policies.
- Narrowly scoped, idempotent, reversible policies with audit logging.
- Secrets in environment variables; do not store payloads or credentials unnecessarily.
- An anomaly score is evidence, not proof. Missing telemetry is not evidence of attack.
- Document capabilities and root requirements (CAP_BPF, CAP_NET_ADMIN, CAP_PERFMON or root) and operational risks.
- Real attack mode (Kali/Metasploit on Host 2) is off by default and gated by an explicit flag plus an allow-listed lab target range.

## 12. Dashboard and API [DESIGN]

- FastAPI endpoints: health, events, graph, alerts, policies, agent status, experiment results.
- A dashboard is minimal and lowest priority; do it after the experiment harness.

## 13. Suggested repository layout

```
app/
  main.py
  api/
  agents/        graph_observer.py threat_analysis.py enforcement.py
  orchestration/ asyncio orchestrator, langgraph adapter
  telemetry/     base.py simulator.py replay.py conntrack.py ebpf/
  detection/     isolation_forest.py gnn/ (optional)
  policies/      tc_ebpf/ networkpolicy/
  graph/
  experiments/   harness, attacks/, baselines/
  metrics/
  storage/
containerlab/    topology files
services/        nginx/ auth/ api/ redis/ postgres/
tests/
scripts/
configs/
data/
docs/
README.md
requirements.txt
```

## 14. Open questions (do not block; choose a reversible default and document it)

1. Kernel version and BTF availability on the Mini PC.
2. Kali as a VM or native on the laptop.
3. Is Containerlab installed, and which container runtime.
4. Is IPv6 in scope.
5. Final trial count and false-positive target (defaults: 10 trials, 1%).
6. Is the 5 ms clock-offset bound achievable on the available network.
