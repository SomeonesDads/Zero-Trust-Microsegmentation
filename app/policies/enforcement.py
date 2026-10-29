from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256

from app.models import Finding, NetworkEvent, Policy


class EnforcementBackend:
    """In-memory tc/eBPF boundary for simulation, never a kernel attachment."""
    name = "tc-ebpf-simulated"

    def __init__(self) -> None:
        self.active: dict[str, Policy] = {}

    def apply(self, policy: Policy) -> Policy:
        applied = policy.model_copy(update={"state": "applied"})
        self.active[policy.policy_id] = applied
        return applied

    def verify(self, policy: Policy) -> bool:
        return policy.policy_id in self.active

    def rollback(self, policy: Policy) -> Policy:
        self.active.pop(policy.policy_id, None)
        return policy.model_copy(update={"state": "rolled_back"})

    def permits(self, event: NetworkEvent) -> bool:
        """Evaluate simulated rules for acceptance tests; no traffic is sent."""
        return not any(
            policy.source in (event.src_service, event.src_container)
            and policy.destination in (event.dst_service, event.dst_container)
            and (policy.port is None or policy.port == event.dst_port)
            and policy.protocol == event.protocol
            for policy in self.active.values())


class DryRunEnforcer:
    def __init__(self, mode: str = "dry-run", backend: EnforcementBackend | None = None) -> None:
        if mode not in {"dry-run", "manual-approve", "auto-approve"}:
            raise ValueError("unsupported enforcement mode")
        self.mode, self.backend = mode, backend or EnforcementBackend()
        self.policies: dict[str, Policy] = {}
        self.audit: list[dict] = []

    def propose(self, finding: Finding) -> Policy:
        source = finding.src_container or finding.source
        destination = finding.dst_container or finding.destination
        if not source or not destination or source == destination:
            raise ValueError("a policy requires distinct, identified source and destination")
        key = f"{source}|{destination}|{finding.dst_port}|{finding.protocol}|scoped"
        policy_id = sha256(key.encode()).hexdigest()[:16]
        if policy_id in self.policies:
            return self.policies[policy_id]
        policy = Policy(policy_id=policy_id, source=source, destination=destination,
                        port=finding.dst_port, protocol=finding.protocol,
                        mode=self.mode, reason=finding.explanation)
        self.policies[policy_id] = policy
        self._audit(policy, "proposed")
        if self.mode == "auto-approve":
            return self.approve(policy_id)
        return policy

    def approve(self, policy_id: str) -> Policy:
        if self.mode == "dry-run":
            raise ValueError("dry-run policies cannot be applied")
        policy = self.policies[policy_id]
        if policy.state == "verified":
            return policy
        if policy.state != "proposed":
            raise ValueError("only proposed policies can be approved")
        for state in ("validated", "approved"):
            policy = policy.model_copy(update={"state": state})
            self.policies[policy_id] = policy
            self._audit(policy, state)
        policy = self.backend.apply(policy)
        self.policies[policy_id] = policy
        self._audit(policy, "applied")
        if not self.backend.verify(policy):
            self.rollback(policy_id)
            raise RuntimeError("simulated enforcement verification failed")
        policy = policy.model_copy(update={"state": "verified"})
        self.policies[policy_id] = policy
        self._audit(policy, "verified")
        return policy

    def rollback(self, policy_id: str) -> Policy:
        policy = self.policies[policy_id]
        if policy.state == "rolled_back":
            return policy
        policy = self.backend.rollback(policy)
        self.policies[policy_id] = policy
        self._audit(policy, "rolled_back")
        return policy

    def _audit(self, policy: Policy, transition: str) -> None:
        self.audit.append({"timestamp": datetime.now(timezone.utc).isoformat(), "policy_id": policy.policy_id,
                           "transition": transition, "backend": self.backend.name, "mode": self.mode})
