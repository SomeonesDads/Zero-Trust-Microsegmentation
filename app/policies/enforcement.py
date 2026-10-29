from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256

from app.models import Finding, Policy


class EnforcementBackend:
    name = "tc-ebpf"

    def apply(self, policy: Policy) -> Policy:
        return policy.model_copy(update={"state": "applied"})

    def rollback(self, policy: Policy) -> Policy:
        return policy.model_copy(update={"state": "rolled_back"})


class DryRunEnforcer:
    def __init__(self, mode: str = "dry-run", backend: EnforcementBackend | None = None) -> None:
        if mode not in {"dry-run", "manual-approve", "auto-approve"}:
            raise ValueError("unsupported enforcement mode")
        self.mode, self.backend = mode, backend or EnforcementBackend()
        self.policies: dict[str, Policy] = {}
        self.audit: list[dict] = []

    def propose(self, finding: Finding) -> Policy:
        key = f"{finding.source}|{finding.destination}|scoped"
        policy_id = sha256(key.encode()).hexdigest()[:16]
        if policy_id in self.policies:
            return self.policies[policy_id]
        policy = Policy(policy_id=policy_id, source=finding.source, destination=finding.destination,
                        mode=self.mode, reason=finding.explanation)
        self.policies[policy_id] = policy
        self._audit(policy, "proposed")
        if self.mode == "auto-approve":
            policy = self.backend.apply(policy)
            self.policies[policy_id] = policy
            self._audit(policy, "applied")
        return policy

    def rollback(self, policy_id: str) -> Policy:
        if policy_id not in self.policies:
            raise KeyError(policy_id)
        policy = self.backend.rollback(self.policies[policy_id])
        self.policies[policy_id] = policy
        self._audit(policy, "rolled_back")
        return policy

    def _audit(self, policy: Policy, transition: str) -> None:
        self.audit.append({"timestamp": datetime.now(timezone.utc).isoformat(), "policy_id": policy.policy_id,
                           "transition": transition, "backend": self.backend.name, "mode": self.mode})

