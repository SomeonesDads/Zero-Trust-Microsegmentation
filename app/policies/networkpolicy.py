from __future__ import annotations

from app.models import Policy


def generate_networkpolicy(policy: Policy) -> dict:
    """Generate a static comparison artifact; this does not apply to a cluster."""
    return {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": f"deny-{policy.source}-to-{policy.destination}"},
            "spec": {"podSelector": {"matchLabels": {"service": policy.destination}},
                     "policyTypes": ["Ingress"], "ingress": []}, "artifact_only": True}

