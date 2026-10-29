from __future__ import annotations

from fastapi import APIRouter, Request

router = APIRouter()


@router.get("/health")
def health(request: Request) -> dict:
    state = request.app.state.orchestrator
    return {"status": "ok", "mode": state.enforcer.mode, "events": len(state.events)}


@router.get("/events")
def events(request: Request) -> list[dict]:
    return [e.model_dump(mode="json") for e in request.app.state.orchestrator.events]


@router.get("/graph")
def graph(request: Request) -> dict:
    return request.app.state.orchestrator.observer.snapshot()


@router.get("/alerts")
def alerts(request: Request) -> list[dict]:
    return [a.model_dump(mode="json") for a in request.app.state.orchestrator.alerts]


@router.get("/policies")
def policies(request: Request) -> list[dict]:
    return [p.model_dump(mode="json") for p in request.app.state.orchestrator.enforcer.policies.values()]


@router.get("/agent-status")
def agent_status(request: Request) -> dict:
    state = request.app.state.orchestrator
    return {"graph_observer": "running", "threat_analysis": "running", "enforcement": state.enforcer.mode}

