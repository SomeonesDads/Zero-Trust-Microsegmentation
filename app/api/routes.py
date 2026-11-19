from __future__ import annotations

from typing import Literal
from fastapi import APIRouter, Request, Query, Response

router = APIRouter()


@router.get("/health")
async def health(request: Request, response: Response) -> dict:
    state = request.app.state.orchestrator
    status = "error" if state.status == "failed" else "ok"
    if state.metrics["analysis_queue_dropped"]:
        status = "degraded"
    source_health = getattr(state.source, "health", lambda: {})()
    if source_health.get("queue_dropped") or source_health.get("conntrack_overruns") or any(
            source_health.get("ebpf", {}).get(key, 0) for key in ("perf_lost", "submit_failed", "entry_map_failed")):
        status = "degraded"
    if state.status == "failed":
        status = "error"
        response.status_code = 503
    elif request.app.state.config.source == "live" and not source_health.get("ebpf_ready"):
        status = "not-ready"
        response.status_code = 503
    return {"status": status, "source": request.app.state.config.source,
            "mode": state.enforcer.mode, "events": len(state.events), "pipeline": state.status,
            "error": state.error}


@router.get("/events")
async def events(request: Request, offset: int = Query(0, ge=0), limit: int = Query(1000, ge=1, le=10000)) -> list[dict]:
    return [e.model_dump(mode="json") for e in list(request.app.state.orchestrator.events)[offset:offset + limit]]


@router.get("/graph")
async def graph(request: Request, view: Literal["services", "instances"] = "services") -> dict:
    return request.app.state.orchestrator.observer.snapshot(view)


@router.get("/alerts")
async def alerts(request: Request, limit: int = Query(1000, ge=1, le=10000)) -> list[dict]:
    return [a.model_dump(mode="json") for a in list(request.app.state.orchestrator.alerts)[-limit:]]


@router.get("/policies")
async def policies(request: Request) -> list[dict]:
    return [p.model_dump(mode="json") for p in request.app.state.orchestrator.enforcer.policies.values()]


@router.get("/agent-status")
async def agent_status(request: Request) -> dict:
    state = request.app.state.orchestrator
    return {"graph_observer": state.status, "threat_analysis": state.status,
            "enforcement": state.enforcer.mode, "error": state.error}


@router.get("/telemetry-health")
async def telemetry_health(request: Request) -> dict:
    state = request.app.state.orchestrator
    health = getattr(state.source, "health", lambda: {"status": state.status})()
    return {"source": request.app.state.config.source, **health, "pipeline": state.metrics,
            "detector_out_of_order": getattr(state.detector, "out_of_order", 0),
            "detector_window_overflows": getattr(state.detector, "window_overflows", 0)}


@router.get("/scores")
async def scores(request: Request, limit: int = Query(1000, ge=1, le=10000)) -> list[dict]:
    return list(request.app.state.orchestrator.scores)[-limit:]


@router.get("/policy-audit")
async def audit(request: Request) -> list[dict]:
    return list(request.app.state.orchestrator.enforcer.audit)

