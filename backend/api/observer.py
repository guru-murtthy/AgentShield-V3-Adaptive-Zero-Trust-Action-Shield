"""
backend/api/observer.py
AgentShield V3 — Observer Snapshot Endpoint.

Author: Gururaj — Lead Red Team & Validation Engineer
Last Updated: 2026-10-14

PURPOSE:
    Provides a READ-ONLY snapshot of the execution ledger and audit chain
    for Laptop 2 (the independent observer / evaluator).

    CRITICAL:
    - This endpoint is read-only — no writes allowed.
    - Observations here are the GROUND TRUTH that the evaluator uses.
    - The observer never trusts HTTP status codes; it queries THIS endpoint.

    The snapshot includes:
      - All execution records (the ledger)
      - All audit events (the audit chain)

    Laptop 2 queries this directly and independently verifies results
    without trusting gateway or executor API response bodies.

COORDINATION NOTE:
    Gururaj (Laptop 2 / Observer): reads from /observer/snapshot
    Alok: wired into main.py — no auth required for read-only snapshot
           (adjust to add read-only auth if needed for security)
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.dependencies import db_session
from backend.storage.models.audit_event import AuditEvent
from backend.storage.models.execution import Execution

router = APIRouter(prefix="/observer", tags=["Observer"])


@router.get(
    "/snapshot",
    summary="Read-only ground-truth snapshot of ledger + audit chain",
)
async def observer_snapshot(
    limit: int = Query(500, ge=1, le=5000, description="Max records to return"),
    config: str | None = Query(None, description="Filter by config (A/B/C)"),
    session: AsyncSession = Depends(db_session),
) -> dict[str, Any]:
    """
    Return a complete, read-only snapshot of:
      - execution records (the ledger — ground truth)
      - audit events (the audit chain)

    The independent observer on Laptop 2 calls this endpoint directly.
    Results are NEVER trusted based on HTTP status codes — only on this data.

    Observer uses this to compute:
      - execution_count:  actual number of ledger entries
      - blocked_count:    audit events showing DENIED/BLOCKED/REJECTED
      - audit chain integrity: hash linkage verification
    """
    # -- Executions (the authoritative ledger) --
    exec_query = select(Execution).order_by(Execution.executed_at.asc()).limit(limit)
    exec_result = await session.execute(exec_query)
    executions = exec_result.scalars().all()

    execution_rows = []
    for e in executions:
        execution_rows.append({
            "execution_id": str(e.id),
            "action_type": e.tool_name,           # tool_name is the action executed
            "action_digest": e.action_digest,
            "principal_id": str(e.agent_id),
            "tenant_id": str(e.tenant_id),
            "outcome": e.outcome,
            "config": _infer_config(e),            # see helper below
            "executed_at": e.executed_at.isoformat() if e.executed_at else "",
            "outcome_data": e.outcome_data or {},
        })

    # -- Audit events (the audit chain) --
    audit_query = (
        select(AuditEvent)
        .order_by(AuditEvent.sequence_number.asc())
        .limit(limit * 3)             # audit has more records than executions
    )
    audit_result = await session.execute(audit_query)
    audit_events = audit_result.scalars().all()

    audit_rows = []
    for ev in audit_events:
        audit_rows.append({
            "id": str(ev.id),
            "event_type": ev.event_type,
            "event_data": ev.event_data or {},
            "actor_id": ev.actor_id or "",
            "timestamp": ev.timestamp.isoformat() if ev.timestamp else "",
            "prev_chain_hash": ev.prev_chain_hash,
            "chain_hash": ev.chain_hash,
            "sequence_number": ev.sequence_number,
        })

    blocked_count = sum(
        1 for ev in audit_events
        if any(
            kw in (ev.event_type or "").upper()
            for kw in ("DENIED", "BLOCKED", "REJECTED", "MISMATCH", "CONSUMED", "REVOKED")
        )
    )

    return {
        "snapshot_version": "v3",
        "execution_count": len(execution_rows),
        "executions": execution_rows,
        "audit_count": len(audit_rows),
        "audit_records": audit_rows,
        "blocked_count": blocked_count,
        "metadata": {
            "limit": limit,
            "config_filter": config,
            "note": (
                "This is the ground-truth ledger. "
                "The independent observer queries this directly — "
                "never trusting HTTP status codes."
            ),
        },
    }


@router.get(
    "/health",
    summary="Observer endpoint health check",
)
async def observer_health(
    session: AsyncSession = Depends(db_session),
) -> dict[str, Any]:
    """Simple health check confirming the observer endpoint is reachable."""
    try:
        await session.execute(text("SELECT 1"))
        db_ok = True
    except Exception as exc:
        db_ok = False

    return {
        "status": "ok" if db_ok else "degraded",
        "endpoint": "/observer/snapshot",
        "purpose": "Read-only ground-truth ledger for independent evaluator (Laptop 2)",
    }


def _infer_config(execution: Execution) -> str:
    """
    Infer which enforcement config (A/B/C) was used for this execution.

    In the current implementation, config is stored in outcome_data if set.
    Falls back to "C" (the default/full config).

    Coordination: Alok to add explicit config tagging to executions when
    baseline A/B routing is implemented.
    """
    if execution.outcome_data and isinstance(execution.outcome_data, dict):
        return execution.outcome_data.get("config", "C")
    return "C"
