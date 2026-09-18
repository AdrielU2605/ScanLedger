"""The audit ledger across scans (PRD FR-11, 10.4).

A target refused at creation time never becomes a scan, so its denial would be
invisible if the ledger could only be read per-scan - yet that refusal is
exactly the evidence that proves the scope lock works. This router exposes the
whole ledger, and the refusals in particular, whether or not a scan exists.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select

from app.api.deps import AppState, get_state
from app.db.tables import ScanLedgerRow
from app.models.api import LedgerEntryRead, LedgerList

router = APIRouter(prefix="/api/ledger", tags=["ledger"])


def _to_read(row: ScanLedgerRow) -> LedgerEntryRead:
    return LedgerEntryRead(
        destination=row.destination,
        port=row.port,
        module=row.module,
        decision=row.decision,
        reason=row.reason,
        outcome=row.outcome,
        recorded_at=row.created_at,
        scan_id=row.scan_id,
        scope_id=row.scope_id,
    )


@router.get("", response_model=LedgerList)
async def list_ledger(
    decision: str | None = Query(default=None, pattern="^(allowed|denied)$"),
    scope_id: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    state: AppState = Depends(get_state),
) -> LedgerList:
    async with state.session_factory() as session:
        query = select(ScanLedgerRow)
        count_query = select(func.count()).select_from(ScanLedgerRow)
        for column, value in (
            (ScanLedgerRow.decision, decision),
            (ScanLedgerRow.scope_id, scope_id),
        ):
            if value is not None:
                query = query.where(column == value)
                count_query = count_query.where(column == value)

        total = (await session.execute(count_query)).scalar() or 0
        result = await session.execute(
            query.order_by(ScanLedgerRow.created_at.desc(), ScanLedgerRow.id)
            .limit(limit)
            .offset(offset)
        )
        return LedgerList(
            items=[_to_read(row) for row in result.scalars()],
            total=int(total),
            limit=limit,
            offset=offset,
        )


@router.get("/refusals", response_model=LedgerList)
async def list_refusals(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    state: AppState = Depends(get_state),
) -> LedgerList:
    """Every destination ScanLedger refused, including pre-scan refusals."""
    return await list_ledger(
        decision="denied", scope_id=None, limit=limit, offset=offset, state=state
    )
