"""Scan lifecycle routes (PRD 7.4).

``GET /api/scans/{id}`` is authoritative; the SSE stream is advisory and
reconnects with a last event id, replaying persisted events so a dropped
connection never loses progress (PRD 7.3).
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Any

from fastapi import APIRouter, Depends, Header, Query, Request, Response, status
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select, update

from app.api.deps import AppState, get_state
from app.db.tables import ModuleRunRow, ScanRow
from app.models.api import ModuleRunRead, ScanCreate, ScanDetail, ScanList, ScanSummary
from app.models.domain import ScanStatus
from app.models.errors import ScanAlreadyTerminalError, ScanNotFoundError
from app.services.scans import create_scan

router = APIRouter(prefix="/api/scans", tags=["scans"])

SSE_KEEPALIVE_SECONDS = 15.0


def _summary(row: ScanRow) -> ScanSummary:
    return ScanSummary.model_validate(row)


@router.post("", status_code=status.HTTP_202_ACCEPTED, response_model=ScanDetail)
async def queue_scan(payload: ScanCreate, state: AppState = Depends(get_state)) -> ScanDetail:
    scan_id = await create_scan(state.session_factory, state.registry, payload)
    return await get_scan(scan_id, state)


@router.get("", response_model=ScanList)
async def list_scans(
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    scan_status: str | None = Query(default=None, alias="status"),
    state: AppState = Depends(get_state),
) -> ScanList:
    async with state.session_factory() as session:
        query = select(ScanRow)
        count_query = select(func.count()).select_from(ScanRow)
        if scan_status is not None:
            query = query.where(ScanRow.status == scan_status)
            count_query = count_query.where(ScanRow.status == scan_status)

        total = (await session.execute(count_query)).scalar() or 0
        result = await session.execute(
            query.order_by(ScanRow.created_at.desc()).limit(limit).offset(offset)
        )
        return ScanList(
            items=[_summary(row) for row in result.scalars()],
            total=int(total),
            limit=limit,
            offset=offset,
        )


@router.get("/{scan_id}", response_model=ScanDetail)
async def get_scan(scan_id: str, state: AppState = Depends(get_state)) -> ScanDetail:
    async with state.session_factory() as session:
        scan = await session.get(ScanRow, scan_id)
        if scan is None:
            raise ScanNotFoundError(f"no scan with id {scan_id!r}")

        runs = await session.execute(
            select(ModuleRunRow)
            .where(ModuleRunRow.scan_id == scan_id)
            .order_by(ModuleRunRow.module)
        )
        return ScanDetail(
            **_summary(scan).model_dump(),
            resolved_addresses=list(scan.resolved_addrs_json),
            selected_modules=list(scan.selected_modules_json),
            attestation_text=scan.attestation_text,
            attestation_version=scan.attestation_version,
            attestation_at=scan.attestation_at,
            cancel_requested=scan.cancel_requested,
            module_runs=[ModuleRunRead.model_validate(run) for run in runs.scalars()],
        )


@router.post("/{scan_id}/cancel", response_model=ScanDetail)
async def cancel_scan(scan_id: str, state: AppState = Depends(get_state)) -> ScanDetail:
    async with state.session_factory() as session:
        scan = await session.get(ScanRow, scan_id)
        if scan is None:
            raise ScanNotFoundError(f"no scan with id {scan_id!r}")
        if ScanStatus(scan.status).is_terminal:
            raise ScanAlreadyTerminalError(
                f"this scan already finished with status {scan.status!r}"
            )

        await session.execute(
            update(ScanRow).where(ScanRow.id == scan_id).values(cancel_requested=True)
        )
        await session.commit()

    return await get_scan(scan_id, state)


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(scan_id: str, state: AppState = Depends(get_state)) -> Response:
    async with state.session_factory() as session:
        scan = await session.get(ScanRow, scan_id)
        if scan is None:
            raise ScanNotFoundError(f"no scan with id {scan_id!r}")
        await session.delete(scan)
        await session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/{scan_id}/events")
async def scan_events(
    scan_id: str,
    request: Request,
    last_event_id: int = Header(default=0, alias="Last-Event-ID"),
    state: AppState = Depends(get_state),
) -> StreamingResponse:
    async with state.session_factory() as session:
        if await session.get(ScanRow, scan_id) is None:
            raise ScanNotFoundError(f"no scan with id {scan_id!r}")

    async def stream() -> AsyncIterator[str]:
        queue = state.events.subscribe(scan_id)
        try:
            for missed in await state.events.events_since(scan_id, last_event_id):
                yield _format_event(
                    missed.sequence, missed.event_type, missed.module, missed.payload
                )

            while not await request.is_disconnected():
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=SSE_KEEPALIVE_SECONDS)
                except TimeoutError:
                    yield ": keepalive\n\n"
                    continue
                yield _format_event(event.sequence, event.event_type, event.module, event.payload)
        finally:
            state.events.unsubscribe(scan_id, queue)

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


def _format_event(
    sequence: int, event_type: str, module: str | None, payload: dict[str, Any]
) -> str:
    body = json.dumps({"module": module, **payload}, default=str)
    return f"id: {sequence}\nevent: {event_type}\ndata: {body}\n\n"
