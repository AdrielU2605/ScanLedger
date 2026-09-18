"""Findings, ledger, and exports for a stored scan (PRD UX-08, FR-12)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query
from fastapi.responses import PlainTextResponse
from sqlalchemy import func, select

from app.api.deps import AppState, get_state
from app.db.tables import FindingRow, ModuleRunRow, ScanLedgerRow, ScanRow, ScopeProfileRow
from app.models.api import FindingList, FindingRead, LedgerEntryRead
from app.models.errors import ScanNotFoundError, TargetInvalidError
from app.services.reports import build_json_export, build_markdown_export

router = APIRouter(prefix="/api/scans", tags=["findings"])


def _to_read(row: FindingRow) -> FindingRead:
    return FindingRead(
        id=row.id,
        host=row.host,
        port=row.port,
        category=row.category,
        kind=row.kind,
        title=row.title,
        summary=row.summary,
        normalized_value=row.normalized_value,
        raw_evidence=row.raw_evidence,
        module=row.module,
        observed_at=row.observed_at,
        confidence=row.confidence,
        sources=list(row.sources_json),
        fingerprint=row.fingerprint,
    )


@router.get("/{scan_id}/findings", response_model=FindingList)
async def list_findings(
    scan_id: str,
    category: str | None = None,
    module: str | None = None,
    host: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    state: AppState = Depends(get_state),
) -> FindingList:
    async with state.session_factory() as session:
        if await session.get(ScanRow, scan_id) is None:
            raise ScanNotFoundError(f"no scan with id {scan_id!r}")

        query = select(FindingRow).where(FindingRow.scan_id == scan_id)
        count_query = (
            select(func.count()).select_from(FindingRow).where(FindingRow.scan_id == scan_id)
        )
        for column, value in (
            (FindingRow.category, category),
            (FindingRow.module, module),
            (FindingRow.host, host),
        ):
            if value is not None:
                query = query.where(column == value)
                count_query = count_query.where(column == value)

        total = (await session.execute(count_query)).scalar() or 0
        result = await session.execute(
            query.order_by(FindingRow.host, FindingRow.port, FindingRow.kind)
            .limit(limit)
            .offset(offset)
        )
        return FindingList(
            items=[_to_read(row) for row in result.scalars()],
            total=int(total),
            limit=limit,
            offset=offset,
        )


@router.get("/{scan_id}/ledger", response_model=list[LedgerEntryRead])
async def get_ledger(scan_id: str, state: AppState = Depends(get_state)) -> list[LedgerEntryRead]:
    """Every destination this scan probed, and every one it refused."""
    async with state.session_factory() as session:
        if await session.get(ScanRow, scan_id) is None:
            raise ScanNotFoundError(f"no scan with id {scan_id!r}")

        result = await session.execute(
            select(ScanLedgerRow)
            .where(ScanLedgerRow.scan_id == scan_id)
            .order_by(ScanLedgerRow.created_at, ScanLedgerRow.id)
        )
        return [
            LedgerEntryRead(
                destination=row.destination,
                port=row.port,
                module=row.module,
                decision=row.decision,
                reason=row.reason,
                outcome=row.outcome,
                recorded_at=row.created_at,
            )
            for row in result.scalars()
        ]


async def _load_export_inputs(state: AppState, scan_id: str) -> tuple[Any, ...]:
    async with state.session_factory() as session:
        scan = await session.get(ScanRow, scan_id)
        if scan is None:
            raise ScanNotFoundError(f"no scan with id {scan_id!r}")
        scope = await session.get(ScopeProfileRow, scan.scope_id)
        if scope is None:
            raise ScanNotFoundError("the scope profile for this scan no longer exists")

        runs = await session.execute(
            select(ModuleRunRow)
            .where(ModuleRunRow.scan_id == scan_id)
            .order_by(ModuleRunRow.module)
        )
        findings = await session.execute(
            select(FindingRow)
            .where(FindingRow.scan_id == scan_id)
            .order_by(FindingRow.category, FindingRow.host, FindingRow.port)
        )
        ledger = await session.execute(
            select(ScanLedgerRow)
            .where(ScanLedgerRow.scan_id == scan_id)
            .order_by(ScanLedgerRow.created_at, ScanLedgerRow.id)
        )
        return (
            scan,
            scope,
            list(runs.scalars()),
            list(findings.scalars()),
            list(ledger.scalars()),
        )


@router.get("/{scan_id}/export")
async def export_scan(
    scan_id: str,
    export_format: str = Query(default="json", alias="format"),
    mode: str = Query(default="summary"),
    state: AppState = Depends(get_state),
) -> Any:
    if export_format not in ("json", "md"):
        raise TargetInvalidError(f"unknown export format {export_format!r}; expected json or md")
    if mode not in ("summary", "full"):
        raise TargetInvalidError(f"unknown export mode {mode!r}; expected summary or full")

    scan, scope, runs, findings, ledger = await _load_export_inputs(state, scan_id)

    if export_format == "json":
        return build_json_export(scan, scope, runs, findings, ledger)

    return PlainTextResponse(
        build_markdown_export(scan, scope, runs, findings, ledger, mode=mode),
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="scanledger-{scan_id}.md"'},
    )
