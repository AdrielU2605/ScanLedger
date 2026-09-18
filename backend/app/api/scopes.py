"""Scope profile CRUD (PRD UX-02, 7.4).

Validation happens through ``ScopeProfile.create``, the same code path the
guard uses, so a profile that could not be enforced cannot be saved.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy import select

from app.api.deps import AppState, get_state
from app.db.tables import ScanRow, ScopeProfileRow
from app.guard.scanguard import ScopeProfile, ScopeValidationError
from app.models.api import ScopeCreate, ScopeRead
from app.models.errors import ScopeInUseError, ScopeInvalidError, ScopeNotFoundError

router = APIRouter(prefix="/api/scopes", tags=["scopes"])


def _to_read(row: ScopeProfileRow) -> ScopeRead:
    return ScopeRead(
        id=row.id,
        name=row.name,
        entries=list(row.entries_json),
        allow_cgnat=row.allow_cgnat,
        allow_link_local=row.allow_link_local,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _validate(payload: ScopeCreate) -> None:
    try:
        ScopeProfile.create(
            payload.name,
            payload.entries,
            allow_cgnat=payload.allow_cgnat,
            allow_link_local=payload.allow_link_local,
        )
    except ScopeValidationError as exc:
        raise ScopeInvalidError(str(exc)) from exc


@router.get("", response_model=list[ScopeRead])
async def list_scopes(state: AppState = Depends(get_state)) -> list[ScopeRead]:
    async with state.session_factory() as session:
        result = await session.execute(select(ScopeProfileRow).order_by(ScopeProfileRow.name))
        return [_to_read(row) for row in result.scalars()]


@router.post("", response_model=ScopeRead, status_code=status.HTTP_201_CREATED)
async def create_scope(payload: ScopeCreate, state: AppState = Depends(get_state)) -> ScopeRead:
    _validate(payload)
    async with state.session_factory() as session:
        existing = await session.execute(
            select(ScopeProfileRow).where(ScopeProfileRow.name == payload.name)
        )
        if existing.scalar() is not None:
            raise ScopeInvalidError(f"a scope profile named {payload.name!r} already exists")

        row = ScopeProfileRow(
            name=payload.name,
            entries_json=list(payload.entries),
            allow_cgnat=payload.allow_cgnat,
            allow_link_local=payload.allow_link_local,
        )
        session.add(row)
        await session.commit()
        return _to_read(row)


@router.put("/{scope_id}", response_model=ScopeRead)
async def update_scope(
    scope_id: str, payload: ScopeCreate, state: AppState = Depends(get_state)
) -> ScopeRead:
    _validate(payload)
    async with state.session_factory() as session:
        row = await session.get(ScopeProfileRow, scope_id)
        if row is None:
            raise ScopeNotFoundError(f"no scope profile with id {scope_id!r}")

        row.name = payload.name
        row.entries_json = list(payload.entries)
        row.allow_cgnat = payload.allow_cgnat
        row.allow_link_local = payload.allow_link_local
        await session.commit()
        return _to_read(row)


@router.delete("/{scope_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scope(scope_id: str, state: AppState = Depends(get_state)) -> Response:
    async with state.session_factory() as session:
        row = await session.get(ScopeProfileRow, scope_id)
        if row is None:
            raise ScopeNotFoundError(f"no scope profile with id {scope_id!r}")

        in_use = await session.execute(select(ScanRow.id).where(ScanRow.scope_id == scope_id))
        if in_use.scalar() is not None:
            raise ScopeInUseError(
                "this scope profile is referenced by stored scans; delete those scans first "
                "so their audit record never loses the scope it was authorized against"
            )

        await session.delete(row)
        await session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
