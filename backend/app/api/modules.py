"""Module catalog (PRD UX-06, 7.4)."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.deps import AppState, get_state
from app.models.api import ModuleRead
from app.models.domain import TargetType

router = APIRouter(prefix="/api/modules", tags=["modules"])


@router.get("", response_model=list[ModuleRead])
async def list_modules(
    target_type: TargetType | None = None, state: AppState = Depends(get_state)
) -> list[ModuleRead]:
    return [
        ModuleRead(
            name=entry.name,
            display_name=entry.display_name,
            description=entry.description,
            category=entry.category,
            supported_targets=list(entry.supported_targets),
            readiness=entry.readiness,
            release=entry.release,
            optional_dependency=entry.optional_dependency,
        )
        for entry in state.registry.catalog(target_type)
    ]
