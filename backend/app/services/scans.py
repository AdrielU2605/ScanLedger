"""Scan creation (PRD FR-01, UX-04).

A scan row exists only after scope, target, modules, intensity, and the
authorization attestation have all passed. The target is validated through
ScanGuard here - before any module is dispatched - so a refusal is recorded in
the ledger and returned to the user without a scan ever being queued.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db.ledger import DatabaseLedger
from app.db.tables import ModuleRunRow, ScanRow, ScopeProfileRow
from app.guard.scanguard import ScanGuard, ScopeProfile, ScopeValidationError, TargetRejected
from app.models.api import ScanCreate
from app.models.domain import ModuleStatus, ScanStatus, TargetType
from app.models.errors import (
    AttestationRequiredError,
    ScopeInvalidError,
    ScopeNotFoundError,
    ScopeRefusedError,
    TargetInvalidError,
)
from app.modules.registry import ModuleRegistry
from app.scan.governor import INTENSITY_PROFILES

ATTESTATION_VERSION = "v1"
ATTESTATION_TEXT = (
    "I own the systems in this scope profile, or I hold written authorization to "
    "actively scan them, and I understand ScanLedger sends real network probes."
)


async def load_scope_profile(session: AsyncSession, scope_id: str) -> ScopeProfile:
    row = await session.get(ScopeProfileRow, scope_id)
    if row is None:
        raise ScopeNotFoundError(f"no scope profile with id {scope_id!r}")
    try:
        return ScopeProfile.create(
            row.name,
            row.entries_json,
            allow_cgnat=row.allow_cgnat,
            allow_link_local=row.allow_link_local,
        )
    except ScopeValidationError as exc:
        raise ScopeInvalidError(str(exc)) from exc


async def create_scan(
    session_factory: async_sessionmaker[AsyncSession],
    registry: ModuleRegistry,
    request: ScanCreate,
) -> str:
    if not request.attestation_accepted:
        raise AttestationRequiredError(
            "a scan cannot be launched until you confirm you own or are authorized "
            "to scan every host in this scope profile"
        )

    if request.intensity_profile not in INTENSITY_PROFILES:
        raise TargetInvalidError(
            f"unknown intensity profile {request.intensity_profile!r}",
            details={"known_profiles": sorted(INTENSITY_PROFILES)},
        )

    for module_name in request.modules:
        registry.get(module_name)

    async with session_factory() as session:
        scope = await load_scope_profile(session, request.scope_id)

    guard = ScanGuard(scope, DatabaseLedger(session_factory))
    try:
        target = await guard.validate_target(request.target)
    except TargetRejected as exc:
        raise ScopeRefusedError(
            f"{exc.target} is outside the authorized scope for this scan: {exc.reason}",
            destination=exc.target,
            reason=exc.reason,
        ) from exc

    resolved = (
        [str(address) for address in target.addresses]
        if target.network is None
        else [str(target.network)]
    )
    normalized = str(target.network) if target.network is not None else resolved[0]

    async with session_factory() as session:
        scan = ScanRow(
            scope_id=request.scope_id,
            target_input=request.target,
            target_normalized=normalized,
            target_type=str(TargetType(target.kind)),
            resolved_addrs_json=resolved,
            intensity_profile=request.intensity_profile,
            selected_modules_json=list(request.modules),
            status=str(ScanStatus.QUEUED),
            note=request.note,
            attestation_text=ATTESTATION_TEXT,
            attestation_version=ATTESTATION_VERSION,
            attestation_at=datetime.now(UTC),
        )
        session.add(scan)
        await session.flush()

        for module_name in request.modules:
            session.add(
                ModuleRunRow(
                    scan_id=scan.id,
                    module=module_name,
                    status=str(ModuleStatus.QUEUED),
                )
            )
        await session.commit()
        return scan.id
