"""Retention and cache expiry (PRD FR-13).

Runs at startup and after every scan reaches a terminal state, never as a
manual step. Scan deletion relies on the ON DELETE CASCADE foreign keys, which
is why the session layer turns SQLite's per-connection foreign key enforcement
on - without it the dependent rows would silently survive.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from sqlalchemy import CursorResult, delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db.tables import CacheEntryRow, ScanRow
from app.models.domain import ScanStatus

DEFAULT_RETENTION_DAYS = 90


@dataclass(frozen=True)
class RetentionSummary:
    scans_deleted: int
    cache_entries_deleted: int


async def sweep_expired_cache(
    session_factory: async_sessionmaker[AsyncSession], *, now: datetime | None = None
) -> int:
    moment = now or datetime.now(UTC)
    async with session_factory() as session:
        # A DML statement returns a CursorResult at runtime; the declared
        # return type of Session.execute is the broader Result.
        result = cast(
            CursorResult[Any],
            await session.execute(delete(CacheEntryRow).where(CacheEntryRow.expires_at <= moment)),
        )
        await session.commit()
        return int(result.rowcount or 0)


async def sweep_old_scans(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    retention_days: int = DEFAULT_RETENTION_DAYS,
    now: datetime | None = None,
) -> int:
    moment = now or datetime.now(UTC)
    cutoff = moment - timedelta(days=retention_days)

    async with session_factory() as session:
        # Only terminal scans are swept: an in-flight scan older than the
        # retention window is still running work someone is watching.
        result = await session.execute(
            select(ScanRow.id).where(
                ScanRow.created_at < cutoff,
                ScanRow.status.in_(
                    [
                        str(ScanStatus.COMPLETED),
                        str(ScanStatus.COMPLETED_WITH_WARNINGS),
                        str(ScanStatus.FAILED),
                        str(ScanStatus.CANCELED),
                    ]
                ),
            )
        )
        expired_ids = list(result.scalars())
        if not expired_ids:
            return 0

        await session.execute(delete(ScanRow).where(ScanRow.id.in_(expired_ids)))
        await session.commit()
        return len(expired_ids)


async def run_retention(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    retention_days: int = DEFAULT_RETENTION_DAYS,
    now: datetime | None = None,
) -> RetentionSummary:
    scans = await sweep_old_scans(session_factory, retention_days=retention_days, now=now)
    cache = await sweep_expired_cache(session_factory, now=now)
    return RetentionSummary(scans_deleted=scans, cache_entries_deleted=cache)
