"""Retention and cache expiry tests (PRD FR-13)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db.tables import CacheEntryRow, ModuleRunRow, ScanLedgerRow, ScanRow, ScopeProfileRow
from app.models.domain import ModuleStatus, ScanStatus
from app.services.retention import run_retention, sweep_expired_cache, sweep_old_scans

SessionFactory = async_sessionmaker[AsyncSession]


async def add_scan(session_factory: SessionFactory, *, age_days: int, status: ScanStatus) -> str:
    created = datetime.now(UTC) - timedelta(days=age_days)
    async with session_factory() as session:
        scope = ScopeProfileRow(name=f"scope-{age_days}-{status}", entries_json=["127.0.0.1"])
        session.add(scope)
        await session.flush()

        scan = ScanRow(
            scope_id=scope.id,
            target_input="127.0.0.1",
            target_normalized="127.0.0.1",
            target_type="ip",
            resolved_addrs_json=["127.0.0.1"],
            intensity_profile="polite",
            selected_modules_json=["noop"],
            status=str(status),
            attestation_text="attested",
            attestation_version="v1",
            attestation_at=created,
            created_at=created,
        )
        session.add(scan)
        await session.flush()

        session.add(ModuleRunRow(scan_id=scan.id, module="noop", status=str(ModuleStatus.DONE)))
        session.add(
            ScanLedgerRow(
                scan_id=scan.id,
                destination="127.0.0.1",
                port=22,
                module="scanguard",
                decision="allowed",
                reason="inside the active scope profile",
                outcome="connected",
            )
        )
        await session.commit()
        return scan.id


class TestScanRetention:
    async def test_expired_terminal_scans_are_deleted(
        self, session_factory: SessionFactory
    ) -> None:
        old = await add_scan(session_factory, age_days=120, status=ScanStatus.COMPLETED)
        recent = await add_scan(session_factory, age_days=3, status=ScanStatus.COMPLETED)

        assert await sweep_old_scans(session_factory, retention_days=90) == 1

        async with session_factory() as session:
            assert await session.get(ScanRow, old) is None
            assert await session.get(ScanRow, recent) is not None

    async def test_dependent_rows_go_with_the_scan(self, session_factory: SessionFactory) -> None:
        """Proves the SQLite foreign-key pragma is actually on."""
        scan_id = await add_scan(session_factory, age_days=120, status=ScanStatus.COMPLETED)
        await sweep_old_scans(session_factory, retention_days=90)

        async with session_factory() as session:
            runs = await session.execute(
                select(ModuleRunRow).where(ModuleRunRow.scan_id == scan_id)
            )
            ledger = await session.execute(
                select(ScanLedgerRow).where(ScanLedgerRow.scan_id == scan_id)
            )
            assert runs.scalars().all() == []
            assert ledger.scalars().all() == []

    async def test_an_old_running_scan_is_not_swept(self, session_factory: SessionFactory) -> None:
        """Retention must not delete work that is still in flight."""
        running = await add_scan(session_factory, age_days=200, status=ScanStatus.RUNNING)
        assert await sweep_old_scans(session_factory, retention_days=90) == 0

        async with session_factory() as session:
            assert await session.get(ScanRow, running) is not None


class TestCacheExpiry:
    async def test_only_expired_entries_are_removed(self, session_factory: SessionFactory) -> None:
        now = datetime.now(UTC)
        async with session_factory() as session:
            session.add(
                CacheEntryRow(
                    cache_key="nvd:expired",
                    source="nvd",
                    schema_version=1,
                    status="ok",
                    retrieved_at=now - timedelta(days=2),
                    expires_at=now - timedelta(hours=1),
                )
            )
            session.add(
                CacheEntryRow(
                    cache_key="nvd:fresh",
                    source="nvd",
                    schema_version=1,
                    status="ok",
                    retrieved_at=now,
                    expires_at=now + timedelta(hours=23),
                )
            )
            await session.commit()

        assert await sweep_expired_cache(session_factory) == 1

        async with session_factory() as session:
            remaining = await session.execute(select(CacheEntryRow.cache_key))
            assert list(remaining.scalars()) == ["nvd:fresh"]


class TestCombinedSweep:
    async def test_run_retention_reports_both_counts(self, session_factory: SessionFactory) -> None:
        await add_scan(session_factory, age_days=365, status=ScanStatus.FAILED)
        async with session_factory() as session:
            session.add(
                CacheEntryRow(
                    cache_key="kev:old",
                    source="kev",
                    schema_version=1,
                    status="ok",
                    retrieved_at=datetime.now(UTC) - timedelta(days=5),
                    expires_at=datetime.now(UTC) - timedelta(days=4),
                )
            )
            await session.commit()

        summary = await run_retention(session_factory, retention_days=90)
        assert summary.scans_deleted == 1
        assert summary.cache_entries_deleted == 1
