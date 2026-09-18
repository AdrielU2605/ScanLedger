"""Scan runner tests (PRD FR-01, 7.3, 9)."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db.tables import ModuleRunRow, ScanRow, ScopeProfileRow
from app.models.api import ScanCreate
from app.models.domain import ModuleStatus, ScanStatus
from app.models.errors import WorkerAlreadyRunningError
from app.modules.registry import ModuleRegistry
from app.scan.events import EventPublisher
from app.scan.runner import ScanRunner
from app.services.scans import create_scan
from tests.conftest_db import NoOpModule

SessionFactory = async_sessionmaker[AsyncSession]


@pytest.fixture
def events(session_factory: SessionFactory) -> EventPublisher:
    return EventPublisher(session_factory)


@pytest.fixture
def runner(
    session_factory: SessionFactory, registry: ModuleRegistry, events: EventPublisher
) -> ScanRunner:
    return ScanRunner(session_factory, registry, events)


async def make_scope(session_factory: SessionFactory) -> str:
    async with session_factory() as session:
        row = ScopeProfileRow(name="self-test", entries_json=["127.0.0.0/24"])
        session.add(row)
        await session.commit()
        return row.id


async def queue_scan(
    session_factory: SessionFactory, registry: ModuleRegistry, *, modules: list[str] | None = None
) -> str:
    scope_id = await make_scope(session_factory)
    return await create_scan(
        session_factory,
        registry,
        ScanCreate(
            scope_id=scope_id,
            target="127.0.0.1",
            modules=modules or ["noop"],
            attestation_accepted=True,
        ),
    )


class TestWorkerLock:
    async def test_second_worker_refuses_to_start(
        self, session_factory: SessionFactory, registry: ModuleRegistry, events: EventPublisher
    ) -> None:
        first = ScanRunner(session_factory, registry, events)
        await first.acquire_worker_lock()

        second = ScanRunner(session_factory, registry, events)
        with pytest.raises(WorkerAlreadyRunningError, match="already running"):
            await second.acquire_worker_lock()

    async def test_a_stale_lock_can_be_taken_over(
        self, session_factory: SessionFactory, registry: ModuleRegistry, events: EventPublisher
    ) -> None:
        """A crashed worker must not lock the database forever."""
        first = ScanRunner(session_factory, registry, events)
        await first.acquire_worker_lock(now=datetime.now(UTC) - timedelta(minutes=5))

        second = ScanRunner(session_factory, registry, events)
        await second.acquire_worker_lock()

    async def test_releasing_frees_the_lock(
        self, session_factory: SessionFactory, registry: ModuleRegistry, events: EventPublisher
    ) -> None:
        first = ScanRunner(session_factory, registry, events)
        await first.acquire_worker_lock()
        await first.release_worker_lock()

        second = ScanRunner(session_factory, registry, events)
        await second.acquire_worker_lock()


class TestClaim:
    async def test_claim_returns_the_queued_scan_once(
        self, session_factory: SessionFactory, registry: ModuleRegistry, runner: ScanRunner
    ) -> None:
        scan_id = await queue_scan(session_factory, registry)

        assert await runner.claim_next_scan() == scan_id
        # Already running - a second claim finds nothing queued.
        assert await runner.claim_next_scan() is None

    async def test_two_runners_cannot_claim_the_same_scan(
        self,
        session_factory: SessionFactory,
        registry: ModuleRegistry,
        events: EventPublisher,
        runner: ScanRunner,
    ) -> None:
        scan_id = await queue_scan(session_factory, registry)
        rival = ScanRunner(session_factory, registry, events)

        claims = [await runner.claim_next_scan(), await rival.claim_next_scan()]
        assert claims.count(scan_id) == 1
        assert claims.count(None) == 1

    async def test_claim_marks_the_scan_running_and_records_the_owner(
        self, session_factory: SessionFactory, registry: ModuleRegistry, runner: ScanRunner
    ) -> None:
        scan_id = await queue_scan(session_factory, registry)
        await runner.claim_next_scan()

        async with session_factory() as session:
            scan = await session.get(ScanRow, scan_id)
            assert scan is not None
            assert scan.status == str(ScanStatus.RUNNING)
            assert scan.claimed_by == runner.owner_id
            assert scan.started_at is not None


class TestExecution:
    async def test_a_scan_with_a_succeeding_module_completes(
        self,
        session_factory: SessionFactory,
        registry: ModuleRegistry,
        runner: ScanRunner,
        noop_module: NoOpModule,
    ) -> None:
        scan_id = await queue_scan(session_factory, registry)
        await runner.claim_next_scan()

        assert await runner.execute_scan(scan_id) is ScanStatus.COMPLETED
        assert noop_module.calls == 1

        async with session_factory() as session:
            scan = await session.get(ScanRow, scan_id)
            assert scan is not None
            assert scan.status == str(ScanStatus.COMPLETED)
            assert scan.finished_at is not None

            run = await session.execute(select(ModuleRunRow).where(ModuleRunRow.scan_id == scan_id))
            module_run = run.scalar_one()
            assert module_run.status == str(ModuleStatus.DONE)
            assert module_run.attempt_count == 1

    async def test_a_failing_module_yields_completed_with_warnings(
        self,
        session_factory: SessionFactory,
        events: EventPublisher,
    ) -> None:
        from app.models.errors import ModuleError
        from app.modules.base import ModuleContext, ModuleResult

        class FailingModule(NoOpModule):
            metadata = NoOpModule.metadata

            async def run(self, context: ModuleContext) -> ModuleResult:
                raise ModuleError("the probe could not complete")

        class SecondModule(NoOpModule):
            metadata = replace(NoOpModule.metadata, name="noop2")

        mixed = ModuleRegistry()
        mixed.register(FailingModule())
        mixed.register(SecondModule())
        runner = ScanRunner(session_factory, mixed, events)

        scan_id = await queue_scan(session_factory, mixed, modules=["noop", "noop2"])
        await runner.claim_next_scan()

        assert await runner.execute_scan(scan_id) is ScanStatus.COMPLETED_WITH_WARNINGS

        async with session_factory() as session:
            runs = await session.execute(
                select(ModuleRunRow).where(ModuleRunRow.scan_id == scan_id)
            )
            by_name = {run.module: run for run in runs.scalars()}
            assert by_name["noop"].status == str(ModuleStatus.FAILED)
            assert by_name["noop"].safe_error_message is not None
            assert by_name["noop2"].status == str(ModuleStatus.DONE)

    async def test_a_scan_whose_every_module_fails_is_failed(
        self, session_factory: SessionFactory, events: EventPublisher
    ) -> None:
        from app.models.errors import ModuleError
        from app.modules.base import ModuleContext, ModuleResult

        class FailingModule(NoOpModule):
            async def run(self, context: ModuleContext) -> ModuleResult:
                raise ModuleError("nothing worked")

        only_failing = ModuleRegistry()
        only_failing.register(FailingModule())
        runner = ScanRunner(session_factory, only_failing, events)

        scan_id = await queue_scan(session_factory, only_failing)
        await runner.claim_next_scan()

        assert await runner.execute_scan(scan_id) is ScanStatus.FAILED

    async def test_cancel_halts_before_the_next_module(
        self, session_factory: SessionFactory, registry: ModuleRegistry, runner: ScanRunner
    ) -> None:
        from sqlalchemy import update

        scan_id = await queue_scan(session_factory, registry)
        await runner.claim_next_scan()
        async with session_factory() as session:
            await session.execute(
                update(ScanRow).where(ScanRow.id == scan_id).values(cancel_requested=True)
            )
            await session.commit()

        assert await runner.execute_scan(scan_id) is ScanStatus.CANCELED

        async with session_factory() as session:
            runs = await session.execute(
                select(ModuleRunRow).where(ModuleRunRow.scan_id == scan_id)
            )
            assert runs.scalar_one().status == str(ModuleStatus.SKIPPED)


class TestRestartRecovery:
    async def test_running_module_runs_become_interrupted_not_done(
        self, session_factory: SessionFactory, registry: ModuleRegistry, runner: ScanRunner
    ) -> None:
        """A crash must never be readable as a completed module (PRD 3.2)."""
        from sqlalchemy import update

        scan_id = await queue_scan(session_factory, registry)
        await runner.claim_next_scan()
        async with session_factory() as session:
            await session.execute(
                update(ModuleRunRow)
                .where(ModuleRunRow.scan_id == scan_id)
                .values(status=str(ModuleStatus.RUNNING))
            )
            await session.commit()

        recovered = await runner.recover_interrupted()
        assert recovered == 1

        async with session_factory() as session:
            run = await session.execute(select(ModuleRunRow).where(ModuleRunRow.scan_id == scan_id))
            assert run.scalar_one().status == str(ModuleStatus.INTERRUPTED)

            scan = await session.get(ScanRow, scan_id)
            assert scan is not None
            assert scan.status == str(ScanStatus.QUEUED)
            assert scan.claimed_by is None

    async def test_a_recovered_scan_can_be_claimed_again(
        self, session_factory: SessionFactory, registry: ModuleRegistry, runner: ScanRunner
    ) -> None:
        scan_id = await queue_scan(session_factory, registry)
        await runner.claim_next_scan()
        await runner.recover_interrupted()

        assert await runner.claim_next_scan() == scan_id
