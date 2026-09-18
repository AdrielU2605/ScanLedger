"""The durable scan runner (PRD FR-01, 7.3, 9).

One in-process worker owns every scan. Three properties matter here:

* **One worker only.** A second process finding a fresh heartbeat in
  ``worker_lock`` refuses to start, because two workers claiming one scan would
  double the probes sent at the lab.
* **Transactional claim.** A scan moves queued -> running with a conditional
  UPDATE; if the row count is not 1 someone else took it and we move on.
* **Restart recovery.** Module runs left ``running`` by a crash become
  ``interrupted`` - never silently ``done`` - and their scan is re-queued, so a
  missing result can never be read as "nothing was there".
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db.ledger import DatabaseLedger
from app.db.tables import FindingRow, ModuleRunRow, ScanRow, ScopeProfileRow, WorkerLockRow
from app.guard.scanguard import ScanGuard, ScopeProfile, TargetRejected
from app.models.domain import (
    ModuleStatus,
    ScanEventType,
    ScanStatus,
    TargetType,
)
from app.models.errors import AppError, ModuleError, WorkerAlreadyRunningError
from app.modules.base import ModuleContext
from app.modules.registry import ModuleRegistry
from app.scan.events import EventPublisher
from app.scan.governor import BudgetExceeded, IntensityGovernor
from app.services.retention import DEFAULT_RETENTION_DAYS, run_retention

HEARTBEAT_INTERVAL_SECONDS = 5.0
LOCK_STALE_AFTER_SECONDS = 30.0
POLL_INTERVAL_SECONDS = 0.25


def _hostname() -> str:
    """Machine name for the worker lock.

    ``socket.gethostname`` performs no network I/O, but this module is not a
    network boundary file, so the name is read through ``os`` instead to keep
    the static boundary check honest about which files may touch sockets.
    """
    return os.environ.get("COMPUTERNAME") or os.environ.get("HOSTNAME") or "localhost"


class ScanRunner:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        registry: ModuleRegistry,
        events: EventPublisher,
        *,
        retention_days: int = DEFAULT_RETENTION_DAYS,
        poll_interval: float = POLL_INTERVAL_SECONDS,
    ) -> None:
        self._session_factory = session_factory
        self._registry = registry
        self._events = events
        self._retention_days = retention_days
        self._poll_interval = poll_interval
        self._owner_id = str(uuid.uuid4())
        self._task: asyncio.Task[None] | None = None
        self._heartbeat_task: asyncio.Task[None] | None = None
        self._stopping = asyncio.Event()

    @property
    def owner_id(self) -> str:
        return self._owner_id

    # --- process model -------------------------------------------------

    async def acquire_worker_lock(self, *, now: datetime | None = None) -> None:
        moment = now or datetime.now(UTC)
        stale_before = moment - timedelta(seconds=LOCK_STALE_AFTER_SECONDS)

        async with self._session_factory() as session:
            existing = await session.get(WorkerLockRow, 1)
            if existing is None:
                session.add(
                    WorkerLockRow(
                        id=1,
                        owner_id=self._owner_id,
                        pid=os.getpid(),
                        hostname=_hostname(),
                        acquired_at=moment,
                        heartbeat_at=moment,
                    )
                )
                await session.commit()
                return

            heartbeat = existing.heartbeat_at
            if heartbeat.tzinfo is None:
                heartbeat = heartbeat.replace(tzinfo=UTC)
            if heartbeat > stale_before and existing.owner_id != self._owner_id:
                raise WorkerAlreadyRunningError(
                    "another ScanLedger worker is already running against this database "
                    f"(pid {existing.pid} on {existing.hostname}); the durable worker runs "
                    "in-process, so only one API process may serve this database",
                    details={"pid": existing.pid, "hostname": existing.hostname},
                )

            existing.owner_id = self._owner_id
            existing.pid = os.getpid()
            existing.hostname = _hostname()
            existing.acquired_at = moment
            existing.heartbeat_at = moment
            await session.commit()

    async def release_worker_lock(self) -> None:
        async with self._session_factory() as session:
            existing = await session.get(WorkerLockRow, 1)
            if existing is not None and existing.owner_id == self._owner_id:
                await session.delete(existing)
                await session.commit()

    async def _beat(self) -> None:
        async with self._session_factory() as session:
            await session.execute(
                update(WorkerLockRow)
                .where(WorkerLockRow.owner_id == self._owner_id)
                .values(heartbeat_at=datetime.now(UTC))
            )
            await session.commit()

    # --- recovery ------------------------------------------------------

    async def recover_interrupted(self) -> int:
        """Turn crash leftovers into explicit interrupted state, then re-queue."""
        async with self._session_factory() as session:
            interrupted = await session.execute(
                update(ModuleRunRow)
                .where(ModuleRunRow.status == str(ModuleStatus.RUNNING))
                .values(
                    status=str(ModuleStatus.INTERRUPTED),
                    safe_error_message="the worker stopped before this module finished",
                    finished_at=datetime.now(UTC),
                )
            )
            await session.execute(
                update(ScanRow)
                .where(ScanRow.status == str(ScanStatus.RUNNING))
                .values(status=str(ScanStatus.QUEUED), claimed_by=None)
            )
            await session.commit()
            return int(interrupted.rowcount or 0)

    # --- worker loop ---------------------------------------------------

    async def start(self) -> None:
        await self.acquire_worker_lock()
        await self.recover_interrupted()
        await run_retention(self._session_factory, retention_days=self._retention_days)
        self._stopping.clear()
        self._task = asyncio.create_task(self._loop())
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())

    async def stop(self) -> None:
        self._stopping.set()
        for task in (self._task, self._heartbeat_task):
            if task is not None:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
        self._task = None
        self._heartbeat_task = None
        await self.release_worker_lock()

    async def _heartbeat_loop(self) -> None:
        while not self._stopping.is_set():
            await self._beat()
            await asyncio.sleep(HEARTBEAT_INTERVAL_SECONDS)

    async def _loop(self) -> None:
        while not self._stopping.is_set():
            scan_id = await self.claim_next_scan()
            if scan_id is None:
                await asyncio.sleep(self._poll_interval)
                continue
            await self.execute_scan(scan_id)

    async def claim_next_scan(self) -> str | None:
        """Take the oldest queued scan, or return None if another worker won."""
        async with self._session_factory() as session:
            result = await session.execute(
                select(ScanRow.id)
                .where(ScanRow.status == str(ScanStatus.QUEUED))
                .order_by(ScanRow.created_at)
                .limit(1)
            )
            candidate = result.scalar()
            if candidate is None:
                return None

            claimed = await session.execute(
                update(ScanRow)
                .where(ScanRow.id == candidate, ScanRow.status == str(ScanStatus.QUEUED))
                .values(
                    status=str(ScanStatus.RUNNING),
                    claimed_by=self._owner_id,
                    started_at=datetime.now(UTC),
                )
            )
            await session.commit()
            if (claimed.rowcount or 0) != 1:
                return None
            return str(candidate)

    # --- execution -----------------------------------------------------

    async def execute_scan(self, scan_id: str) -> ScanStatus:
        async with self._session_factory() as session:
            scan = await session.get(ScanRow, scan_id)
            if scan is None:
                return ScanStatus.FAILED
            scope_row = await session.get(ScopeProfileRow, scan.scope_id)
            if scope_row is None:
                return await self._finish(
                    scan_id, ScanStatus.FAILED, "the scope profile for this scan no longer exists"
                )
            selected = list(scan.selected_modules_json)
            target_input = scan.target_input
            target_type = TargetType(scan.target_type)
            intensity = scan.intensity_profile
            scope = ScopeProfile.create(
                scope_row.name,
                scope_row.entries_json,
                allow_cgnat=scope_row.allow_cgnat,
                allow_link_local=scope_row.allow_link_local,
            )

        await self._events.publish(
            scan_id, ScanEventType.SCAN_STATUS, {"status": str(ScanStatus.RUNNING)}
        )

        ledger = DatabaseLedger(self._session_factory, scan_id=scan_id)
        guard = ScanGuard(scope, ledger)
        governor = IntensityGovernor(intensity)

        try:
            target = await guard.validate_target(target_input)
        except TargetRejected as exc:
            # The scope can change between creating and running a scan; a scan
            # that is no longer in scope must not run on the old decision.
            return await self._finish(
                scan_id, ScanStatus.FAILED, f"target refused at dispatch: {exc.reason}"
            )

        any_success = False
        any_problem = False

        for module_name in selected:
            if await self._cancel_requested(scan_id):
                await self._mark_remaining_skipped(scan_id, "the scan was canceled")
                return await self._finish(scan_id, ScanStatus.CANCELED, None)

            module = self._registry.get(module_name)
            if not module.applies_to(target_type):
                await self._set_module_status(
                    scan_id,
                    module_name,
                    ModuleStatus.NOT_APPLICABLE,
                    reason=f"this module does not support a {target_type} target",
                )
                continue

            await self._set_module_status(scan_id, module_name, ModuleStatus.RUNNING)
            context = ModuleContext(
                scan_id=scan_id,
                target=target,
                guard=guard,
                governor=governor,
                is_cancel_requested=lambda: False,
            )

            try:
                result = await asyncio.wait_for(
                    module.run(context), timeout=module.metadata.timeout_seconds
                )
            except TimeoutError:
                any_problem = True
                await self._set_module_status(
                    scan_id,
                    module_name,
                    ModuleStatus.FAILED,
                    reason=f"module timed out after {module.metadata.timeout_seconds:g}s",
                    code="module_timeout",
                )
            except BudgetExceeded as exc:
                any_problem = True
                await self._set_module_status(
                    scan_id,
                    module_name,
                    ModuleStatus.FAILED,
                    reason=str(exc),
                    code="budget_exceeded",
                )
            except (ModuleError, TargetRejected) as exc:
                any_problem = True
                code = exc.code if isinstance(exc, AppError) else "target_out_of_scope"
                await self._set_module_status(
                    scan_id, module_name, ModuleStatus.FAILED, reason=str(exc), code=str(code)
                )
            else:
                any_success = True
                await self._store_findings(scan_id, result.findings)
                await self._set_module_status(
                    scan_id,
                    module_name,
                    ModuleStatus.DONE,
                    finding_count=len(result.findings),
                    cache_hit=result.cache_hit,
                )

        if await self._cancel_requested(scan_id):
            await self._mark_remaining_skipped(scan_id, "the scan was canceled")
            return await self._finish(scan_id, ScanStatus.CANCELED, None)

        if not any_success:
            return await self._finish(
                scan_id, ScanStatus.FAILED, "no module produced a valid terminal result"
            )
        if any_problem:
            return await self._finish(scan_id, ScanStatus.COMPLETED_WITH_WARNINGS, None)
        return await self._finish(scan_id, ScanStatus.COMPLETED, None)

    async def _store_findings(self, scan_id: str, findings: tuple) -> None:
        if not findings:
            return
        async with self._session_factory() as session:
            for finding in findings:
                session.add(
                    FindingRow(
                        scan_id=scan_id,
                        host=finding.host,
                        port=finding.port,
                        category=str(finding.category),
                        kind=finding.kind,
                        title=finding.title,
                        summary=finding.summary,
                        normalized_value=finding.normalized_value,
                        raw_evidence=finding.raw_evidence,
                        module=finding.module,
                        observed_at=finding.observed_at,
                        confidence=None if finding.confidence is None else str(finding.confidence),
                        sources_json=list(finding.sources),
                        fingerprint=finding.fingerprint,
                    )
                )
            await session.commit()

    async def _cancel_requested(self, scan_id: str) -> bool:
        async with self._session_factory() as session:
            result = await session.execute(
                select(ScanRow.cancel_requested).where(ScanRow.id == scan_id)
            )
            return bool(result.scalar())

    async def _set_module_status(
        self,
        scan_id: str,
        module_name: str,
        status: ModuleStatus,
        *,
        reason: str | None = None,
        code: str | None = None,
        finding_count: int = 0,
        cache_hit: bool = False,
    ) -> None:
        now = datetime.now(UTC)
        values: dict[str, object] = {"status": str(status)}
        if status is ModuleStatus.RUNNING:
            values["started_at"] = now
        else:
            values["finished_at"] = now
            values["finding_count"] = finding_count
            values["cache_hit"] = cache_hit
        if reason is not None:
            values["safe_error_message"] = reason
        if code is not None:
            values["safe_error_code"] = code

        async with self._session_factory() as session:
            if status is ModuleStatus.RUNNING:
                await session.execute(
                    update(ModuleRunRow)
                    .where(ModuleRunRow.scan_id == scan_id, ModuleRunRow.module == module_name)
                    .values(attempt_count=ModuleRunRow.attempt_count + 1, **values)
                )
            else:
                await session.execute(
                    update(ModuleRunRow)
                    .where(ModuleRunRow.scan_id == scan_id, ModuleRunRow.module == module_name)
                    .values(**values)
                )
            await session.commit()

        await self._events.publish(
            scan_id,
            ScanEventType.MODULE_STATUS,
            {"status": str(status), "reason": reason, "finding_count": finding_count},
            module=module_name,
        )

    async def _mark_remaining_skipped(self, scan_id: str, reason: str) -> None:
        async with self._session_factory() as session:
            await session.execute(
                update(ModuleRunRow)
                .where(
                    ModuleRunRow.scan_id == scan_id,
                    ModuleRunRow.status.in_([str(ModuleStatus.QUEUED), str(ModuleStatus.RUNNING)]),
                )
                .values(
                    status=str(ModuleStatus.SKIPPED),
                    safe_error_message=reason,
                    finished_at=datetime.now(UTC),
                )
            )
            await session.commit()

    async def _finish(self, scan_id: str, status: ScanStatus, reason: str | None) -> ScanStatus:
        async with self._session_factory() as session:
            await session.execute(
                update(ScanRow)
                .where(ScanRow.id == scan_id)
                .values(status=str(status), finished_at=datetime.now(UTC))
            )
            await session.commit()

        await self._events.publish(
            scan_id, ScanEventType.SCAN_STATUS, {"status": str(status), "reason": reason}
        )
        await run_retention(self._session_factory, retention_days=self._retention_days)
        return status
