"""Database-backed audit ledger sink.

Implements the ``LedgerSink`` protocol ScanGuard writes through, so the guard
stays unaware of persistence. Writes are append-only: no update or delete path
exists here, and rows leave only when their parent scan is deleted.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db.tables import ScanLedgerRow
from app.guard.ledger import Decision


class DatabaseLedger:
    """Ledger sink bound to one scan (or to none, for pre-scan validation)."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        scan_id: str | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._scan_id = scan_id

    def for_scan(self, scan_id: str) -> DatabaseLedger:
        return DatabaseLedger(self._session_factory, scan_id=scan_id)

    async def record(
        self,
        *,
        destination: str,
        port: int | None,
        module: str,
        decision: Decision,
        reason: str,
        outcome: str,
    ) -> None:
        async with self._session_factory() as session:
            session.add(
                ScanLedgerRow(
                    scan_id=self._scan_id,
                    destination=destination,
                    port=port,
                    module=module,
                    decision=decision,
                    reason=reason,
                    outcome=outcome,
                )
            )
            await session.commit()
