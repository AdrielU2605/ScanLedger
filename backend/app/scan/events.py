"""Scan progress events (PRD 7.3, UX-07).

SSE is advisory and the status endpoint is authoritative, so every event is
persisted with a monotonic per-scan sequence before it is broadcast. A client
that drops the stream reconnects with a last event id and replays what it
missed from the table rather than losing progress.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db.tables import ScanEventRow
from app.models.domain import ScanEventType


@dataclass(frozen=True)
class ScanEvent:
    scan_id: str
    sequence: int
    event_type: str
    module: str | None
    payload: dict[str, Any]


class EventPublisher:
    """Persists events, then fans them out to any live SSE subscribers."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory
        self._subscribers: dict[str, set[asyncio.Queue[ScanEvent]]] = {}

    async def publish(
        self,
        scan_id: str,
        event_type: ScanEventType,
        payload: dict[str, Any],
        *,
        module: str | None = None,
    ) -> ScanEvent:
        async with self._session_factory() as session:
            next_sequence = await self._next_sequence(session, scan_id)
            session.add(
                ScanEventRow(
                    scan_id=scan_id,
                    sequence=next_sequence,
                    module=module,
                    event_type=str(event_type),
                    payload_json=payload,
                )
            )
            await session.commit()

        event = ScanEvent(
            scan_id=scan_id,
            sequence=next_sequence,
            event_type=str(event_type),
            module=module,
            payload=payload,
        )
        self._broadcast(event)
        return event

    async def _next_sequence(self, session: AsyncSession, scan_id: str) -> int:
        result = await session.execute(
            select(ScanEventRow.sequence)
            .where(ScanEventRow.scan_id == scan_id)
            .order_by(ScanEventRow.sequence.desc())
            .limit(1)
        )
        highest = result.scalar()
        return 1 if highest is None else highest + 1

    async def events_since(self, scan_id: str, after_sequence: int) -> tuple[ScanEvent, ...]:
        async with self._session_factory() as session:
            result = await session.execute(
                select(ScanEventRow)
                .where(ScanEventRow.scan_id == scan_id, ScanEventRow.sequence > after_sequence)
                .order_by(ScanEventRow.sequence)
            )
            return tuple(
                ScanEvent(
                    scan_id=row.scan_id,
                    sequence=row.sequence,
                    event_type=row.event_type,
                    module=row.module,
                    payload=row.payload_json,
                )
                for row in result.scalars()
            )

    def subscribe(self, scan_id: str) -> asyncio.Queue[ScanEvent]:
        queue: asyncio.Queue[ScanEvent] = asyncio.Queue()
        self._subscribers.setdefault(scan_id, set()).add(queue)
        return queue

    def unsubscribe(self, scan_id: str, queue: asyncio.Queue[ScanEvent]) -> None:
        subscribers = self._subscribers.get(scan_id)
        if subscribers is None:
            return
        subscribers.discard(queue)
        if not subscribers:
            del self._subscribers[scan_id]

    def _broadcast(self, event: ScanEvent) -> None:
        for queue in self._subscribers.get(event.scan_id, set()):
            queue.put_nowait(event)
