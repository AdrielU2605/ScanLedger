"""Append-only audit ledger (PRD FR-11, 8.1).

Every destination ScanGuard allows and every destination it denies is recorded
here, so scope compliance is provable rather than asserted. CP1 provides the
in-process sink; CP2 adds the SQLite-backed sink behind the same protocol.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Literal, Protocol

Decision = Literal["allowed", "denied"]


@dataclass(frozen=True)
class LedgerEntry:
    destination: str
    port: int | None
    module: str
    decision: Decision
    reason: str
    outcome: str
    recorded_at: datetime = field(default_factory=lambda: datetime.now(UTC))


class LedgerSink(Protocol):
    """The write side of the audit ledger. Appends only - never updates."""

    async def record(
        self,
        *,
        destination: str,
        port: int | None,
        module: str,
        decision: Decision,
        reason: str,
        outcome: str,
    ) -> None: ...


class InMemoryLedger:
    """In-process ledger sink used by tests and by CP1 before persistence exists."""

    def __init__(self) -> None:
        self._entries: list[LedgerEntry] = []

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
        self._entries.append(
            LedgerEntry(
                destination=destination,
                port=port,
                module=module,
                decision=decision,
                reason=reason,
                outcome=outcome,
            )
        )

    @property
    def entries(self) -> tuple[LedgerEntry, ...]:
        return tuple(self._entries)

    def denied(self) -> tuple[LedgerEntry, ...]:
        return tuple(entry for entry in self._entries if entry.decision == "denied")

    def allowed(self) -> tuple[LedgerEntry, ...]:
        return tuple(entry for entry in self._entries if entry.decision == "allowed")
