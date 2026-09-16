"""Intensity governor - the reason ScanLedger cannot flood its own lab (FR-04).

Concurrency and connection-rate ceilings are hard. ``HARD_CEILING`` is a
code-defined constant, and every intensity profile is validated against it at
import time, so a profile that exceeds a ceiling cannot even be constructed -
let alone selected from the UI or a config file (PRD 8.2).
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, fields
from types import TracebackType


class GovernorConfigError(Exception):
    """A limit set would exceed the hard ceiling, or is otherwise unusable."""


class BudgetExceeded(Exception):
    """A per-host or per-scan work budget ran out; the unit ends cleanly."""

    def __init__(self, scope: str, limit: int) -> None:
        self.scope = scope
        self.limit = limit
        super().__init__(f"{scope} budget of {limit} exceeded")


@dataclass(frozen=True)
class GovernorLimits:
    global_concurrency: int
    per_host_concurrency: int
    connections_per_second: float
    connect_timeout: float
    per_host_budget: int
    per_scan_budget: int

    def validate_against(self, ceiling: GovernorLimits) -> None:
        for spec in fields(self):
            value = getattr(self, spec.name)
            if value <= 0:
                raise GovernorConfigError(f"{spec.name} must be positive, got {value}")
            ceiling_value = getattr(ceiling, spec.name)
            if value > ceiling_value:
                raise GovernorConfigError(
                    f"{spec.name}={value} exceeds the hard ceiling of {ceiling_value}"
                )


HARD_CEILING = GovernorLimits(
    global_concurrency=200,
    per_host_concurrency=20,
    connections_per_second=50.0,
    connect_timeout=5.0,
    per_host_budget=500,
    per_scan_budget=5000,
)

INTENSITY_PROFILES: dict[str, GovernorLimits] = {
    "polite": GovernorLimits(
        global_concurrency=20,
        per_host_concurrency=4,
        connections_per_second=5.0,
        connect_timeout=3.0,
        per_host_budget=200,
        per_scan_budget=2000,
    ),
    "normal": GovernorLimits(
        global_concurrency=60,
        per_host_concurrency=10,
        connections_per_second=15.0,
        connect_timeout=3.0,
        per_host_budget=300,
        per_scan_budget=3000,
    ),
    "thorough": GovernorLimits(
        global_concurrency=150,
        per_host_concurrency=16,
        connections_per_second=30.0,
        connect_timeout=4.0,
        per_host_budget=500,
        per_scan_budget=5000,
    ),
}

for _profile_name, _profile_limits in INTENSITY_PROFILES.items():
    _profile_limits.validate_against(HARD_CEILING)

MAX_BACKOFF_SECONDS = 2.0
INITIAL_BACKOFF_SECONDS = 0.05


class _TokenBucket:
    """Connections-per-second limiter shared by every host in one scan."""

    def __init__(self, rate_per_second: float) -> None:
        self._rate = rate_per_second
        self._tokens = rate_per_second
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                self._tokens = min(self._rate, self._tokens + (now - self._updated) * self._rate)
                self._updated = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                await asyncio.sleep((1.0 - self._tokens) / self._rate)


class IntensityGovernor:
    """Bounds one scan's footprint: concurrency, rate, budgets, and backoff."""

    def __init__(
        self,
        profile_name: str,
        *,
        profiles: dict[str, GovernorLimits] | None = None,
    ) -> None:
        catalog = profiles if profiles is not None else INTENSITY_PROFILES
        if profile_name not in catalog:
            raise GovernorConfigError(f"unknown intensity profile {profile_name!r}")

        limits = catalog[profile_name]
        limits.validate_against(HARD_CEILING)

        self.profile_name = profile_name
        self.limits = limits
        self._global_semaphore = asyncio.Semaphore(limits.global_concurrency)
        self._host_semaphores: dict[str, asyncio.Semaphore] = {}
        self._bucket = _TokenBucket(limits.connections_per_second)
        self._host_counts: dict[str, int] = {}
        self._scan_count = 0
        self._backoff: dict[str, float] = {}

    @property
    def probes_made(self) -> int:
        return self._scan_count

    def probes_made_against(self, host: str) -> int:
        return self._host_counts.get(host, 0)

    def slot(self, host: str) -> _GovernorSlot:
        """Reserve one governed connection slot for *host*."""
        return _GovernorSlot(self, host)

    def report_error(self, host: str) -> None:
        current = self._backoff.get(host, 0.0)
        self._backoff[host] = min(
            MAX_BACKOFF_SECONDS, current * 2 if current else INITIAL_BACKOFF_SECONDS
        )

    def report_success(self, host: str) -> None:
        self._backoff.pop(host, None)

    def backoff_for(self, host: str) -> float:
        return self._backoff.get(host, 0.0)

    def _host_semaphore(self, host: str) -> asyncio.Semaphore:
        semaphore = self._host_semaphores.get(host)
        if semaphore is None:
            semaphore = asyncio.Semaphore(self.limits.per_host_concurrency)
            self._host_semaphores[host] = semaphore
        return semaphore

    async def _acquire(self, host: str) -> None:
        if self._scan_count >= self.limits.per_scan_budget:
            raise BudgetExceeded("per-scan", self.limits.per_scan_budget)
        if self._host_counts.get(host, 0) >= self.limits.per_host_budget:
            raise BudgetExceeded(f"per-host ({host})", self.limits.per_host_budget)

        backoff = self._backoff.get(host, 0.0)
        if backoff:
            await asyncio.sleep(backoff)

        await self._bucket.acquire()
        await self._global_semaphore.acquire()
        try:
            await self._host_semaphore(host).acquire()
        except BaseException:
            self._global_semaphore.release()
            raise

        self._scan_count += 1
        self._host_counts[host] = self._host_counts.get(host, 0) + 1

    def _release(self, host: str) -> None:
        self._host_semaphore(host).release()
        self._global_semaphore.release()


class _GovernorSlot:
    def __init__(self, governor: IntensityGovernor, host: str) -> None:
        self._governor = governor
        self._host = host

    async def __aenter__(self) -> _GovernorSlot:
        await self._governor._acquire(self._host)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self._governor._release(self._host)
