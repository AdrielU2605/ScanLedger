"""Intensity governor tests (PRD 8.2, 10.1)."""

from __future__ import annotations

import asyncio
import time

import pytest

from app.scan.governor import (
    HARD_CEILING,
    INTENSITY_PROFILES,
    BudgetExceeded,
    GovernorConfigError,
    GovernorLimits,
    IntensityGovernor,
)


def limits(**overrides: float) -> GovernorLimits:
    base = {
        "global_concurrency": 10,
        "per_host_concurrency": 4,
        "connections_per_second": 50.0,
        "connect_timeout": 1.0,
        "per_host_budget": 100,
        "per_scan_budget": 100,
    }
    base.update(overrides)
    return GovernorLimits(**base)  # type: ignore[arg-type]


class TestHardCeiling:
    def test_shipped_profiles_are_all_below_the_ceiling(self) -> None:
        for name, profile in INTENSITY_PROFILES.items():
            profile.validate_against(HARD_CEILING)
            assert profile.global_concurrency <= HARD_CEILING.global_concurrency, name

    @pytest.mark.parametrize(
        "field",
        [
            "global_concurrency",
            "per_host_concurrency",
            "connections_per_second",
            "connect_timeout",
            "per_host_budget",
            "per_scan_budget",
        ],
    )
    def test_no_profile_may_exceed_any_ceiling_dimension(self, field: str) -> None:
        over_ceiling = limits(**{field: getattr(HARD_CEILING, field) + 1})
        with pytest.raises(GovernorConfigError, match="exceeds the hard ceiling"):
            over_ceiling.validate_against(HARD_CEILING)

    def test_governor_refuses_an_over_ceiling_profile_at_construction(self) -> None:
        catalog = {"flood": limits(global_concurrency=HARD_CEILING.global_concurrency + 500)}
        with pytest.raises(GovernorConfigError):
            IntensityGovernor("flood", profiles=catalog)

    def test_unknown_profile_is_refused(self) -> None:
        with pytest.raises(GovernorConfigError, match="unknown intensity profile"):
            IntensityGovernor("turbo")


class TestConcurrency:
    async def test_per_host_concurrency_is_never_exceeded(self) -> None:
        governor = IntensityGovernor("test", profiles={"test": limits(per_host_concurrency=3)})
        active = 0
        peak = 0

        async def probe() -> None:
            nonlocal active, peak
            async with governor.slot("10.10.0.1"):
                active += 1
                peak = max(peak, active)
                await asyncio.sleep(0.01)
                active -= 1

        await asyncio.gather(*(probe() for _ in range(12)))
        assert peak == 3

    async def test_global_concurrency_is_never_exceeded_across_hosts(self) -> None:
        governor = IntensityGovernor(
            "test", profiles={"test": limits(global_concurrency=5, per_host_concurrency=4)}
        )
        active = 0
        peak = 0

        async def probe(host: str) -> None:
            nonlocal active, peak
            async with governor.slot(host):
                active += 1
                peak = max(peak, active)
                await asyncio.sleep(0.01)
                active -= 1

        hosts = [f"10.10.0.{i}" for i in range(6)]
        await asyncio.gather(*(probe(host) for host in hosts for _ in range(4)))
        assert peak <= 5

    async def test_slots_are_released_when_the_body_raises(self) -> None:
        governor = IntensityGovernor("test", profiles={"test": limits(per_host_concurrency=1)})

        with pytest.raises(ValueError):
            async with governor.slot("10.10.0.1"):
                raise ValueError("probe failed")

        async with governor.slot("10.10.0.1"):
            pass


class TestRateLimit:
    async def test_connections_per_second_ceiling_is_honored(self) -> None:
        governor = IntensityGovernor(
            "test",
            profiles={"test": limits(connections_per_second=10.0, global_concurrency=20)},
        )

        async def probe() -> None:
            async with governor.slot("10.10.0.1"):
                pass

        started = time.monotonic()
        await asyncio.gather(*(probe() for _ in range(20)))
        elapsed = time.monotonic() - started

        # 20 probes at 10/s cannot complete in under ~1s once the initial
        # bucket of 10 tokens is spent.
        assert elapsed >= 0.8


class TestBudgets:
    async def test_per_host_budget_ends_the_unit_cleanly(self) -> None:
        governor = IntensityGovernor("test", profiles={"test": limits(per_host_budget=3)})

        for _ in range(3):
            async with governor.slot("10.10.0.1"):
                pass

        with pytest.raises(BudgetExceeded, match="per-host"):
            async with governor.slot("10.10.0.1"):
                pass

        # A different host still has its own budget.
        async with governor.slot("10.10.0.2"):
            pass

    async def test_per_scan_budget_stops_the_whole_scan(self) -> None:
        governor = IntensityGovernor(
            "test", profiles={"test": limits(per_scan_budget=2, per_host_budget=100)}
        )

        async with governor.slot("10.10.0.1"):
            pass
        async with governor.slot("10.10.0.2"):
            pass

        with pytest.raises(BudgetExceeded, match="per-scan"):
            async with governor.slot("10.10.0.3"):
                pass


class TestBackoff:
    async def test_errors_back_off_and_success_clears_it(self) -> None:
        governor = IntensityGovernor("polite")

        assert governor.backoff_for("10.10.0.1") == 0.0
        governor.report_error("10.10.0.1")
        first = governor.backoff_for("10.10.0.1")
        governor.report_error("10.10.0.1")
        second = governor.backoff_for("10.10.0.1")

        assert 0 < first < second
        governor.report_success("10.10.0.1")
        assert governor.backoff_for("10.10.0.1") == 0.0

    async def test_backoff_is_capped(self) -> None:
        governor = IntensityGovernor("polite")
        for _ in range(50):
            governor.report_error("10.10.0.1")
        assert governor.backoff_for("10.10.0.1") <= 2.0


class TestFootprintCounters:
    async def test_probe_counts_are_tracked_for_the_ledger_and_ui(self) -> None:
        governor = IntensityGovernor("polite")
        async with governor.slot("10.10.0.1"):
            pass
        async with governor.slot("10.10.0.1"):
            pass
        async with governor.slot("10.10.0.2"):
            pass

        assert governor.probes_made == 3
        assert governor.probes_made_against("10.10.0.1") == 2
        assert governor.probes_made_against("10.10.0.2") == 1
