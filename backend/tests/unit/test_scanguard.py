"""ScanGuard decision tests (PRD 10.1, 10.2 - the required ScanGuard cases).

No socket is opened anywhere in this file: these prove the decision that
happens *before* a socket would exist.
"""

from __future__ import annotations

import ipaddress

import pytest

from app.guard.ledger import InMemoryLedger
from app.guard.resolver import ResolutionError, ResolvedName
from app.guard.scanguard import (
    ScanGuard,
    ScopeProfile,
    ScopeValidationError,
    TargetRejected,
)


def lab_scope() -> ScopeProfile:
    return ScopeProfile.create("lab", ["127.0.0.0/24", "10.10.0.0/24"])


def guard_with(resolver=None) -> tuple[ScanGuard, InMemoryLedger]:
    ledger = InMemoryLedger()
    if resolver is None:
        return ScanGuard(lab_scope(), ledger), ledger
    return ScanGuard(lab_scope(), ledger, resolver=resolver), ledger


def resolver_returning(*addresses: str):
    async def _resolver(hostname: str) -> ResolvedName:
        return ResolvedName(
            hostname=hostname,
            addresses=tuple(ipaddress.ip_address(a) for a in addresses),
        )

    return _resolver


class TestScopeProfile:
    def test_accepts_private_entries(self) -> None:
        profile = ScopeProfile.create("lab", ["10.0.0.0/24", "192.168.1.5", "127.0.0.1"])
        assert len(profile.networks) == 3

    @pytest.mark.parametrize(
        "entry", ["8.8.8.8", "0.0.0.0/0", "203.0.113.0/24", "100.64.0.0/16", "169.254.0.0/16"]
    )
    def test_rejects_entries_outside_allowed_private_ranges(self, entry: str) -> None:
        with pytest.raises(ScopeValidationError) as exc:
            ScopeProfile.create("bad", [entry])
        assert entry in str(exc.value)

    def test_rejects_overbroad_cidr(self) -> None:
        with pytest.raises(ScopeValidationError, match="too broad"):
            ScopeProfile.create("bad", ["10.0.0.0/8"])

    def test_rejects_empty_profile(self) -> None:
        with pytest.raises(ScopeValidationError):
            ScopeProfile.create("empty", [])

    def test_opt_in_ranges_accepted_only_when_enabled(self) -> None:
        with pytest.raises(ScopeValidationError):
            ScopeProfile.create("cgnat", ["100.64.1.0/24"])
        profile = ScopeProfile.create("cgnat", ["100.64.1.0/24"], allow_cgnat=True)
        assert profile.contains_address(ipaddress.ip_address("100.64.1.5"))


class TestValidateTarget:
    async def test_accepts_in_scope_address(self) -> None:
        guard, ledger = guard_with()
        target = await guard.validate_target("127.0.0.1")

        assert target.kind == "ip"
        assert target.addresses == (ipaddress.ip_address("127.0.0.1"),)
        assert len(ledger.allowed()) == 1
        assert ledger.denied() == ()

    async def test_rejects_public_address(self) -> None:
        guard, ledger = guard_with()
        with pytest.raises(TargetRejected, match="public/globally routable"):
            await guard.validate_target("8.8.8.8")
        assert len(ledger.denied()) == 1

    async def test_rejects_cloud_metadata_address(self) -> None:
        guard, ledger = guard_with()
        with pytest.raises(TargetRejected, match="cloud-metadata"):
            await guard.validate_target("169.254.169.254")
        assert ledger.denied()[0].destination == "169.254.169.254"

    @pytest.mark.parametrize("address", ["224.0.0.1", "255.255.255.255", "0.0.0.0"])
    async def test_rejects_multicast_broadcast_and_unspecified(self, address: str) -> None:
        guard, _ = guard_with()
        with pytest.raises(TargetRejected):
            await guard.validate_target(address)

    async def test_rejects_private_address_outside_active_scope(self) -> None:
        """A private address is not automatically authorized - reachable is not allowed."""
        guard, ledger = guard_with()
        with pytest.raises(TargetRejected, match="outside the active scope profile"):
            await guard.validate_target("192.168.50.1")
        assert len(ledger.denied()) == 1

    async def test_accepts_in_scope_cidr(self) -> None:
        guard, _ = guard_with()
        target = await guard.validate_target("10.10.0.0/25")
        assert target.kind == "cidr"
        assert target.network == ipaddress.ip_network("10.10.0.0/25")

    async def test_rejects_cidr_partly_outside_scope(self) -> None:
        """10.10.0.0/23 covers 10.10.1.x, which the scope does not - refuse it whole."""
        guard, ledger = guard_with()
        with pytest.raises(TargetRejected, match="outside the active scope profile"):
            await guard.validate_target("10.10.0.0/23")
        assert len(ledger.denied()) == 1

    async def test_rejects_overbroad_cidr_target(self) -> None:
        guard, _ = guard_with()
        with pytest.raises(TargetRejected, match="broader than the MVP limit"):
            await guard.validate_target("10.0.0.0/8")

    async def test_accepts_hostname_resolving_in_scope(self) -> None:
        guard, _ = guard_with(resolver_returning("127.0.0.1"))
        target = await guard.validate_target("lab.local")
        assert target.kind == "host"
        assert target.addresses == (ipaddress.ip_address("127.0.0.1"),)

    async def test_rejects_hostname_resolving_to_public_address(self) -> None:
        guard, ledger = guard_with(resolver_returning("93.184.216.34"))
        with pytest.raises(TargetRejected, match="public/globally routable"):
            await guard.validate_target("rebind.example")
        assert len(ledger.denied()) == 1

    async def test_rejects_hostname_with_any_out_of_scope_address(self) -> None:
        """Mixed resolution is refused whole, never partially scanned (PRD 2.3)."""
        guard, ledger = guard_with(resolver_returning("127.0.0.1", "8.8.8.8"))
        with pytest.raises(TargetRejected):
            await guard.validate_target("mixed.local")

        assert ledger.allowed() == ()
        assert len(ledger.denied()) == 1

    async def test_rejects_unresolvable_hostname(self) -> None:
        async def failing_resolver(hostname: str):
            raise ResolutionError(f"could not resolve {hostname!r}")

        guard, _ = guard_with(failing_resolver)
        with pytest.raises(TargetRejected, match="could not resolve"):
            await guard.validate_target("nowhere.local")

    async def test_rejects_empty_target(self) -> None:
        guard, _ = guard_with()
        with pytest.raises(TargetRejected, match="empty"):
            await guard.validate_target("   ")


class TestMisconfiguredProfileStillDenied:
    """Even if a profile somehow contains a forbidden destination, deny it."""

    async def test_metadata_address_denied_inside_link_local_profile(self) -> None:
        profile = ScopeProfile.create("link-local-lab", ["169.254.0.0/16"], allow_link_local=True)
        ledger = InMemoryLedger()
        guard = ScanGuard(profile, ledger)

        assert profile.contains_address(ipaddress.ip_address("169.254.169.254"))
        with pytest.raises(TargetRejected, match="cloud-metadata"):
            await guard.validate_target("169.254.169.254")
