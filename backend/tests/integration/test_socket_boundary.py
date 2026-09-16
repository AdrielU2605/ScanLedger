"""Dynamic proof that ScanGuard.connect is the only working socket path.

PRD 10.1: "A process-wide socket block is enabled for the whole suite, and a
test proves the ScanGuard connector and the outbound gateway are the only code
paths that can open a socket."

The one real connection made here is to a listener this test starts on
127.0.0.1, so the suite still performs no live network access.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterator

import pytest

from app.guard.ledger import InMemoryLedger
from app.guard.scanguard import (
    NETWORK_GUARD_ACTIVE,
    ScanGuard,
    ScopeProfile,
    TargetRejected,
)
from app.scan.governor import IntensityGovernor
from tests.conftest import BLOCK_MESSAGE, allow_socket_creation


@pytest.fixture
def local_listener() -> Iterator[int]:
    """A loopback TCP listener for the guard to legitimately reach.

    The escape hatch covers construction only, so the socket block is fully
    active for the duration of every test body below.
    """
    with allow_socket_creation():
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    try:
        yield int(listener.getsockname()[1])
    finally:
        listener.close()


def loopback_guard() -> tuple[ScanGuard, InMemoryLedger]:
    ledger = InMemoryLedger()
    return ScanGuard(ScopeProfile.create("self-test", ["127.0.0.0/24"]), ledger), ledger


class TestBlockIsActive:
    def test_direct_socket_creation_is_blocked(self) -> None:
        with pytest.raises(RuntimeError, match="blocked by the ScanLedger test socket block"):
            socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def test_default_arguments_are_blocked_too(self) -> None:
        with pytest.raises(RuntimeError):
            socket.socket()

    def test_ipv6_tcp_is_blocked(self) -> None:
        with pytest.raises(RuntimeError):
            socket.socket(socket.AF_INET6, socket.SOCK_STREAM)

    def test_block_message_names_the_only_allowed_path(self) -> None:
        assert "ScanGuard.connect()" in BLOCK_MESSAGE


class TestGuardedConnect:
    async def test_guard_can_connect_to_an_in_scope_host(self, local_listener: int) -> None:
        guard, ledger = loopback_guard()
        governor = IntensityGovernor("polite")
        target = await guard.validate_target("127.0.0.1")

        sock = await guard.connect(
            target, ipaddress.ip_address("127.0.0.1"), local_listener, governor
        )
        try:
            assert sock.fileno() != -1
        finally:
            sock.close()

        connected = [entry for entry in ledger.allowed() if entry.outcome == "connected"]
        assert len(connected) == 1
        assert connected[0].destination == "127.0.0.1"
        assert connected[0].port == local_listener
        assert governor.probes_made == 1

    async def test_guard_refuses_an_address_the_target_never_covered(
        self, local_listener: int
    ) -> None:
        """A module cannot smuggle a destination past the guard post-validation."""
        guard, ledger = loopback_guard()
        governor = IntensityGovernor("polite")
        target = await guard.validate_target("127.0.0.1")

        with pytest.raises(TargetRejected, match="not part of the validated target"):
            await guard.connect(target, ipaddress.ip_address("127.0.0.9"), local_listener, governor)

        assert any(entry.decision == "denied" for entry in ledger.entries)

    async def test_guard_refuses_an_out_of_scope_address_at_connect_time(self) -> None:
        guard, ledger = loopback_guard()
        governor = IntensityGovernor("polite")
        target = await guard.validate_target("127.0.0.1")

        with pytest.raises(TargetRejected):
            await guard.connect(target, ipaddress.ip_address("8.8.8.8"), 80, governor)

        assert ledger.denied()[-1].destination == "8.8.8.8"

    @pytest.mark.parametrize("port", [0, -1, 65536])
    async def test_guard_refuses_an_invalid_port(self, port: int) -> None:
        guard, _ = loopback_guard()
        governor = IntensityGovernor("polite")
        target = await guard.validate_target("127.0.0.1")

        with pytest.raises(TargetRejected, match="port"):
            await guard.connect(target, ipaddress.ip_address("127.0.0.1"), port, governor)

    async def test_guard_context_does_not_leak_after_connect(self, local_listener: int) -> None:
        """After a guarded connect returns, the block must be active again."""
        guard, _ = loopback_guard()
        governor = IntensityGovernor("polite")
        target = await guard.validate_target("127.0.0.1")

        sock = await guard.connect(
            target, ipaddress.ip_address("127.0.0.1"), local_listener, governor
        )
        sock.close()

        with pytest.raises(RuntimeError, match="blocked"):
            socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    async def test_guard_context_does_not_leak_when_socket_creation_fails(self) -> None:
        """Even if the socket cannot be built, the block must close behind us."""
        guard, _ = loopback_guard()
        governor = IntensityGovernor("polite")
        target = await guard.validate_target("127.0.0.1")

        def exploding_socket(*args: object, **kwargs: object) -> None:
            raise OSError("no file descriptors available")

        # A nested context so undoing this patch leaves the suite-wide socket
        # block (applied by the autouse fixture) untouched.
        with pytest.MonkeyPatch.context() as patcher:
            patcher.setattr("app.guard.scanguard.socket.socket", exploding_socket)
            with pytest.raises(OSError, match="no file descriptors"):
                await guard.connect(target, ipaddress.ip_address("127.0.0.1"), 9, governor)

        assert NETWORK_GUARD_ACTIVE.get() is False
        with pytest.raises(RuntimeError, match="blocked"):
            socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    async def test_failed_connect_is_ledgered_and_backs_off(self) -> None:
        """A closed port is evidence, not an error - and it must be recorded."""
        guard, ledger = loopback_guard()
        governor = IntensityGovernor("polite")
        target = await guard.validate_target("127.0.0.1")

        # Port 1 on loopback has no listener in this environment.
        with pytest.raises(OSError):
            await guard.connect(target, ipaddress.ip_address("127.0.0.1"), 1, governor)

        failures = [entry for entry in ledger.entries if entry.outcome == "connect_failed"]
        assert len(failures) == 1
        assert governor.backoff_for("127.0.0.1") > 0
