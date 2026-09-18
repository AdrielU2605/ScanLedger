"""Host discovery and port scan against a real loopback listener (PRD FR-07).

These are the first tests where application code actually contacts something.
The listener is started by the test on 127.0.0.1, so the suite still performs
no live network access, and every probe still goes through ScanGuard.connect -
the process-wide socket block would fail the test otherwise.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterator

import pytest

from app.guard.ledger import InMemoryLedger
from app.guard.scanguard import ScanGuard, ScopeProfile
from app.models.domain import FindingCategory
from app.models.errors import ModuleError
from app.modules.base import ModuleContext
from app.modules.host_discovery import HostDiscoveryModule
from app.modules.port_scan import PortScanModule
from app.modules.ports import TOP_100_PORTS, resolve_ports
from app.scan.governor import IntensityGovernor
from tests.conftest import allow_socket_creation


@pytest.fixture
def open_port() -> Iterator[int]:
    with allow_socket_creation():
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(16)
    try:
        yield int(listener.getsockname()[1])
    finally:
        listener.close()


@pytest.fixture
def closed_port() -> int:
    """A port with nothing listening: bound, read, then released."""
    with allow_socket_creation():
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = int(probe.getsockname()[1])
    probe.close()
    return port


async def make_context(
    target_text: str, options: dict | None = None
) -> tuple[ModuleContext, InMemoryLedger]:
    ledger = InMemoryLedger()
    guard = ScanGuard(ScopeProfile.create("self-test", ["127.0.0.0/24"]), ledger)
    target = await guard.validate_target(target_text)
    context = ModuleContext(
        scan_id="scan-1",
        target=target,
        guard=guard,
        governor=IntensityGovernor("normal"),
        is_cancel_requested=lambda: False,
        options=options or {},
    )
    return context, ledger


class TestPortSelection:
    def test_top_100_is_the_default(self) -> None:
        assert resolve_ports({}) == TOP_100_PORTS

    def test_well_known_covers_1_to_1024(self) -> None:
        ports = resolve_ports({"port_selection": "well-known"})
        assert ports[0] == 1
        assert ports[-1] == 1024

    def test_custom_ports_are_deduplicated_and_sorted(self) -> None:
        assert resolve_ports({"port_selection": "custom", "ports": [443, 22, 443]}) == (22, 443)

    @pytest.mark.parametrize(
        "options",
        [
            {"port_selection": "top-1000"},
            {"port_selection": "custom"},
            {"port_selection": "custom", "ports": [70000]},
            {"port_selection": "custom", "ports": ["http"]},
        ],
    )
    def test_bad_selections_raise_a_typed_error(self, options: dict) -> None:
        with pytest.raises(ModuleError):
            resolve_ports(options)


class TestPortScan:
    async def test_open_port_is_detected(self, open_port: int) -> None:
        context, ledger = await make_context(
            "127.0.0.1", {"port_selection": "custom", "ports": [open_port]}
        )
        result = await PortScanModule().run(context)

        open_findings = [f for f in result.findings if f.kind == "port.open"]
        assert len(open_findings) == 1
        assert open_findings[0].port == open_port
        assert open_findings[0].category is FindingCategory.PORT_SERVICE

        # The probe is in the ledger, so the scan's footprint is provable.
        assert any(
            entry.destination == "127.0.0.1" and entry.port == open_port
            for entry in ledger.allowed()
        )

    async def test_closed_port_is_reported_as_closed_not_open(self, closed_port: int) -> None:
        context, _ = await make_context(
            "127.0.0.1", {"port_selection": "custom", "ports": [closed_port]}
        )
        result = await PortScanModule().run(context)

        assert [f for f in result.findings if f.kind == "port.open"] == []
        summary = next(f for f in result.findings if f.kind == "port.summary")
        assert summary.normalized_value["open"] == []
        assert summary.normalized_value["closed_count"] == 1

    async def test_all_closed_produces_an_explicit_summary(self, closed_port: int) -> None:
        """'Everything was closed' must be a stated result, not an empty section."""
        context, _ = await make_context(
            "127.0.0.1", {"port_selection": "custom", "ports": [closed_port]}
        )
        result = await PortScanModule().run(context)

        summary = next(f for f in result.findings if f.kind == "port.summary")
        assert "0 open" in summary.summary
        assert summary.normalized_value["probed"] == 1

    async def test_mixed_open_and_closed(self, open_port: int, closed_port: int) -> None:
        context, _ = await make_context(
            "127.0.0.1", {"port_selection": "custom", "ports": [open_port, closed_port]}
        )
        result = await PortScanModule().run(context)

        summary = next(f for f in result.findings if f.kind == "port.summary")
        assert summary.normalized_value["open"] == [open_port]
        assert summary.normalized_value["closed_count"] == 1

    async def test_every_probe_is_governed(self, open_port: int) -> None:
        context, _ = await make_context(
            "127.0.0.1", {"port_selection": "custom", "ports": [open_port]}
        )
        await PortScanModule().run(context)

        assert context.governor.probes_made == 1
        assert context.governor.hosts_touched == 1

    async def test_findings_have_stable_fingerprints(self, open_port: int) -> None:
        options = {"port_selection": "custom", "ports": [open_port]}
        first_context, _ = await make_context("127.0.0.1", options)
        second_context, _ = await make_context("127.0.0.1", options)

        first = await PortScanModule().run(first_context)
        second = await PortScanModule().run(second_context)

        assert [f.fingerprint for f in first.findings] == [f.fingerprint for f in second.findings]


class TestHostDiscovery:
    async def test_a_listening_host_is_alive_with_evidence(self, open_port: int) -> None:
        context, _ = await make_context("127.0.0.1", {"discovery_ports": [open_port]})
        result = await HostDiscoveryModule().run(context)

        assert len(result.findings) == 1
        finding = result.findings[0]
        assert finding.category is FindingCategory.LIVE_HOST
        assert finding.normalized_value["proved_by_port"] == open_port
        assert "accepted a connection" in (finding.raw_evidence or "")

    async def test_a_refusal_also_proves_the_host_is_there(self, closed_port: int) -> None:
        context, _ = await make_context("127.0.0.1", {"discovery_ports": [closed_port]})
        result = await HostDiscoveryModule().run(context)

        assert len(result.findings) == 1
        assert "refused" in (result.findings[0].raw_evidence or "")

    async def test_a_cidr_target_expands_to_each_address(self, open_port: int) -> None:
        """Every address in the CIDR is probed, and each one says why it is alive.

        The whole 127.0.0.0/8 is loopback, so other addresses in the range
        answer with a refusal rather than silence - which is still proof a
        stack is there, and is recorded as such.
        """
        context, ledger = await make_context("127.0.0.0/30", {"discovery_ports": [open_port]})
        result = await HostDiscoveryModule().run(context)

        by_host = {finding.host: finding for finding in result.findings}
        assert "127.0.0.1" in by_host
        assert "accepted a connection" in (by_host["127.0.0.1"].raw_evidence or "")
        for host, finding in by_host.items():
            if host != "127.0.0.1":
                assert "refused" in (finding.raw_evidence or "")

        # Every address the CIDR covered was probed through the guard.
        probed = {entry.destination for entry in ledger.allowed() if entry.port is not None}
        assert probed >= set(by_host)


class TestGuardIsTheOnlyPath:
    async def test_probing_outside_the_validated_target_is_refused(self, open_port: int) -> None:
        """A module cannot reach an address the target never covered."""
        from app.guard.scanguard import TargetRejected

        context, _ = await make_context("127.0.0.1")
        with pytest.raises(TargetRejected):
            await context.guard.connect(
                context.target,
                ipaddress.ip_address("127.0.0.9"),
                open_port,
                context.governor,
            )
