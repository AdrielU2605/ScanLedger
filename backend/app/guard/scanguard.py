"""ScanGuard - the only code path that may open a socket to a target.

PRD FR-03, 7.6, 8.1. Deny by default. A destination is reachable only when it
is (a) not in an always-denied class, (b) inside the allowed private ranges,
and (c) inside the active, attested scope profile. Every decision, allow or
deny, is written to the append-only audit ledger.

``NETWORK_GUARD_ACTIVE`` is the enforcement hook the test suite uses: the
process-wide socket block in ``tests/conftest.py`` refuses to construct an
outbound TCP socket unless this context variable is set, and it is set in
exactly one place - inside ``ScanGuard.connect``.
"""

from __future__ import annotations

import asyncio
import contextlib
import contextvars
import ipaddress
import socket
import ssl
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from typing import Literal

from app.guard.ledger import LedgerSink
from app.guard.ranges import (
    IPAddress,
    IPNetwork,
    allowed_ranges_for,
    check_prefix_breadth,
    is_always_denied,
    network_always_denied,
    network_within_allowed,
)
from app.guard.resolver import ResolutionError, ResolvedName, resolve_hostname
from app.scan.governor import IntensityGovernor

NETWORK_GUARD_ACTIVE: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "scanledger_network_guard_active", default=False
)

TargetKind = Literal["ip", "cidr", "host"]
Resolver = Callable[[str], Awaitable[ResolvedName]]

MODULE_NAME = "scanguard"


class ScopeValidationError(Exception):
    """A scope profile entry is not a legal lab scope entry."""


class TargetRejected(Exception):
    """A target or destination was refused before any packet was sent."""

    def __init__(self, target: str, reason: str) -> None:
        self.target = target
        self.reason = reason
        super().__init__(f"{target} rejected: {reason}")


@dataclass(frozen=True)
class ScopeProfile:
    """A named, validated lab scope. Every entry is a subset of allowed ranges."""

    name: str
    entries: tuple[str, ...]
    networks: tuple[IPNetwork, ...]
    allow_cgnat: bool = False
    allow_link_local: bool = False

    @classmethod
    def create(
        cls,
        name: str,
        entries: Iterable[str],
        *,
        allow_cgnat: bool = False,
        allow_link_local: bool = False,
    ) -> ScopeProfile:
        raw_entries = tuple(entries)
        if not raw_entries:
            raise ScopeValidationError("a scope profile needs at least one entry")

        allowed = allowed_ranges_for(allow_cgnat=allow_cgnat, allow_link_local=allow_link_local)
        networks: list[IPNetwork] = []
        for raw in raw_entries:
            network = _parse_scope_entry(raw)
            breadth_problem = check_prefix_breadth(network)
            if breadth_problem is not None:
                raise ScopeValidationError(f"{raw!r} is too broad: {breadth_problem}")
            if not network_within_allowed(network, allowed):
                raise ScopeValidationError(
                    f"{raw!r} is not inside the allowed private ranges "
                    "(RFC1918, IPv6 ULA, loopback; CGNAT and link-local require opt-in)"
                )
            networks.append(network)

        return cls(
            name=name,
            entries=raw_entries,
            networks=tuple(networks),
            allow_cgnat=allow_cgnat,
            allow_link_local=allow_link_local,
        )

    def contains_address(self, address: IPAddress) -> bool:
        return any(address in network for network in self.networks)

    def contains_network(self, network: IPNetwork) -> bool:
        return network_within_allowed(network, self.networks)


def _parse_scope_entry(raw: str) -> IPNetwork:
    text = raw.strip()
    if not text:
        raise ScopeValidationError("an empty scope entry is not valid")
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError as exc:
        raise ScopeValidationError(
            f"{raw!r} is not a valid IP address or CIDR - scope profiles accept "
            "literal addresses and CIDRs only"
        ) from exc


@dataclass(frozen=True)
class TlsInfo:
    """Raw TLS facts. Parsing the certificate is the caller's job.

    The guard hands back bytes rather than a parsed certificate so that
    certificate parsing - which handles untrusted, target-controlled data -
    happens outside the boundary module, in code that cannot open a socket.
    """

    certificate_der: bytes | None
    protocol: str | None
    cipher: str | None


@dataclass
class GuardedStream:
    """The only way a module reads from or writes to a target.

    Modules never see a socket: they get these streams, so no module needs a
    socket API of its own and the static boundary check stays strict.
    """

    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    tls: TlsInfo | None = None

    async def close(self) -> None:
        self.writer.close()
        with contextlib.suppress(Exception):
            await self.writer.wait_closed()


@dataclass(frozen=True)
class ValidatedTarget:
    """A target proven in-scope. Nothing may be probed that is not described here."""

    raw: str
    kind: TargetKind
    addresses: tuple[IPAddress, ...] = ()
    network: IPNetwork | None = None

    def covers(self, address: IPAddress) -> bool:
        if self.network is not None:
            return address in self.network
        return address in self.addresses


class ScanGuard:
    """The sole target-socket path for every scan module."""

    def __init__(
        self,
        scope: ScopeProfile,
        ledger: LedgerSink,
        *,
        resolver: Resolver = resolve_hostname,
    ) -> None:
        self._scope = scope
        self._ledger = ledger
        self._resolver = resolver

    @property
    def scope(self) -> ScopeProfile:
        return self._scope

    async def validate_target(self, raw_target: str) -> ValidatedTarget:
        """Prove a target is in scope, or refuse it. No packet is sent here."""
        kind, address_candidates, network_candidate = await self._classify(raw_target)

        if network_candidate is not None:
            await self._validate_network(raw_target, network_candidate)
            return ValidatedTarget(raw=raw_target, kind=kind, network=network_candidate)

        await self._validate_addresses(raw_target, address_candidates)
        return ValidatedTarget(raw=raw_target, kind=kind, addresses=address_candidates)

    async def connect(
        self,
        target: ValidatedTarget,
        address: IPAddress,
        port: int,
        governor: IntensityGovernor,
    ) -> socket.socket:
        """Open the one kind of socket this application is allowed to open.

        The destination is re-checked here even though ``validate_target``
        already cleared it, so a module cannot reach a host by handing the
        guard an address the validated target never covered.
        """
        if not 0 < port <= 65535:
            raise TargetRejected(f"{address}:{port}", "port is outside 1-65535")
        if not target.covers(address):
            await self._deny(str(address), port, "address is not part of the validated target")

        denial = is_always_denied(address)
        if denial is None and not self._scope.contains_address(address):
            denial = "outside the active scope profile"
        if denial is not None:
            await self._deny(str(address), port, denial)

        host_key = str(address)
        async with governor.slot(host_key):
            token = NETWORK_GUARD_ACTIVE.set(True)
            sock: socket.socket | None = None
            try:
                sock = socket.socket(
                    socket.AF_INET if address.version == 4 else socket.AF_INET6,
                    socket.SOCK_STREAM,
                )
                sock.setblocking(False)
                loop = asyncio.get_running_loop()
                await asyncio.wait_for(
                    loop.sock_connect(sock, (str(address), port)),
                    timeout=governor.limits.connect_timeout,
                )
            except BaseException:
                if sock is not None:
                    sock.close()
                governor.report_error(host_key)
                await self._ledger.record(
                    destination=str(address),
                    port=port,
                    module=MODULE_NAME,
                    decision="allowed",
                    reason="inside the active scope profile",
                    outcome="connect_failed",
                )
                raise
            finally:
                NETWORK_GUARD_ACTIVE.reset(token)

        governor.report_success(host_key)
        await self._ledger.record(
            destination=str(address),
            port=port,
            module=MODULE_NAME,
            decision="allowed",
            reason="inside the active scope profile",
            outcome="connected",
        )
        return sock

    async def open_stream(
        self,
        target: ValidatedTarget,
        address: IPAddress,
        port: int,
        governor: IntensityGovernor,
        *,
        use_tls: bool = False,
    ) -> GuardedStream:
        """Open a guarded read/write stream, optionally upgraded to TLS.

        The socket is created by ``connect`` and handed straight to asyncio,
        so no new connection is opened here and every scope check has already
        run. TLS verification is deliberately off: ScanLedger inspects the
        certificate a lab host presents, it does not trust it, and a self
        signed certificate must still be reportable rather than fatal.
        """
        sock = await self.connect(target, address, port, governor)

        token = NETWORK_GUARD_ACTIVE.set(True)
        try:
            if not use_tls:
                reader, writer = await asyncio.open_connection(sock=sock)
                return GuardedStream(reader=reader, writer=writer)

            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.open_connection(
                sock=sock, ssl=context, server_hostname=str(address)
            )
            ssl_object = writer.get_extra_info("ssl_object")
            tls = TlsInfo(
                certificate_der=(ssl_object.getpeercert(binary_form=True) if ssl_object else None),
                protocol=ssl_object.version() if ssl_object else None,
                cipher=(ssl_object.cipher() or (None,))[0] if ssl_object else None,
            )
            return GuardedStream(reader=reader, writer=writer, tls=tls)
        except BaseException:
            sock.close()
            raise
        finally:
            NETWORK_GUARD_ACTIVE.reset(token)

    async def _classify(
        self, raw_target: str
    ) -> tuple[TargetKind, tuple[IPAddress, ...], IPNetwork | None]:
        text = raw_target.strip()
        if not text:
            raise TargetRejected(raw_target, "target is empty")

        if "/" in text:
            try:
                network = ipaddress.ip_network(text, strict=False)
            except ValueError as exc:
                raise TargetRejected(raw_target, f"not a valid CIDR: {exc}") from exc
            return "cidr", (), network

        try:
            return "ip", (ipaddress.ip_address(text),), None
        except ValueError:
            pass

        try:
            resolved = await self._resolver(text)
        except ResolutionError as exc:
            raise TargetRejected(raw_target, str(exc)) from exc
        return "host", resolved.addresses, None

    async def _validate_network(self, raw_target: str, network: IPNetwork) -> None:
        breadth_problem = check_prefix_breadth(network)
        if breadth_problem is not None:
            await self._deny(str(network), None, breadth_problem)

        denial = network_always_denied(network)
        if denial is None and not self._scope.contains_network(network):
            denial = "outside the active scope profile"
        if denial is not None:
            await self._deny(str(network), None, denial)

        await self._ledger.record(
            destination=str(network),
            port=None,
            module=MODULE_NAME,
            decision="allowed",
            reason="inside the active scope profile",
            outcome="validated",
        )

    async def _validate_addresses(self, raw_target: str, addresses: tuple[IPAddress, ...]) -> None:
        if not addresses:
            raise TargetRejected(raw_target, "target resolved to no addresses")

        # A hostname is refused whole if ANY of its addresses is out of scope,
        # rather than scanning the in-scope subset (PRD 2.3, 8.1).
        for address in addresses:
            denial = is_always_denied(address)
            if denial is None and not self._scope.contains_address(address):
                denial = "outside the active scope profile"
            if denial is not None:
                await self._deny(str(address), None, f"{denial} (from target {raw_target})")

        for address in addresses:
            await self._ledger.record(
                destination=str(address),
                port=None,
                module=MODULE_NAME,
                decision="allowed",
                reason="inside the active scope profile",
                outcome="validated",
            )

    async def _deny(self, destination: str, port: int | None, reason: str) -> None:
        await self._ledger.record(
            destination=destination,
            port=port,
            module=MODULE_NAME,
            decision="denied",
            reason=reason,
            outcome="rejected",
        )
        raise TargetRejected(destination, reason)
