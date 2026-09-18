"""Service and version detection (PRD FR-08).

Bounded banner grabbing only: connect, read whatever the service volunteers,
and for HTTP send a single read-only GET. Nothing authenticates, submits a
form, writes data, or sends a payload intended to provoke a vulnerable code
path - that is the Phase 3 boundary.

Live Nmap service detection is deliberately absent from the MVP: it opens its
own sockets outside ScanGuard, which would defeat the whole boundary.
"""

from __future__ import annotations

import asyncio

from app.guard.ranges import IPAddress
from app.guard.scanguard import GuardedStream
from app.models.domain import (
    Confidence,
    FindingCategory,
    ModuleCategory,
    TargetType,
)
from app.models.findings import Finding
from app.modules.base import ModuleContext, ModuleMetadata, ModuleResult, ScanModule
from app.modules.fingerprints import (
    HTTP_SERVER_HEADER,
    ServiceGuess,
    identify_from_banner,
    identify_from_http_server_header,
    service_name_for_port,
)
from app.scan.concurrency import in_bounded_waves
from app.scan.governor import BudgetExceeded

MODULE_NAME = "service_detect"

BANNER_BYTES = 4096
BANNER_WAIT_SECONDS = 3.0
TLS_PORTS = frozenset({443, 465, 636, 993, 995, 8443})
HTTP_PORTS = frozenset({80, 81, 591, 3000, 5000, 8000, 8008, 8080, 8081, 8088, 8888})


def _decode(raw: bytes) -> str:
    """Target-controlled bytes, decoded without ever raising."""
    return raw.decode("utf-8", errors="replace")


class ServiceDetectModule(ScanModule):
    metadata = ModuleMetadata(
        name=MODULE_NAME,
        display_name="Service and version detection",
        description=(
            "Reads the banner an open port volunteers and, for HTTP, sends one "
            "read-only GET. Infers product and version with a confidence level, "
            "and never guesses a version the service did not state."
        ),
        category=ModuleCategory.SERVICE_DETECTION,
        supported_targets=frozenset({TargetType.IP, TargetType.CIDR, TargetType.HOST}),
        timeout_seconds=900.0,
        order=30,
    )

    async def run(self, context: ModuleContext) -> ModuleResult:
        open_ports = context.open_ports_by_host()
        if not open_ports:
            # Nothing to identify is a legitimate outcome, not a failure: it
            # means the port scan found nothing open, or did not run.
            return ModuleResult(
                warnings=(
                    "no open ports were available from this scan, so no service "
                    "could be identified",
                ),
            )

        findings: list[Finding] = []
        budget_reached = False

        factories = [
            (lambda host=host, port=port: self._identify(context, host, port))
            for host, ports in open_ports.items()
            for port in ports
        ]

        async for outcome in in_bounded_waves(factories, wave_size=32):
            if isinstance(outcome, BudgetExceeded):
                budget_reached = True
                continue
            if isinstance(outcome, BaseException):
                raise outcome
            if outcome is not None:
                findings.append(outcome)

        warnings = (
            ("the governor's probe budget was reached; some open ports were not identified",)
            if budget_reached
            else ()
        )
        return ModuleResult(findings=tuple(findings), warnings=warnings)

    async def _identify(self, context: ModuleContext, host: str, port: int) -> Finding | None:
        if context.is_cancel_requested():
            return None

        address = _address_for(context, host)
        if address is None:
            return None

        banner = ""
        guess: ServiceGuess | None = None
        use_tls = port in TLS_PORTS

        try:
            stream = await context.guard.open_stream(
                context.target, address, port, context.governor, use_tls=use_tls
            )
        except BudgetExceeded:
            raise
        except (TimeoutError, OSError):
            return None

        try:
            banner = await self._read_banner(stream, host, port, use_tls)
        finally:
            await stream.close()

        if banner:
            guess = identify_from_banner(banner, port)
            if guess is None:
                header = HTTP_SERVER_HEADER.search(banner)
                if header is not None:
                    guess = identify_from_http_server_header(header.group(1))

        if guess is None:
            # Nothing identifiable: fall back to the conventional name for the
            # port, explicitly at low confidence, rather than inventing detail.
            guess = service_name_for_port(port) or ServiceGuess(
                service="unknown", product=None, version=None, confidence=Confidence.LOW
            )

        return _service_finding(host, port, guess, banner, use_tls)

    async def _read_banner(self, stream: GuardedStream, host: str, port: int, use_tls: bool) -> str:
        """Read what the service offers; ask politely once if it stays silent."""
        try:
            raw = await asyncio.wait_for(
                stream.reader.read(BANNER_BYTES), timeout=BANNER_WAIT_SECONDS
            )
        except (TimeoutError, OSError):
            raw = b""

        if raw:
            return _decode(raw)

        # The service volunteered nothing. Ask once with a read-only GET -
        # regardless of port number, because a lab service on a non-standard
        # port is the normal case, not the exception. No credentials, no body,
        # no side effects.
        try:
            stream.writer.write(
                f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: ScanLedger\r\n"
                "Accept: */*\r\nConnection: close\r\n\r\n".encode()
            )
            await stream.writer.drain()
            raw = await asyncio.wait_for(
                stream.reader.read(BANNER_BYTES), timeout=BANNER_WAIT_SECONDS
            )
        except (TimeoutError, OSError):
            return ""
        return _decode(raw)


def _address_for(context: ModuleContext, host: str) -> IPAddress | None:
    for candidate in context.target.addresses:
        if str(candidate) == host:
            return candidate
    if context.target.network is not None:
        for candidate in context.target.network:
            if str(candidate) == host:
                return candidate
    return None


def _service_finding(
    host: str, port: int, guess: ServiceGuess, banner: str, use_tls: bool
) -> Finding:
    described = guess.product or guess.service
    version = f" {guess.version}" if guess.version else ""
    transport = "tls" if use_tls else "tcp"

    return Finding(
        host=host,
        port=port,
        category=FindingCategory.PORT_SERVICE,
        kind="service.detected",
        title=f"{host}:{port}/tcp runs {described}{version}",
        summary=(
            f"Identified as {described}{version}"
            f" ({guess.confidence} confidence, {transport})."
            + ("" if guess.version else " The service did not state a version.")
        ),
        module=MODULE_NAME,
        identity_key=f"service/{port}",
        normalized_value={
            "port": port,
            "service": guess.service,
            "product": guess.product,
            "version": guess.version,
            "transport": transport,
        },
        # Truncated and rendered inertly by the client; never executed.
        raw_evidence=banner[:2000] if banner else None,
        confidence=guess.confidence,
    )
