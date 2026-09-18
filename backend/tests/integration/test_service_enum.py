"""Service detection and read-only enumeration (PRD FR-08).

The servers here are started by the test on 127.0.0.1, so the suite still
performs no live network access, and every probe still runs through
ScanGuard.open_stream - the process-wide socket block would fail otherwise.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
from collections.abc import AsyncIterator, Callable

import pytest

from app.guard.ledger import InMemoryLedger
from app.guard.scanguard import ScanGuard, ScopeProfile
from app.models.domain import Confidence, FindingCategory
from app.models.findings import Finding
from app.modules.base import ModuleContext
from app.modules.fingerprints import (
    identify_from_banner,
    identify_from_http_server_header,
    service_name_for_port,
)
from app.modules.protocol_enum import ProtocolEnumModule
from app.modules.service_detect import ServiceDetectModule
from app.scan.governor import IntensityGovernor
from tests.conftest import allow_socket_creation

Handler = Callable[[asyncio.StreamReader, asyncio.StreamWriter], object]


async def start_server(handler: Handler, ssl_context: ssl.SSLContext | None = None) -> tuple:
    """A loopback server built from a pre-made socket, so the block allows it."""
    with allow_socket_creation():
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.setblocking(False)
    port = int(listener.getsockname()[1])
    server = await asyncio.start_server(handler, sock=listener, ssl=ssl_context)
    return server, port


async def make_context(open_ports: list[int], host: str = "127.0.0.1") -> ModuleContext:
    ledger = InMemoryLedger()
    guard = ScanGuard(ScopeProfile.create("self-test", ["127.0.0.0/24"]), ledger)
    target = await guard.validate_target(host)
    prior = tuple(
        Finding(
            host=host,
            port=port,
            category=FindingCategory.PORT_SERVICE,
            kind="port.open",
            title=f"{host}:{port} open",
            summary="open",
            module="port_scan",
            identity_key=f"tcp/{port}",
        )
        for port in open_ports
    )
    return ModuleContext(
        scan_id="scan-1",
        target=target,
        guard=guard,
        governor=IntensityGovernor("normal"),
        is_cancel_requested=lambda: False,
        prior_findings=prior,
    )


@pytest.fixture
async def ssh_server() -> AsyncIterator[int]:
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n")
        await writer.drain()
        writer.close()

    server, port = await start_server(handler)
    async with server:
        yield port


@pytest.fixture
async def http_server() -> AsyncIterator[int]:
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        request = await reader.read(1024)
        if b"/robots.txt" in request:
            body = "User-agent: *\nDisallow: /admin\n"
            writer.write(f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n\r\n{body}".encode())
        else:
            body = "<html><head><title>Lab Box</title></head><body>hi</body></html>"
            writer.write(
                (
                    "HTTP/1.1 200 OK\r\n"
                    "Server: nginx/1.18.0 (Ubuntu)\r\n"
                    "X-Frame-Options: DENY\r\n"
                    f"Content-Length: {len(body)}\r\n\r\n{body}"
                ).encode()
            )
        await writer.drain()
        writer.close()

    server, port = await start_server(handler)
    async with server:
        yield port


class TestFingerprints:
    def test_a_stated_version_is_high_confidence(self) -> None:
        guess = identify_from_banner("SSH-2.0-OpenSSH_8.9p1 Ubuntu", 22)
        assert guess is not None
        assert guess.product == "OpenSSH"
        assert guess.version == "8.9p1"
        assert guess.confidence is Confidence.HIGH

    def test_a_product_without_a_version_stays_medium(self) -> None:
        guess = identify_from_banner("220 mail.lab ESMTP Postfix", 25)
        assert guess is not None
        assert guess.product == "Postfix"
        assert guess.version is None
        assert guess.confidence is Confidence.MEDIUM

    def test_an_unrecognised_banner_yields_nothing_rather_than_a_guess(self) -> None:
        assert identify_from_banner("hello there", 12345) is None

    def test_a_port_number_alone_is_only_ever_low_confidence(self) -> None:
        """A convention is not an observation, and must never carry a version."""
        guess = service_name_for_port(22)
        assert guess is not None
        assert guess.service == "ssh"
        assert guess.product is None
        assert guess.version is None
        assert guess.confidence is Confidence.LOW

    def test_server_header_is_split_into_product_and_version(self) -> None:
        guess = identify_from_http_server_header("nginx/1.18.0 (Ubuntu)")
        assert guess.product == "nginx"
        assert guess.version == "1.18.0"
        assert guess.confidence is Confidence.HIGH


class TestServiceDetection:
    async def test_a_banner_identifies_product_and_version(self, ssh_server: int) -> None:
        context = await make_context([ssh_server])
        result = await ServiceDetectModule().run(context)

        assert len(result.findings) == 1
        finding = result.findings[0]
        assert finding.normalized_value["product"] == "OpenSSH"
        assert finding.normalized_value["version"] == "8.9p1"
        assert finding.confidence is Confidence.HIGH
        assert "OpenSSH" in (finding.raw_evidence or "")

    async def test_an_http_server_header_is_used(self, http_server: int) -> None:
        context = await make_context([http_server])
        result = await ServiceDetectModule().run(context)

        finding = result.findings[0]
        assert finding.normalized_value["product"] == "nginx"
        assert finding.normalized_value["version"] == "1.18.0"

    async def test_a_silent_port_gets_a_low_confidence_name_and_no_version(self) -> None:
        """Absence of a banner must never become an invented version."""

        async def silent(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await asyncio.sleep(0.2)
            writer.close()

        server, port = await start_server(silent)
        async with server:
            context = await make_context([port])
            result = await ServiceDetectModule().run(context)

        finding = result.findings[0]
        assert finding.normalized_value["version"] is None
        assert finding.confidence is Confidence.LOW
        assert "did not state a version" in finding.summary

    async def test_no_open_ports_is_a_warning_not_a_failure(self) -> None:
        context = await make_context([])
        result = await ServiceDetectModule().run(context)

        assert result.findings == ()
        assert result.warnings
        assert "no open ports" in result.warnings[0]


class TestProtocolEnumeration:
    async def test_http_metadata_is_collected(self, http_server: int) -> None:
        context = await make_context([http_server])
        result = await ProtocolEnumModule().run(context)

        responses = [f for f in result.findings if f.kind == "http.response"]
        assert responses, (
            f"expected an http.response finding, got {[f.kind for f in result.findings]}"
        )
        response = responses[0]
        assert response.normalized_value["status"] == 200
        assert response.normalized_value["server"] == "nginx/1.18.0 (Ubuntu)"
        assert response.normalized_value["title"] == "Lab Box"
        assert "x-frame-options" in response.normalized_value["security_headers_present"]
        assert "content-security-policy" in response.normalized_value["security_headers_missing"]

    async def test_robots_txt_is_captured(self, http_server: int) -> None:
        context = await make_context([http_server])
        result = await ProtocolEnumModule().run(context)

        robots_findings = [f for f in result.findings if f.kind == "http.robots"]
        assert robots_findings, "expected robots.txt to be captured"
        robots = robots_findings[0]
        assert "Disallow: /admin" in (robots.raw_evidence or "")

    async def test_evidence_is_stored_as_text_not_markup(self, http_server: int) -> None:
        """Target-controlled HTML must never reach the client as markup."""
        context = await make_context([http_server])
        result = await ProtocolEnumModule().run(context)

        response = [f for f in result.findings if f.kind == "http.response"][0]
        # Only headers are retained; the body (which contained HTML) is not.
        assert "<html>" not in (response.raw_evidence or "")

    async def test_a_non_http_port_yields_no_http_finding(self, ssh_server: int) -> None:
        """An SSH port is tried once and then left alone - no invented HTTP."""
        context = await make_context([ssh_server])
        result = await ProtocolEnumModule().run(context)
        assert [f for f in result.findings if f.kind.startswith("http.")] == []


class TestGuardOwnsEveryConnection:
    async def test_probes_are_ledgered_and_governed(self, http_server: int) -> None:
        context = await make_context([http_server])
        await ServiceDetectModule().run(context)

        assert context.governor.probes_made >= 1
        assert context.governor.hosts_touched == 1
