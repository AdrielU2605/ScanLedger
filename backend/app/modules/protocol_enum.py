"""Read-only protocol enumeration (PRD FR-08).

Collects what a service publishes about itself: HTTP status, headers, page
title, security headers, robots.txt, and the TLS certificate a host presents.

Everything here is a GET or a handshake. Nothing authenticates, posts, or
writes, and no request is crafted to trigger a vulnerability - that would be
exploitation, which belongs to a separate Phase 3 tool.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from datetime import UTC
from typing import Any

from app.guard.ranges import IPAddress
from app.guard.scanguard import GuardedStream, TlsInfo
from app.models.domain import (
    Confidence,
    FindingCategory,
    ModuleCategory,
    TargetType,
)
from app.models.findings import Finding
from app.modules.base import ModuleContext, ModuleMetadata, ModuleResult, ScanModule
from app.modules.service_detect import TLS_PORTS, _address_for, _decode
from app.scan.concurrency import in_bounded_waves
from app.scan.governor import BudgetExceeded

MODULE_NAME = "protocol_enum"

READ_BYTES = 16384
READ_TIMEOUT = 4.0
TITLE_PATTERN = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
STATUS_PATTERN = re.compile(r"^HTTP/[\d.]+\s+(\d{3})")

SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
)


@dataclass(frozen=True)
class HttpResponse:
    status: int | None
    headers: dict[str, str]
    title: str | None
    raw_head: str


class ProtocolEnumModule(ScanModule):
    metadata = ModuleMetadata(
        name=MODULE_NAME,
        display_name="Read-only protocol enumeration",
        description=(
            "Collects HTTP status, headers, page title, security headers and "
            "robots.txt, plus TLS certificate subject, SAN, issuer and validity. "
            "Read-only: nothing is written, submitted, or authenticated."
        ),
        category=ModuleCategory.ENUMERATION,
        supported_targets=frozenset({TargetType.IP, TargetType.CIDR, TargetType.HOST}),
        timeout_seconds=900.0,
        order=40,
    )

    async def run(self, context: ModuleContext) -> ModuleResult:
        open_ports = context.open_ports_by_host()
        if not open_ports:
            return ModuleResult(
                warnings=("no open ports were available from this scan to enumerate",),
            )

        findings: list[Finding] = []
        budget_reached = False

        factories = [
            (lambda host=host, port=port: self._enumerate(context, host, port))
            for host, ports in open_ports.items()
            for port in ports
        ]

        async for outcome in in_bounded_waves(factories, wave_size=16):
            if isinstance(outcome, BudgetExceeded):
                budget_reached = True
                continue
            if isinstance(outcome, BaseException):
                raise outcome
            if isinstance(outcome, list):
                findings.extend(outcome)

        warnings = (
            ("the governor's probe budget was reached; some ports were not enumerated",)
            if budget_reached
            else ()
        )
        return ModuleResult(findings=tuple(findings), warnings=warnings)

    async def _enumerate(self, context: ModuleContext, host: str, port: int) -> list[Finding]:
        if context.is_cancel_requested():
            return []

        address = _address_for(context, host)
        if address is None:
            return []

        # Any open port is tried, not just the conventional HTTP ones: a
        # finding is only recorded if the service actually answers with a
        # valid HTTP status line, so a non-HTTP port costs one read and is
        # then left alone.
        use_tls = port in TLS_PORTS
        findings: list[Finding] = []

        try:
            stream = await context.guard.open_stream(
                context.target, address, port, context.governor, use_tls=use_tls
            )
        except BudgetExceeded:
            raise
        except (TimeoutError, OSError):
            return []

        try:
            if stream.tls is not None:
                certificate = _certificate_finding(host, port, stream.tls)
                if certificate is not None:
                    findings.append(certificate)

            response = await self._fetch(stream, host, "/")
        finally:
            await stream.close()

        if response is not None:
            findings.extend(_http_findings(host, port, response, use_tls))

        robots = await self._fetch_path(context, host, port, address, use_tls, "/robots.txt")
        if robots is not None:
            findings.append(robots)

        return findings

    async def _fetch_path(
        self,
        context: ModuleContext,
        host: str,
        port: int,
        address: IPAddress,
        use_tls: bool,
        path: str,
    ) -> Finding | None:
        try:
            stream = await context.guard.open_stream(
                context.target, address, port, context.governor, use_tls=use_tls
            )
        except BudgetExceeded:
            raise
        except (TimeoutError, OSError):
            return None

        try:
            response = await self._fetch(stream, host, path)
        finally:
            await stream.close()

        if response is None or response.status != 200:
            return None

        body = response.raw_head.split("\r\n\r\n", 1)
        content = body[1] if len(body) > 1 else ""
        if not content.strip():
            return None

        return Finding(
            host=host,
            port=port,
            category=FindingCategory.ENUMERATION,
            kind="http.robots",
            title=f"{host}:{port} publishes robots.txt",
            summary=f"robots.txt returned {len(content)} characters of directives.",
            module=MODULE_NAME,
            identity_key=f"robots/{port}",
            normalized_value={"port": port, "length": len(content)},
            raw_evidence=content[:2000],
            confidence=Confidence.HIGH,
        )

    async def _fetch(self, stream: GuardedStream, host: str, path: str) -> HttpResponse | None:
        try:
            stream.writer.write(
                f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: ScanLedger\r\n"
                "Accept: */*\r\nConnection: close\r\n\r\n".encode()
            )
            await stream.writer.drain()
            raw = await asyncio.wait_for(stream.reader.read(READ_BYTES), timeout=READ_TIMEOUT)
        except (TimeoutError, OSError):
            return None

        if not raw:
            return None

        text = _decode(raw)
        status_match = STATUS_PATTERN.match(text)
        if status_match is None:
            return None

        head = text.split("\r\n\r\n", 1)[0]
        headers: dict[str, str] = {}
        for line in head.split("\r\n")[1:]:
            if ":" in line:
                name, _, value = line.partition(":")
                headers[name.strip().lower()] = value.strip()

        title_match = TITLE_PATTERN.search(text)
        title = title_match.group(1).strip()[:200] if title_match else None

        return HttpResponse(
            status=int(status_match.group(1)),
            headers=headers,
            title=title,
            raw_head=text,
        )


def _http_findings(host: str, port: int, response: HttpResponse, use_tls: bool) -> list[Finding]:
    scheme = "https" if use_tls else "http"
    present = [name for name in SECURITY_HEADERS if name in response.headers]
    missing = [name for name in SECURITY_HEADERS if name not in response.headers]

    summary_bits = [f"HTTP {response.status}"]
    if response.headers.get("server"):
        summary_bits.append(f"Server: {response.headers['server']}")
    if response.title:
        summary_bits.append(f"Title: {response.title}")

    return [
        Finding(
            host=host,
            port=port,
            category=FindingCategory.ENUMERATION,
            kind="http.response",
            title=f"{host}:{port} answered an HTTP request ({scheme})",
            summary=". ".join(summary_bits) + ".",
            module=MODULE_NAME,
            identity_key=f"http/{port}",
            normalized_value={
                "port": port,
                "scheme": scheme,
                "status": response.status,
                "server": response.headers.get("server"),
                "title": response.title,
                "security_headers_present": present,
                "security_headers_missing": missing,
            },
            # Headers only - the body is not stored, and nothing is rendered
            # as markup by the client.
            raw_evidence=response.raw_head.split("\r\n\r\n", 1)[0][:2000],
            confidence=Confidence.HIGH,
        )
    ]


def _certificate_finding(host: str, port: int, tls: TlsInfo) -> Finding | None:
    if tls.certificate_der is None:
        return None

    details = _parse_certificate(tls.certificate_der)
    if details is None:
        return Finding(
            host=host,
            port=port,
            category=FindingCategory.ENUMERATION,
            kind="tls.session",
            title=f"{host}:{port} negotiated TLS",
            summary=(
                f"Negotiated {tls.protocol or 'TLS'} with cipher {tls.cipher or 'unknown'}. "
                "The certificate could not be parsed and is reported as unreadable rather "
                "than assumed valid."
            ),
            module=MODULE_NAME,
            identity_key=f"tls/{port}",
            normalized_value={"port": port, "protocol": tls.protocol, "cipher": tls.cipher},
            confidence=Confidence.MEDIUM,
        )

    return Finding(
        host=host,
        port=port,
        category=FindingCategory.ENUMERATION,
        kind="tls.cert",
        title=(
            f"{host}:{port} presents a TLS certificate for "
            f"{details['subject'] or 'an unnamed subject'}"
        ),
        summary=(
            f"Issued by {details['issuer'] or 'an unnamed issuer'}, valid "
            f"{details['not_before']} to {details['not_after']}"
            + (f", SAN: {', '.join(details['san'][:5])}" if details["san"] else "")
            + f". Negotiated {tls.protocol or 'TLS'}."
        ),
        module=MODULE_NAME,
        identity_key=f"tls/{port}",
        normalized_value={
            "port": port,
            "protocol": tls.protocol,
            "cipher": tls.cipher,
            **details,
        },
        confidence=Confidence.HIGH,
    )


def _parse_certificate(der: bytes) -> dict[str, Any] | None:
    """Parse an untrusted, target-supplied certificate.

    Returns None rather than raising: a malformed certificate is evidence
    about the host, not a reason to fail the module.
    """
    try:
        from cryptography import x509

        certificate = x509.load_der_x509_certificate(der)
        san: list[str] = []
        try:
            extension = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san = [str(name) for name in extension.value.get_values_for_type(x509.DNSName)]
        except x509.ExtensionNotFound:
            san = []

        return {
            "subject": certificate.subject.rfc4514_string(),
            "issuer": certificate.issuer.rfc4514_string(),
            "serial": format(certificate.serial_number, "x"),
            "not_before": certificate.not_valid_before_utc.astimezone(UTC).isoformat(),
            "not_after": certificate.not_valid_after_utc.astimezone(UTC).isoformat(),
            "san": san,
            "self_signed": certificate.subject == certificate.issuer,
        }
    except Exception:
        return None
