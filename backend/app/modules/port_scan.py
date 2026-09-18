"""Unprivileged TCP connect port scanning (PRD FR-07).

Port state is inferred from the connect outcome, and the three states are kept
distinct on purpose:

* **open** - the connection was accepted.
* **closed** - the connection was refused, which is a definite answer.
* **filtered** - nothing answered before the governor's timeout, which is the
  absence of an answer rather than evidence of a closed port.

Every host gets a summary finding even when nothing is open, so "every port we
tried was closed" is an explicit result rather than an empty section someone
could read as "not scanned" (PRD 2.3, 3.2).
"""

from __future__ import annotations

from dataclasses import dataclass

from app.guard.ranges import IPAddress
from app.models.domain import (
    Confidence,
    FindingCategory,
    ModuleCategory,
    TargetType,
)
from app.models.findings import Finding
from app.modules.base import ModuleContext, ModuleMetadata, ModuleResult, ScanModule
from app.modules.ports import iter_target_addresses, resolve_ports
from app.scan.concurrency import in_bounded_waves
from app.scan.governor import BudgetExceeded

MODULE_NAME = "port_scan"

OPEN = "open"
CLOSED = "closed"
FILTERED = "filtered"


@dataclass(frozen=True)
class PortObservation:
    address: str
    port: int
    state: str


class PortScanModule(ScanModule):
    metadata = ModuleMetadata(
        name=MODULE_NAME,
        display_name="TCP connect port scan",
        description=(
            "Determines open, closed, and filtered TCP ports with unprivileged "
            "connect probes. No raw sockets and no administrator rights."
        ),
        category=ModuleCategory.PORT_SCAN,
        supported_targets=frozenset({TargetType.IP, TargetType.CIDR, TargetType.HOST}),
        timeout_seconds=1800.0,
    )

    async def run(self, context: ModuleContext) -> ModuleResult:
        ports = resolve_ports(context.options)
        addresses = list(iter_target_addresses(context.target))

        observations: list[PortObservation] = []
        budget_reached = False

        async def probe(address: IPAddress, port: int) -> PortObservation | None:
            if context.is_cancel_requested():
                return None
            return PortObservation(
                address=str(address),
                port=port,
                state=await self._probe_state(context, address, port),
            )

        factories = [
            (lambda address=address, port=port: probe(address, port))
            for address in addresses
            for port in ports
        ]

        async for outcome in in_bounded_waves(factories):
            if isinstance(outcome, BudgetExceeded):
                budget_reached = True
                continue
            if isinstance(outcome, BaseException):
                raise outcome
            if outcome is not None:
                observations.append(outcome)

        findings = _to_findings(observations)

        warnings: tuple[str, ...] = ()
        if budget_reached:
            warnings = (
                "the governor's probe budget was reached before every port was "
                "tested; untested ports are not reported as closed",
            )

        return ModuleResult(findings=findings, warnings=warnings)

    async def _probe_state(self, context: ModuleContext, address: IPAddress, port: int) -> str:
        try:
            sock = await context.guard.connect(context.target, address, port, context.governor)
        except ConnectionRefusedError:
            return CLOSED
        except TimeoutError:
            return FILTERED
        except OSError:
            # Unreachable, reset, or a host-level error: no definite answer.
            return FILTERED
        else:
            sock.close()
            return OPEN


def _to_findings(observations: list[PortObservation]) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    per_host: dict[str, list[PortObservation]] = {}
    for observation in observations:
        per_host.setdefault(observation.address, []).append(observation)

    for host, host_observations in per_host.items():
        open_ports = sorted(o.port for o in host_observations if o.state == OPEN)
        closed = sum(1 for o in host_observations if o.state == CLOSED)
        filtered = sum(1 for o in host_observations if o.state == FILTERED)

        for port in open_ports:
            findings.append(
                Finding(
                    host=host,
                    port=port,
                    category=FindingCategory.PORT_SERVICE,
                    kind="port.open",
                    title=f"{host}:{port}/tcp is open",
                    summary=f"A TCP connect to port {port} was accepted.",
                    module=MODULE_NAME,
                    identity_key=f"tcp/{port}",
                    normalized_value={"port": port, "protocol": "tcp", "state": OPEN},
                    raw_evidence=f"connect() to {host}:{port} succeeded",
                    confidence=Confidence.HIGH,
                )
            )

        findings.append(
            Finding(
                host=host,
                category=FindingCategory.PORT_SERVICE,
                kind="port.summary",
                title=f"{host}: {len(open_ports)} open of {len(host_observations)} probed",
                summary=(
                    f"{len(open_ports)} open, {closed} closed, {filtered} filtered "
                    f"across {len(host_observations)} probed TCP ports."
                ),
                module=MODULE_NAME,
                identity_key="tcp-summary",
                normalized_value={
                    "probed": len(host_observations),
                    "open": open_ports,
                    "closed_count": closed,
                    "filtered_count": filtered,
                },
                confidence=Confidence.HIGH,
            )
        )

    return tuple(findings)
