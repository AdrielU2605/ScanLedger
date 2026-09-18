"""Host discovery by unprivileged TCP connect (PRD FR-07).

No ICMP and no raw sockets: a host is called alive when a TCP connect to one of
a small common-port set gets a definite answer, and the finding records exactly
which port proved it. That keeps the module unprivileged on Windows and keeps
the evidence auditable - "alive" always says why.

A refused connection proves a host is there just as well as an accepted one,
which is why both count as evidence of life.
"""

from __future__ import annotations

from app.guard.ranges import IPAddress
from app.models.domain import (
    Confidence,
    FindingCategory,
    ModuleCategory,
    TargetType,
)
from app.models.findings import Finding
from app.modules.base import ModuleContext, ModuleMetadata, ModuleResult, ScanModule
from app.modules.ports import iter_target_addresses, resolve_discovery_ports
from app.scan.concurrency import in_bounded_waves
from app.scan.governor import BudgetExceeded

MODULE_NAME = "host_discovery"


class HostDiscoveryModule(ScanModule):
    metadata = ModuleMetadata(
        name=MODULE_NAME,
        display_name="Host discovery",
        description=(
            "Finds live hosts with unprivileged TCP connect probes to a small "
            "common-port set. Records which port proved the host alive."
        ),
        category=ModuleCategory.DISCOVERY,
        supported_targets=frozenset({TargetType.IP, TargetType.CIDR, TargetType.HOST}),
        timeout_seconds=600.0,
    )

    async def run(self, context: ModuleContext) -> ModuleResult:
        ports = resolve_discovery_ports(context.options)
        addresses = list(iter_target_addresses(context.target))

        findings: list[Finding] = []
        budget_reached = False

        async def probe(address: IPAddress) -> Finding | None:
            for port in ports:
                if context.is_cancel_requested():
                    return None
                evidence = await self._probe_once(context, address, port)
                if evidence is not None:
                    return _alive_finding(address, port, evidence)
            return None

        factories = [lambda address=address: probe(address) for address in addresses]

        async for outcome in in_bounded_waves(factories):
            if isinstance(outcome, BudgetExceeded):
                budget_reached = True
                continue
            if isinstance(outcome, BaseException):
                raise outcome
            if outcome is not None:
                findings.append(outcome)

        warnings: tuple[str, ...] = ()
        if budget_reached:
            # An exhausted budget is reported, never hidden: the unexamined
            # hosts must not read as "nothing was there" (PRD 3.2).
            warnings = (
                "the governor's probe budget was reached before every address was "
                "examined; hosts beyond that point were not tested",
            )

        return ModuleResult(findings=tuple(findings), warnings=warnings)

    async def _probe_once(
        self, context: ModuleContext, address: IPAddress, port: int
    ) -> str | None:
        """Return the evidence string if the host answered, else None."""
        try:
            sock = await context.guard.connect(context.target, address, port, context.governor)
        except ConnectionRefusedError:
            # Refused is still an answer - something is listening on that stack.
            return f"tcp/{port} refused the connection"
        except (TimeoutError, OSError):
            return None
        else:
            sock.close()
            return f"tcp/{port} accepted a connection"


def _alive_finding(address: IPAddress, port: int, evidence: str) -> Finding:
    return Finding(
        host=str(address),
        category=FindingCategory.LIVE_HOST,
        kind="host.live",
        title=f"{address} is alive",
        summary=f"Responded on {evidence}.",
        module=MODULE_NAME,
        identity_key="alive",
        normalized_value={"address": str(address), "proved_by_port": port},
        raw_evidence=evidence,
        confidence=Confidence.HIGH,
    )
