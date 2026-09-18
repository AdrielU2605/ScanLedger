"""The scan module contract (PRD FR-02).

A module is an isolated unit that receives a *guarded* connector and nothing
else. It cannot open its own socket: the only network handle it is given is
``context.guard``, and the static boundary check plus the process-wide socket
block fail the build if a module tries to reach the network another way.

Adding a module is registration, not a change to orchestration logic.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, ClassVar

from app.guard.scanguard import ScanGuard, ValidatedTarget
from app.models.domain import ModuleCategory, ModuleReadiness, TargetType
from app.models.findings import Finding
from app.scan.governor import IntensityGovernor

__all__ = [
    "MVP_RELEASE",
    "NEXT_RELEASE",
    "ModuleContext",
    "ModuleMetadata",
    "ModuleResult",
    "ScanModule",
]

MVP_RELEASE = "mvp"
NEXT_RELEASE = "1.1"


@dataclass(frozen=True)
class ModuleMetadata:
    name: str
    display_name: str
    description: str
    category: ModuleCategory
    supported_targets: frozenset[TargetType]
    release: str = MVP_RELEASE
    optional_dependency: str | None = None
    timeout_seconds: float = 120.0
    cache_ttl_seconds: int | None = None
    # Modules run in ascending order regardless of the order they were
    # selected in, because service detection is useless before the port scan
    # that tells it which ports are open.
    order: int = 50


@dataclass
class ModuleContext:
    """Everything a module is allowed to touch."""

    scan_id: str
    target: ValidatedTarget
    guard: ScanGuard
    governor: IntensityGovernor
    is_cancel_requested: Callable[[], bool]
    options: dict[str, Any] = field(default_factory=dict)
    # Findings produced earlier in this same scan. Service detection needs to
    # know which ports the port scan found open, and reading them here keeps
    # modules from reaching into the database themselves.
    prior_findings: tuple[Finding, ...] = ()

    def open_ports_by_host(self) -> dict[str, tuple[int, ...]]:
        found: dict[str, list[int]] = {}
        for finding in self.prior_findings:
            if finding.kind == "port.open" and finding.port is not None:
                found.setdefault(finding.host, []).append(finding.port)
        return {host: tuple(sorted(ports)) for host, ports in found.items()}


@dataclass(frozen=True)
class ModuleResult:
    findings: tuple[Finding, ...] = ()
    cache_hit: bool = False
    warnings: tuple[str, ...] = field(default_factory=tuple)


class ScanModule(ABC):
    """Base class for every scan module."""

    metadata: ClassVar[ModuleMetadata]

    @property
    def name(self) -> str:
        return self.metadata.name

    def applies_to(self, target_type: TargetType) -> bool:
        return target_type in self.metadata.supported_targets

    def readiness(self) -> ModuleReadiness:
        """Whether this module can run here and now.

        Native MVP modules are always ready; a module with an unmet optional
        dependency reports it so the launch screen can say it will be skipped
        rather than failing the scan (UX-06).
        """
        if self.metadata.release != MVP_RELEASE:
            return ModuleReadiness.RELEASE_1_1
        if self.metadata.optional_dependency is not None and not self.dependency_available():
            return ModuleReadiness.NEEDS_EXTERNAL_TOOL
        return ModuleReadiness.READY

    def dependency_available(self) -> bool:
        """Overridden by modules that declare an optional dependency."""
        return self.metadata.optional_dependency is None

    @abstractmethod
    async def run(self, context: ModuleContext) -> ModuleResult:
        """Probe through the guard and return normalized findings.

        Raises a typed ``ModuleError`` on failure; the runner records the safe
        reason on the module run and lets the rest of the scan continue.
        """
