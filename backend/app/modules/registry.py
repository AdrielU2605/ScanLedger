"""Module registry (PRD FR-02).

The default registry is empty until CP3 registers the native probe modules.
Tests build their own isolated registry, so a test double is never reachable
from the running application.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.models.domain import ModuleCategory, ModuleReadiness, TargetType
from app.models.errors import UnknownModuleError
from app.modules.base import ScanModule


@dataclass(frozen=True)
class ModuleCatalogEntry:
    name: str
    display_name: str
    description: str
    category: ModuleCategory
    supported_targets: tuple[str, ...]
    readiness: ModuleReadiness
    release: str
    optional_dependency: str | None


class ModuleRegistry:
    def __init__(self) -> None:
        self._modules: dict[str, ScanModule] = {}

    def register(self, module: ScanModule) -> None:
        if module.name in self._modules:
            raise ValueError(f"module {module.name!r} is already registered")
        self._modules[module.name] = module

    def get(self, name: str) -> ScanModule:
        try:
            return self._modules[name]
        except KeyError:
            raise UnknownModuleError(
                f"unknown module {name!r}",
                details={"known_modules": sorted(self._modules)},
            ) from None

    def has(self, name: str) -> bool:
        return name in self._modules

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._modules))

    def all(self) -> tuple[ScanModule, ...]:
        return tuple(self._modules[name] for name in sorted(self._modules))

    def catalog(self, target_type: TargetType | None = None) -> tuple[ModuleCatalogEntry, ...]:
        entries: list[ModuleCatalogEntry] = []
        for module in self.all():
            metadata = module.metadata
            readiness = module.readiness()
            if target_type is not None and not module.applies_to(target_type):
                readiness = ModuleReadiness.NOT_APPLICABLE
            entries.append(
                ModuleCatalogEntry(
                    name=metadata.name,
                    display_name=metadata.display_name,
                    description=metadata.description,
                    category=metadata.category,
                    supported_targets=tuple(sorted(str(t) for t in metadata.supported_targets)),
                    readiness=readiness,
                    release=metadata.release,
                    optional_dependency=metadata.optional_dependency,
                )
            )
        return tuple(entries)


default_registry = ModuleRegistry()


def register_builtin_modules(registry: ModuleRegistry | None = None) -> ModuleRegistry:
    """Register the native MVP probe modules.

    Imported here rather than at module scope so the registry stays importable
    by tests that want an empty one.
    """
    from app.modules.host_discovery import HostDiscoveryModule
    from app.modules.port_scan import PortScanModule
    from app.modules.protocol_enum import ProtocolEnumModule
    from app.modules.service_detect import ServiceDetectModule

    target = registry if registry is not None else default_registry
    for module in (
        HostDiscoveryModule(),
        PortScanModule(),
        ServiceDetectModule(),
        ProtocolEnumModule(),
    ):
        if not target.has(module.name):
            target.register(module)
    return target
