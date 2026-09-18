"""Module registry and Finding fingerprint tests (PRD FR-02, FR-11)."""

from __future__ import annotations

import pytest

from app.models.domain import Confidence, FindingCategory, ModuleCategory, TargetType
from app.models.errors import UnknownModuleError
from app.models.findings import Finding, compute_fingerprint
from app.modules.base import ModuleMetadata, ModuleReadiness
from app.modules.registry import ModuleRegistry
from tests.conftest_db import NoOpModule


class TestRegistry:
    def test_register_and_retrieve(self) -> None:
        registry = ModuleRegistry()
        module = NoOpModule()
        registry.register(module)

        assert registry.get("noop") is module
        assert registry.names() == ("noop",)

    def test_unknown_module_lists_what_is_known(self) -> None:
        registry = ModuleRegistry()
        registry.register(NoOpModule())

        with pytest.raises(UnknownModuleError) as exc:
            registry.get("nmap_live")
        assert exc.value.details["known_modules"] == ["noop"]

    def test_duplicate_registration_is_refused(self) -> None:
        registry = ModuleRegistry()
        registry.register(NoOpModule())
        with pytest.raises(ValueError, match="already registered"):
            registry.register(NoOpModule())

    def test_builtin_registration_is_the_two_native_probe_modules(self) -> None:
        """Only native, guarded modules ship - no live external scanner."""
        from app.modules.registry import register_builtin_modules

        registry = register_builtin_modules(ModuleRegistry())
        assert registry.names() == ("host_discovery", "port_scan")

    def test_builtin_registration_is_idempotent(self) -> None:
        from app.modules.registry import register_builtin_modules

        registry = register_builtin_modules(ModuleRegistry())
        register_builtin_modules(registry)
        assert registry.names() == ("host_discovery", "port_scan")

    def test_catalog_marks_unsupported_target_types_not_applicable(self) -> None:
        class CidrOnlyModule(NoOpModule):
            metadata = ModuleMetadata(
                name="cidr_only",
                display_name="CIDR only",
                description="Supports CIDR targets only.",
                category=ModuleCategory.DISCOVERY,
                supported_targets=frozenset({TargetType.CIDR}),
            )

        registry = ModuleRegistry()
        registry.register(CidrOnlyModule())

        assert registry.catalog(TargetType.CIDR)[0].readiness is ModuleReadiness.READY
        assert registry.catalog(TargetType.IP)[0].readiness is ModuleReadiness.NOT_APPLICABLE

    def test_release_1_1_modules_are_marked(self) -> None:
        class SmbModule(NoOpModule):
            metadata = ModuleMetadata(
                name="smb_enum",
                display_name="SMB enumeration",
                description="Release 1.1.",
                category=ModuleCategory.ENUMERATION,
                supported_targets=frozenset({TargetType.IP}),
                release="1.1",
            )

        registry = ModuleRegistry()
        registry.register(SmbModule())
        assert registry.catalog()[0].readiness is ModuleReadiness.RELEASE_1_1


class TestFingerprint:
    def _finding(self, **overrides: object) -> Finding:
        defaults: dict[str, object] = {
            "host": "127.0.0.1",
            "category": FindingCategory.PORT_SERVICE,
            "kind": "port.open",
            "title": "Open port 22",
            "summary": "OpenSSH 8.2",
            "module": "port_scan",
            "identity_key": "tcp/22",
            "port": 22,
        }
        defaults.update(overrides)
        return Finding(**defaults)  # type: ignore[arg-type]

    def test_identical_observations_share_a_fingerprint(self) -> None:
        assert self._finding().fingerprint == self._finding().fingerprint

    def test_a_changed_version_keeps_the_same_identity(self) -> None:
        """So a diff reports 'changed', not a removal plus an addition."""
        before = self._finding(summary="OpenSSH 8.2", confidence=Confidence.HIGH)
        after = self._finding(summary="OpenSSH 9.1", confidence=Confidence.LOW)
        assert before.fingerprint == after.fingerprint

    @pytest.mark.parametrize(
        "difference",
        [
            {"host": "127.0.0.2"},
            {"port": 23},
            {"kind": "port.closed"},
            {"module": "service_detect"},
            {"identity_key": "tcp/22/alt"},
        ],
    )
    def test_different_identities_differ(self, difference: dict) -> None:
        assert self._finding().fingerprint != self._finding(**difference).fingerprint

    def test_a_portless_finding_is_stable(self) -> None:
        host_finding = self._finding(port=None, kind="host.live", identity_key="alive")
        assert host_finding.fingerprint == compute_fingerprint(
            module="port_scan",
            kind="host.live",
            host="127.0.0.1",
            port=None,
            identity_key="alive",
        )
