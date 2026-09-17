"""Domain vocabulary: the states and categories the whole system agrees on.

PRD 7.3 (scan and module state model) and 6.1 (finding schema).
"""

from __future__ import annotations

from enum import StrEnum


class ScanStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    COMPLETED_WITH_WARNINGS = "completed_with_warnings"
    FAILED = "failed"
    CANCELED = "canceled"

    @property
    def is_terminal(self) -> bool:
        return self in _TERMINAL_SCAN_STATUSES


_TERMINAL_SCAN_STATUSES = frozenset(
    {
        ScanStatus.COMPLETED,
        ScanStatus.COMPLETED_WITH_WARNINGS,
        ScanStatus.FAILED,
        ScanStatus.CANCELED,
    }
)


class ModuleStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    SKIPPED = "skipped"
    NOT_APPLICABLE = "not_applicable"
    INTERRUPTED = "interrupted"

    @property
    def is_terminal(self) -> bool:
        return self in _TERMINAL_MODULE_STATUSES

    @property
    def is_success(self) -> bool:
        return self is ModuleStatus.DONE


_TERMINAL_MODULE_STATUSES = frozenset(
    {
        ModuleStatus.DONE,
        ModuleStatus.FAILED,
        ModuleStatus.SKIPPED,
        ModuleStatus.NOT_APPLICABLE,
        ModuleStatus.INTERRUPTED,
    }
)


class TargetType(StrEnum):
    IP = "ip"
    CIDR = "cidr"
    HOST = "host"


class ModuleCategory(StrEnum):
    DISCOVERY = "discovery"
    PORT_SCAN = "port_scan"
    SERVICE_DETECTION = "service_detection"
    ENUMERATION = "enumeration"
    VULNERABILITY = "vulnerability"
    IMPORT = "import"


class ModuleReadiness(StrEnum):
    READY = "ready"
    NEEDS_EXTERNAL_TOOL = "needs_external_tool"
    NOT_APPLICABLE = "not_applicable"
    RELEASE_1_1 = "release_1_1"


class FindingCategory(StrEnum):
    LIVE_HOST = "live_host"
    PORT_SERVICE = "port_service"
    ENUMERATION = "enumeration"
    VULNERABILITY = "vulnerability"


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ScanEventType(StrEnum):
    SCAN_STATUS = "scan_status"
    MODULE_STATUS = "module_status"
    FOOTPRINT = "footprint"
