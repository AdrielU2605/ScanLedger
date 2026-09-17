"""Typed error taxonomy.

Every failure the API or a module can produce has a stable code, an HTTP
status, and a message safe to show a user and to store in ``module_runs``.
A scope refusal in particular must name what was refused and why (PRD UX-12),
so ``ScopeRefusedError`` carries the offending destination separately.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any


class ErrorCode(StrEnum):
    # Scope and target
    SCOPE_INVALID = "scope_invalid"
    SCOPE_NOT_FOUND = "scope_not_found"
    SCOPE_IN_USE = "scope_in_use"
    TARGET_INVALID = "target_invalid"
    TARGET_OUT_OF_SCOPE = "target_out_of_scope"
    # Authorization gate
    ATTESTATION_REQUIRED = "attestation_required"
    # Scans
    SCAN_NOT_FOUND = "scan_not_found"
    SCAN_ALREADY_TERMINAL = "scan_already_terminal"
    MODULE_UNKNOWN = "module_unknown"
    MODULE_NOT_SELECTED = "module_not_selected"
    # Runner and process model
    WORKER_ALREADY_RUNNING = "worker_already_running"
    # Modules at runtime
    MODULE_TIMEOUT = "module_timeout"
    MODULE_DEPENDENCY_MISSING = "module_dependency_missing"
    MODULE_FAILED = "module_failed"
    BUDGET_EXCEEDED = "budget_exceeded"
    # Providers
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    PROVIDER_RATE_LIMITED = "provider_rate_limited"


class AppError(Exception):
    """Base for every error the application raises deliberately."""

    code: ErrorCode = ErrorCode.MODULE_FAILED
    http_status: int = 500

    def __init__(self, message: str, *, details: dict[str, Any] | None = None) -> None:
        self.message = message
        self.details = details or {}
        super().__init__(message)

    def to_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"code": str(self.code), "message": self.message}
        if self.details:
            payload["details"] = self.details
        return payload


class ScopeInvalidError(AppError):
    code = ErrorCode.SCOPE_INVALID
    http_status = 422


class ScopeNotFoundError(AppError):
    code = ErrorCode.SCOPE_NOT_FOUND
    http_status = 404


class ScopeInUseError(AppError):
    code = ErrorCode.SCOPE_IN_USE
    http_status = 409


class TargetInvalidError(AppError):
    code = ErrorCode.TARGET_INVALID
    http_status = 422


class ScopeRefusedError(AppError):
    """A target was refused because it is outside the authorized scope.

    This is the refusal the UI must render prominently and the ledger must
    already contain by the time it is raised.
    """

    code = ErrorCode.TARGET_OUT_OF_SCOPE
    http_status = 422

    def __init__(self, message: str, *, destination: str, reason: str) -> None:
        super().__init__(message, details={"destination": destination, "reason": reason})
        self.destination = destination
        self.reason = reason


class AttestationRequiredError(AppError):
    code = ErrorCode.ATTESTATION_REQUIRED
    http_status = 422


class ScanNotFoundError(AppError):
    code = ErrorCode.SCAN_NOT_FOUND
    http_status = 404


class ScanAlreadyTerminalError(AppError):
    code = ErrorCode.SCAN_ALREADY_TERMINAL
    http_status = 409


class UnknownModuleError(AppError):
    code = ErrorCode.MODULE_UNKNOWN
    http_status = 422


class WorkerAlreadyRunningError(AppError):
    """Another process already owns the durable worker (PRD 9, process model)."""

    code = ErrorCode.WORKER_ALREADY_RUNNING
    http_status = 409


class ModuleError(AppError):
    """Base for typed module failures; the reason is stored on the module run."""

    code = ErrorCode.MODULE_FAILED
    http_status = 500


class ModuleTimeoutError(ModuleError):
    code = ErrorCode.MODULE_TIMEOUT


class ModuleDependencyMissingError(ModuleError):
    code = ErrorCode.MODULE_DEPENDENCY_MISSING


class BudgetExceededError(ModuleError):
    code = ErrorCode.BUDGET_EXCEEDED
