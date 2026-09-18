"""Pydantic request and response models (PRD 7.4)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.domain import ModuleCategory, ModuleReadiness

MAX_TARGET_LENGTH = 255


class ScopeCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    entries: list[str] = Field(min_length=1)
    allow_cgnat: bool = False
    allow_link_local: bool = False


class ScopeRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    entries: list[str]
    allow_cgnat: bool
    allow_link_local: bool
    created_at: datetime
    updated_at: datetime


class ModuleRead(BaseModel):
    name: str
    display_name: str
    description: str
    category: ModuleCategory
    supported_targets: list[str]
    readiness: ModuleReadiness
    release: str
    optional_dependency: str | None


class ScanCreate(BaseModel):
    scope_id: str
    target: str = Field(min_length=1, max_length=MAX_TARGET_LENGTH)
    modules: list[str] = Field(min_length=1)
    intensity_profile: str = "polite"
    note: str | None = Field(default=None, max_length=2000)
    attestation_accepted: bool = False
    module_options: dict[str, Any] = Field(default_factory=dict)


class ModuleRunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    module: str
    status: str
    attempt_count: int
    cache_hit: bool
    finding_count: int
    safe_error_code: str | None
    safe_error_message: str | None
    started_at: datetime | None
    finished_at: datetime | None


class ScanSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    scope_id: str
    target_input: str
    target_normalized: str
    target_type: str
    intensity_profile: str
    status: str
    note: str | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class ScanDetail(ScanSummary):
    resolved_addresses: list[str]
    selected_modules: list[str]
    attestation_text: str
    attestation_version: str
    attestation_at: datetime
    cancel_requested: bool
    module_runs: list[ModuleRunRead]


class ScanList(BaseModel):
    items: list[ScanSummary]
    total: int
    limit: int
    offset: int


class FindingRead(BaseModel):
    id: str
    host: str
    port: int | None
    category: str
    kind: str
    title: str
    summary: str
    normalized_value: dict[str, Any]
    raw_evidence: str | None
    module: str
    observed_at: datetime
    confidence: str | None
    sources: list[str]
    fingerprint: str


class FindingList(BaseModel):
    items: list[FindingRead]
    total: int
    limit: int
    offset: int


class LedgerEntryRead(BaseModel):
    destination: str
    port: int | None
    module: str
    decision: str
    reason: str
    outcome: str
    recorded_at: datetime
    scan_id: str | None = None
    scope_id: str | None = None


class LedgerList(BaseModel):
    items: list[LedgerEntryRead]
    total: int
    limit: int
    offset: int


class ErrorResponse(BaseModel):
    code: str
    message: str
    details: dict[str, Any] | None = None
