"""SQLAlchemy models (PRD 7.5).

Tables that later checkpoints own (host_results, service_results, cve_matches)
are deliberately absent: they arrive with the modules that populate them, in
their own migrations.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from app.models.domain import ModuleStatus, ScanStatus


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_uuid() -> str:
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    type_annotation_map = {dict[str, Any]: JSON, list[str]: JSON, list[dict[str, Any]]: JSON}


class ScopeProfileRow(Base):
    __tablename__ = "scope_profiles"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    name: Mapped[str] = mapped_column(String(120), nullable=False, unique=True)
    entries_json: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    allow_cgnat: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    allow_link_local: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    scans: Mapped[list[ScanRow]] = relationship(back_populates="scope")


class ScanRow(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    scope_id: Mapped[str] = mapped_column(
        ForeignKey("scope_profiles.id", ondelete="RESTRICT"), nullable=False
    )
    target_input: Mapped[str] = mapped_column(String(255), nullable=False)
    target_normalized: Mapped[str] = mapped_column(String(255), nullable=False)
    target_type: Mapped[str] = mapped_column(String(16), nullable=False)
    resolved_addrs_json: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    intensity_profile: Mapped[str] = mapped_column(String(32), nullable=False)
    selected_modules_json: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    module_options_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default=str(ScanStatus.QUEUED), index=True
    )
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    attestation_text: Mapped[str] = mapped_column(Text, nullable=False)
    attestation_version: Mapped[str] = mapped_column(String(32), nullable=False)
    attestation_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    claimed_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    scope: Mapped[ScopeProfileRow] = relationship(back_populates="scans")
    module_runs: Mapped[list[ModuleRunRow]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class ModuleRunRow(Base):
    __tablename__ = "module_runs"
    __table_args__ = (UniqueConstraint("scan_id", "module", name="uq_module_run_scan_module"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    scan_id: Mapped[str] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    module: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default=str(ModuleStatus.QUEUED)
    )
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cache_hit: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    finding_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    safe_error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    safe_error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    scan: Mapped[ScanRow] = relationship(back_populates="module_runs")


class FindingRow(Base):
    """Evidence storage (PRD 6.1). CP3 populates it; CP2 creates it with FTS5."""

    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_findings_scan_category", "scan_id", "category"),
        Index("ix_findings_scan_module", "scan_id", "module"),
        Index("ix_findings_scan_host_port", "scan_id", "host", "port"),
        Index("ix_findings_fingerprint", "fingerprint"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    scan_id: Mapped[str] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    host: Mapped[str] = mapped_column(String(64), nullable=False)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    normalized_value: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    raw_evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    module: Mapped[str] = mapped_column(String(64), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    confidence: Mapped[str | None] = mapped_column(String(16), nullable=True)
    sources_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)


class ScanLedgerRow(Base):
    """Append-only. Never updated, and deleted only with its parent scan."""

    __tablename__ = "scan_ledger"
    __table_args__ = (
        CheckConstraint("decision in ('allowed', 'denied')", name="ck_ledger_decision"),
        Index("ix_ledger_scan_decision", "scan_id", "decision"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    scan_id: Mapped[str | None] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=True, index=True
    )
    # A refusal at creation time has no scan, so the deciding scope is what
    # keeps it attributable.
    scope_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    destination: Mapped[str] = mapped_column(String(64), nullable=False)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    module: Mapped[str] = mapped_column(String(64), nullable=False)
    decision: Mapped[str] = mapped_column(String(16), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    outcome: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )


class ScanEventRow(Base):
    """Progress events, retained for SSE reconnect with a last event id."""

    __tablename__ = "scan_events"
    __table_args__ = (UniqueConstraint("scan_id", "sequence", name="uq_event_scan_sequence"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    module: Mapped[str | None] = mapped_column(String(64), nullable=True)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    payload_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )


class CacheEntryRow(Base):
    __tablename__ = "cache_entries"

    cache_key: Mapped[str] = mapped_column(String(255), primary_key=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    response_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    normalized_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    retrieved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )


class WorkerLockRow(Base):
    """Single-row lock enforcing the one-worker process model (PRD 9).

    A second process finding a fresh heartbeat here refuses to start rather
    than racing for queued scans and doubling probes.
    """

    __tablename__ = "worker_lock"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    owner_id: Mapped[str] = mapped_column(String(36), nullable=False)
    pid: Mapped[int] = mapped_column(Integer, nullable=False)
    hostname: Mapped[str] = mapped_column(String(120), nullable=False)
    acquired_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    heartbeat_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
